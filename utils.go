//
// Copyright 2019-2020 Nestybox, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/nestybox/sysbox-libs/dockerUtils"
	libutils "github.com/nestybox/sysbox-libs/utils"
	utils "github.com/nestybox/sysbox-libs/utils"
	intf "github.com/nestybox/sysbox-mgr/intf"
	"github.com/nestybox/sysbox-mgr/subidAlloc"
	"github.com/nestybox/sysbox-mgr/volMgr"
	"github.com/opencontainers/runc/libcontainer/mount"
	"github.com/opencontainers/runc/libcontainer/user"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"

	"golang.org/x/sys/unix"
)

const SHIFTFS_MAGIC int64 = 0x6a656a62

var progDeps = []string{"rsync", "modprobe", "iptables"}

type exclusiveMntTable struct {
	mounts map[string][]string // mount source -> list of containers using that mount source
	lock   sync.Mutex
}

func newExclusiveMntTable() *exclusiveMntTable {
	return &exclusiveMntTable{
		mounts: make(map[string][]string),
	}
}

func (t *exclusiveMntTable) add(mntSrc, containerId string) {
	t.lock.Lock()
	defer t.lock.Unlock()

	cids, found := t.mounts[mntSrc]
	if found {
		logrus.Warnf("mount source at %s should be mounted in one container only, but is already mounted in containers %v", mntSrc, cids)
	}
	t.mounts[mntSrc] = append(cids, containerId)
}

func (t *exclusiveMntTable) remove(mntSrc, containerId string) {
	t.lock.Lock()
	defer t.lock.Unlock()

	cids, found := t.mounts[mntSrc]
	if !found {
		return
	}

	cids = utils.StringSliceRemove(cids, []string{containerId})

	if len(cids) > 0 {
		t.mounts[mntSrc] = cids
	} else {
		delete(t.mounts, mntSrc)
	}
}

func allocSubidRange(subID []user.SubID, size, min, max uint64) ([]user.SubID, error) {
	var holeStart, holeEnd uint64

	if size == 0 {
		return subID, fmt.Errorf("invalid allocation size: %d", size)
	}

	sortedSubID := subID

	// Sort the subIDs by starting range (simplifies the allocation)
	sort.Slice(sortedSubID, func(i, j int) bool {
		return sortedSubID[i].SubID < sortedSubID[j].SubID
	})

	holeStart = min

	for _, id := range sortedSubID {
		holeEnd = uint64(id.SubID)

		if (holeEnd >= holeStart) && (holeEnd-holeStart >= size) {
			sortedSubID = append(sortedSubID, user.SubID{Name: "sysbox", SubID: int64(holeStart), Count: int64(size)})
			return sortedSubID, nil
		}

		holeStart = uint64(id.SubID + id.Count)
	}

	holeEnd = max
	if holeEnd-holeStart < size {
		return sortedSubID, fmt.Errorf("failed to allocate %d subids in range %d, %d", size, min, max)
	}

	sortedSubID = append(sortedSubID, user.SubID{Name: "sysbox", SubID: int64(holeStart), Count: int64(size)})
	return sortedSubID, nil
}

func writeSubidFile(path string, subID []user.SubID) error {
	var buf bytes.Buffer
	for _, id := range subID {
		l := fmt.Sprintf("%s:%d:%d\n", id.Name, id.SubID, id.Count)
		buf.WriteString(l)
	}

	return ioutil.WriteFile(path, []byte(buf.String()), 0644)
}

func configSubidRange(path string, size, min, max uint64) error {

	subID, err := user.ParseSubIDFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// We will create an new file with only the "sysbox" entry
			subID = []user.SubID{}
		} else {
			return fmt.Errorf("error parsing file %s: %s", path, err)
		}
	}

	// Check if there are any subids configured for user "sysbox"
	numSysboxEntries := 0
	idx := 0
	for i, id := range subID {
		if id.Name == "sysbox" {
			numSysboxEntries = numSysboxEntries + 1
			idx = i
		}
	}

	// If a single valid subID range for user "sysbox" is found, let's use it.
	if numSysboxEntries == 1 && uint64(subID[idx].Count) == size {
		return nil
	}

	// If there are multiple ranges for user sysbox (something we don't support)
	// eliminate them and replace them with a single one.
	if numSysboxEntries > 0 {
		tmpSubID := []user.SubID{}
		for _, id := range subID {
			if id.Name != "sysbox" {
				tmpSubID = append(tmpSubID, id)
			}
		}
		subID = tmpSubID
	}

	// Allocate range for user sysbox
	subID, err = allocSubidRange(subID, size, min, max)
	if err != nil {
		return fmt.Errorf("failed to configure subid range for sysbox: %s", err)
	}

	// Sort by subID
	sort.Slice(subID, func(i, j int) bool {
		return subID[i].SubID < subID[j].SubID
	})

	// Write it to the subuid file
	if err = writeSubidFile(path, subID); err != nil {
		return fmt.Errorf("failed to configure subid range for sysbox: %s", err)
	}

	return nil
}

// getSubidLimits returns the subuid min, subuid max, subgid min, and subgid max limits
// for the host (in that order)
func getSubidLimits(file string) ([]uint64, error) {

	// defaults (see login.defs(5); we set the max limits to 2^32 because uid(gid)
	// are 32-bit, even though login.defs(5) indicates it's above this value)
	limits := []uint64{100000, 4294967295, 100000, 4294967295}

	// check if these defaults are overridden by login.defs; if login.defs does not exist, move on.
	f, err := os.Open(file)
	if err != nil {
		return limits, nil
	}
	defer f.Close()

	tokens := map[string]uint{
		"SUB_UID_MIN": 0,
		"SUB_UID_MAX": 1,
		"SUB_GID_MIN": 2,
		"SUB_GID_MAX": 3,
	}

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		for token, pos := range tokens {
			if strings.Contains(line, token) {
				valStr := strings.Fields(line)
				if len(valStr) < 2 {
					return limits, fmt.Errorf("failed to parse file %s: line %s: expected two fields, found %d field(s)", file, line, len(valStr))
				}
				limits[pos], err = strconv.ParseUint(valStr[1], 10, 64)
				if err != nil {
					return limits, fmt.Errorf("failed to parse line %s: %s", line, err)
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return limits, fmt.Errorf("failed to scan file %s: %v", file, err)
	}

	return limits, nil
}

func setupSubidAlloc(ctx *cli.Context) (intf.SubidAlloc, error) {

	// get subid min/max limits from login.defs (if any)
	limits, err := getSubidLimits("/etc/login.defs")
	if err != nil {
		return nil, err
	}

	subUidMin := limits[0]
	subUidMax := limits[1]
	subGidMin := limits[2]
	subGidMax := limits[3]

	// configure the subuid(gid) range for "sysbox"
	if err := configSubidRange("/etc/subuid", subidRangeSize, subUidMin, subUidMax); err != nil {
		return nil, err
	}
	if err := configSubidRange("/etc/subgid", subidRangeSize, subGidMin, subGidMax); err != nil {
		return nil, err
	}

	subuidSrc, err := os.Open("/etc/subuid")
	if err != nil {
		return nil, err
	}
	defer subuidSrc.Close()

	subgidSrc, err := os.Open("/etc/subgid")
	if err != nil {
		return nil, err
	}
	defer subgidSrc.Close()

	subidAlloc, err := subidAlloc.New("sysbox", subuidSrc, subgidSrc)
	if err != nil {
		return nil, err
	}

	return subidAlloc, nil
}

func setupDockerVolMgr(ctx *cli.Context) (intf.VolMgr, error) {
	var statfs syscall.Statfs_t

	hostDir := filepath.Join(sysboxLibDir, "docker")
	if err := os.MkdirAll(hostDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create %v: %v", hostDir, err)
	}

	// The host dir that is bind-mounted into the sys container's /var/lib/docker can't be
	// on the following filesystems, as docker inside the sys container uses overlayfs for
	// its images and overlayfs can't be mounted on top of these.

	unsupportedFs := map[string]int64{
		"tmpfs":     unix.TMPFS_MAGIC,
		"overlayfs": unix.OVERLAYFS_SUPER_MAGIC,
		"shiftfs":   SHIFTFS_MAGIC,
	}

	if err := syscall.Statfs(hostDir, &statfs); err != nil {
		return nil, fmt.Errorf("failed to find filesystem info for %s", hostDir)
	}

	for name, magic := range unsupportedFs {
		if int64(statfs.Type) == magic {
			return nil, fmt.Errorf("host dir for docker vol manager (%s) can't be on %v", hostDir, name)
		}
	}

	return volMgr.New("dockerVolMgr", hostDir, true)
}

func setupKubeletVolMgr(ctx *cli.Context) (intf.VolMgr, error) {

	var statfs syscall.Statfs_t

	hostDir := filepath.Join(sysboxLibDir, "kubelet")
	if err := os.MkdirAll(hostDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create %v: %v", hostDir, err)
	}

	// The host dir that is bind-mounted into the sys container's /var/lib/kubelet
	// directory can't be on the following filesystems, as kubelet inside the sys
	// container does not support them.
	unsupportedFs := map[string]int64{
		"shiftfs": SHIFTFS_MAGIC,
	}

	if err := syscall.Statfs(hostDir, &statfs); err != nil {
		return nil, fmt.Errorf("failed to find filesystem info for %s", hostDir)
	}

	for name, magic := range unsupportedFs {
		if int64(statfs.Type) == magic {
			return nil, fmt.Errorf("host dir for kubelet vol manager (%s) can't be on %v", hostDir, name)
		}
	}

	return volMgr.New("kubeletVolMgr", hostDir, true)
}

func setupK3sVolMgr(ctx *cli.Context) (intf.VolMgr, error) {

	var statfs syscall.Statfs_t

	hostDir := filepath.Join(sysboxLibDir, "rancher-k3s")
	if err := os.MkdirAll(hostDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create %v: %v", hostDir, err)
	}

	// The host dir that is bind-mounted into the sys container's
	// /var/lib/rancher/k3s directory can't be on the following filesystems,
	// as k3s inside the sys container does not support them.
	unsupportedFs := map[string]int64{
		"shiftfs": SHIFTFS_MAGIC,
	}

	if err := syscall.Statfs(hostDir, &statfs); err != nil {
		return nil, fmt.Errorf("failed to find filesystem info for %s", hostDir)
	}

	for name, magic := range unsupportedFs {
		if int64(statfs.Type) == magic {
			return nil, fmt.Errorf("host dir for kubelet vol manager (%s) can't be on %v", hostDir, name)
		}
	}

	return volMgr.New("k3sVolMgr", hostDir, true)
}

func setupContainerdVolMgr(ctx *cli.Context) (intf.VolMgr, error) {

	var statfs syscall.Statfs_t

	hostDir := filepath.Join(sysboxLibDir, "containerd")
	if err := os.MkdirAll(hostDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create %v: %v", hostDir, err)
	}

	// The host dir that is bind-mounted into the sys container's
	// /var/lib/containerd/io.containerd.snapshotter.v1.overlayfs
	// directory can't be on the following filesystems, as containerd inside the sys
	// container does not support them.
	unsupportedFs := map[string]int64{
		"shiftfs": SHIFTFS_MAGIC,
	}

	if err := syscall.Statfs(hostDir, &statfs); err != nil {
		return nil, fmt.Errorf("failed to find filesystem info for %s", hostDir)
	}

	for name, magic := range unsupportedFs {
		if int64(statfs.Type) == magic {
			return nil, fmt.Errorf("host dir for containerd vol manager (%s) can't be on %v", hostDir, name)
		}
	}

	return volMgr.New("containerdVolMgr", hostDir, true)
}

func setupWorkDirs() error {

	// Cleanup work dirs in case they were left unclean from a prior session (e.g., if
	// sysbox was running and stopped with SIGKILL)
	if err := cleanupWorkDirs(); err != nil {
		return err
	}

	if err := os.MkdirAll(sysboxRunDir, 0700); err != nil {
		return fmt.Errorf("failed to create %s: %s", sysboxRunDir, err)
	}

	// SysboxLibDir requires slightly less stringent permissions to ensure
	// that sysbox-runc is capable of operating in this path during container
	// initialization. Also, note that even though SysboxLibDir is typically
	// owned by 'root:root', here we are explicitly enforcing it to address
	// (testing) scenarios where this may not be the case.
	if err := os.MkdirAll(sysboxLibDir, 0710); err != nil {
		return fmt.Errorf("failed to create %s: %s", sysboxLibDir, err)
	}
	if err := os.Chown(sysboxLibDir, int(0), int(0)); err != nil {
		return fmt.Errorf("failed to chown %s: %s", sysboxLibDir, err)
	}

	return nil
}

func cleanupWorkDirs() error {

	// Remove any mounts under the sysbox lib dir (we don't expect any because normally
	// sysbox-mgr removes all mounts it creates, unless is was killed with SIGKILL).
	mountinfos, err := mount.GetMounts()
	if err != nil {
		return fmt.Errorf("failed to obtain mounts: %s", err)
	}

	for _, mi := range mountinfos {
		if strings.HasPrefix(mi.Mountpoint, sysboxLibDir+"/") {
			if err := unix.Unmount(mi.Mountpoint, unix.MNT_DETACH); err != nil {
				return fmt.Errorf("failed to unmount %s: %s", mi.Mountpoint, err)
			}
		}
	}

	// Remove the sysbox lib dir
	if err := os.RemoveAll(sysboxLibDir); err != nil {
		logrus.Warnf("failed to cleanup %s: %v", sysboxLibDir, err)
	}

	return nil
}

// Sanitize the given container's rootfs.
func sanitizeRootfs(id, rootfs string) string {

	// Docker containers on overlayfs have a rootfs under "/var/lib/docker/overlay2/<container-id>/merged".
	// However, Docker removes the "merged" directory during container stop and re-creates
	// it during container start. Thus, we can't rely on the presence of "merged" to
	// determine if a container was stopped or removed. Instead, we use the rootfs path up
	// to <container-id>.

	isDocker, err := dockerUtils.ContainerIsDocker(id, rootfs)
	if err == nil && isDocker {
		if strings.Contains(rootfs, "overlay2") && filepath.Base(rootfs) == "merged" {
			return filepath.Dir(rootfs)
		}
	}

	return rootfs
}

// getLinuxHeaderMounts returns a list of read-only mounts of the host's linux
// kernel headers.
func getLinuxHeaderMounts(kernelHdrPath string) ([]specs.Mount, error) {

	var path = kernelHdrPath

	if _, err := os.Stat(path); os.IsNotExist(err) {
		logrus.Warnf("No kernel-headers found in host filesystem at %s. No headers will be mounted inside any of the containers.", kernelHdrPath)
		return []specs.Mount{}, nil
	}

	// Create a mount-spec making use of the kernel-hdr-path in the host. This way,
	// sys containers will have kernel-headers exposed in the same path utilized by
	// the host. In addition to this, a softlink will be added to container's rootfs,
	// if its expected kernel-header-path differs from the one of the host -- refer
	// to reqFsState() for details.
	//
	// Finally, notice that here we enable 'follow' flag as some distros (e.g., Ubuntu)
	// heavily symlink the linux-header directory.
	mounts, err := createMountSpec(
		path,
		path,
		"bind",
		[]string{"ro", "rbind", "rprivate"},
		true,
		[]string{"/usr/src"},
	)
	if err != nil {
		return nil,
			fmt.Errorf("failed to create mount spec for linux headers at %s: %v", path, err)
	}

	return mounts, nil
}

// getLibModMount returns a list of read-only mounts for the host's kernel modules dir (/lib/modules/<kernel-release>).
func getLibModMounts() ([]specs.Mount, error) {

	kernelRel, err := libutils.GetKernelRelease()
	if err != nil {
		return nil, err
	}

	path := filepath.Join("/lib/modules/", kernelRel)
	if _, err := os.Stat(path); err != nil {
		return nil, err
	}

	mounts := []specs.Mount{}

	// Do *not* follow symlinks as they normally point to the linux headers which we
	// mount also (see getLinuxHeadersMount()).
	mounts, err = createMountSpec(
		path,
		path,
		"bind",
		[]string{"ro", "rbind", "rprivate"}, false, []string{"/usr/src"},
	)

	if err != nil {
		return nil, fmt.Errorf("failed to create mount spec for linux modules at %s: %v",
			path, err)
	}

	return mounts, nil
}

// createMountSpec returns a mount spec with the given source, destination, type, and
// options. 'source' must be an absolute path. 'dest' is absolute with respect to the
// container's rootfs. If followSymlinks is true, this function follows symlinks under the
// source path and returns additional mount specs to ensure the symlinks are valid at the
// destination. If symlinkFilt is not empty, only symlinks that resolve to paths that
// are prefixed by the symlinkFilt strings are allowed.
func createMountSpec(
	source string,
	dest string,
	mountType string,
	mountOpt []string,
	followSymlinks bool,
	symlinkFilt []string) ([]specs.Mount, error) {

	mounts := []specs.Mount{}
	m := specs.Mount{
		Source:      source,
		Destination: dest,
		Type:        mountType,
		Options:     mountOpt,
	}
	mounts = append(mounts, m)

	if followSymlinks {
		links, err := followSymlinksUnder(source)
		if err != nil {
			return nil, fmt.Errorf("failed to follow symlinks under %s: %v", source, err)
		}

		if len(symlinkFilt) == 0 {
			symlinkFilt = append(symlinkFilt, "")
		}

		// apply symlink filtering
		for _, filt := range symlinkFilt {
			filt = filepath.Clean(filt)
			filtLinks := utils.StringSliceRemoveMatch(links, func(s string) bool {
				if strings.HasPrefix(s, filt+"/") {
					return false
				}
				return true
			})

			if len(filtLinks) == 0 {
				continue
			}

			lcp := longestCommonPath(filtLinks)
			lcp = filepath.Clean(lcp)

			// Skip if we are matching the original (above) mount-spec.
			if lcp == source && lcp == dest {
				continue
			}

			// if the lcp is underneath the source, ignore it
			if !strings.HasPrefix(lcp, source+"/") {
				m := specs.Mount{
					Source:      lcp,
					Destination: lcp,
					Type:        mountType,
					Options:     mountOpt,
				}
				mounts = append(mounts, m)
			}
		}
	}

	return mounts, nil
}

// finds longest-common-path among the given absolute paths
func longestCommonPath(paths []string) string {

	if len(paths) == 0 {
		return ""
	} else if len(paths) == 1 {
		return paths[0]
	}

	// find the shortest and longest paths in the set
	shortest, longest := paths[0], paths[0]
	for _, p := range paths[1:] {
		if p < shortest {
			shortest = p
		} else if p > longest {
			longest = p
		}
	}

	// find the first 'i' common characters between the shortest and longest paths
	lcp := shortest
	for i := 0; i < len(shortest) && i < len(longest); i++ {
		if shortest[i] != longest[i] {
			lcp = shortest[:i]
			break
		}
	}

	// if the longest common prefix does not end on a path separator, we may
	// have left a path component truncated, and we need to strip it off
	// (the longest common path of "/root/aba" and "/root/aca" is "/root/" and not "/root/a")
	if !strings.HasSuffix(lcp, "/") {
		// in the case we have something like "/root/a" and "/root/a/b", no need to strip "a" off
		if (len(lcp) < len(shortest) && shortest[len(lcp)] != '/') ||
			(len(lcp) < len(longest) && longest[len(lcp)] != '/') {
			if idx := strings.LastIndex(lcp, "/"); idx != -1 {
				lcp = lcp[:idx]
			}
		}
	}

	return lcp
}

// returns a list of all symbolic links under the given directory
func followSymlinksUnder(dir string) ([]string, error) {

	// walk dir; if file is symlink (use os.Lstat()), readlink() and add to slice
	symlinks := []string{}

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		var (
			fi       os.FileInfo
			realpath string
			link     string
		)

		if path == dir {
			return nil
		}
		fi, err = os.Lstat(path)
		if err != nil {
			return fmt.Errorf("failed to lstat %s: %v", path, err)
		}
		if fi.Mode()&os.ModeSymlink == 0 {
			return nil
		}

		link, err = os.Readlink(path)
		if err != nil {
			return fmt.Errorf("failed to resolve symlink at %s: %v", path, err)
		}

		if filepath.IsAbs(link) {
			realpath = link
		} else {
			realpath = filepath.Join(filepath.Dir(path), link)
		}

		symlinks = append(symlinks, realpath)
		return nil
	})

	if err != nil {
		return nil, err
	}

	return symlinks, nil
}

func mntSrcUidShiftNeeded(mntSrc string, uid, gid uint32) (bool, uint32, uint32, error) {

	// The determination on whether to uid-shift the given mount source directory
	// is done by checking the ownership of the dir and the first level subdirs
	// under it (if any), and comparing their owner:group versus that of the
	// container's root user. This heuristic works well for the mounts for which
	// we normally do preps (e.g., mounts over the container's /var/lib/docker,
	// /var/lib/kubelet, etc.). We want to avoid an exhaustive check as it can be
	// quite slow if the directory hierarchy underneath the mount source is
	// extensive (e.g., if we are bind-mounting a fully populated docker cache on
	// the host to the container's /var/lib/docker).

	var mntSrcUid, mntSrcGid uint32

	// mnt src ownership check
	fi, err := os.Stat(mntSrc)
	if err != nil {
		return false, 0, 0, err
	}

	st, _ := fi.Sys().(*syscall.Stat_t)

	mntSrcUid = st.Uid
	mntSrcGid = st.Gid

	// If the host uid assigned to the container's root user differs from the
	// uid of the dir being mounted into the container, then we perform uid
	// shifting. Same for gid.
	if uid != mntSrcUid && gid != mntSrcGid {
		return true, mntSrcUid, mntSrcGid, nil
	}

	// If the mount dir has same ownership as the container, check the subdirs
	// before we make a determination on whether ownership shifting will be
	// required.
	dirFis := []os.FileInfo{}

	dirFis, err = ioutil.ReadDir(mntSrc)
	if err != nil {
		return false, 0, 0, err
	}

	numNeedChown := 0
	for _, fi := range dirFis {
		st, _ := fi.Sys().(*syscall.Stat_t)
		if uid != st.Uid || gid != st.Gid {
			numNeedChown += 1
		}
	}

	needChown := (numNeedChown == len(dirFis))

	return needChown, mntSrcUid, mntSrcGid, nil
}

func preFlightCheck() error {
	for _, prog := range progDeps {
		if !libutils.CmdExists(prog) {
			return fmt.Errorf("%s is not installed on host.", prog)
		}
	}

	// Required to allow dummy configfs folders to be exposed inside containers.
	if err := exec.Command("modprobe", "configfs").Run(); err != nil {
		return fmt.Errorf("failed to modprobe configfs: %s", err)
	}

	return nil
}

func getInode(file string) (uint64, error) {
	var st unix.Stat_t

	if err := unix.Stat(file, &st); err != nil {
		return 0, fmt.Errorf("unable to stat %s: %s", file, err)
	}

	return st.Ino, nil
}
