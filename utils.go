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
	"path/filepath"
	"sort"
	"strconv"
	"strings"
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

	// TODO: lock the /etc/subuid(gid) file (?)

	var buf bytes.Buffer
	for _, id := range subID {
		l := fmt.Sprintf("%s:%d:%d\n", id.Name, id.SubID, id.Count)
		buf.WriteString(l)
	}

	return ioutil.WriteFile(path, []byte(buf.String()), 644)
}

func configSubidRange(path string, size, min, max uint64) error {

	subID, err := user.ParseSubIDFile(path)
	if err != nil {
		return fmt.Errorf("error parsing file %s: %s", path, err)
	}

	// Remove existing config for user sysbox
	//
	// TODO: this only handles zero or one entries for user "sysbox" in the subuid file;
	// it's possible (but rare) that there are multiple such entries though.

	index := -1
	for i, id := range subID {
		if id.Name == "sysbox" {
			if uint64(id.Count) == size {
				return nil
			}
			index = i
		}
	}

	if index >= 0 {
		copy(subID[index:], subID[index+1:])
		subID = subID[:len(subID)-1]
	}

	subID, err = allocSubidRange(subID, size, min, max)
	if err != nil {
		return fmt.Errorf("failed to configure subid range for sysbox: %s", err)
	}

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

	// check if these defaults are overriden by login.defs; if login.defs does not exist, move on.
	f, err := os.Open(file)
	if err != nil {
		return limits, nil
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "SUB_UID_MIN") {
			valStr := strings.Split(line, " ")[1]
			limits[0], err = strconv.ParseUint(valStr, 10, 64)
		}
		if strings.Contains(line, "SUB_UID_MAX") {
			valStr := strings.Split(line, " ")[1]
			limits[1], err = strconv.ParseUint(valStr, 10, 64)
		}
		if strings.Contains(line, "SUB_GID_MIN") {
			valStr := strings.Split(line, " ")[1]
			limits[2], err = strconv.ParseUint(valStr, 10, 64)
		}
		if strings.Contains(line, "SUB_GID_MAX") {
			valStr := strings.Split(line, " ")[1]
			limits[3], err = strconv.ParseUint(valStr, 10, 64)
		}
		if err != nil {
			return limits, fmt.Errorf("failed to parse line %s: %s", line, err)
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
		if statfs.Type == magic {
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
		if statfs.Type == magic {
			return nil, fmt.Errorf("host dir for kubelet vol manager (%s) can't be on %v", hostDir, name)
		}
	}

	return volMgr.New("kubeletVolMgr", hostDir, true)
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
		if statfs.Type == magic {
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
		return err
	}
	if err := os.MkdirAll(sysboxLibDir, 0700); err != nil {
		return err
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
	if _, err := os.Stat(sysboxLibDir); err == nil {
		if err := removeDirContents(sysboxLibDir); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}

	return nil
}

func removeDirContents(path string) error {
	dir, err := ioutil.ReadDir(path)
	if err != nil {
		return fmt.Errorf("ReadDir(%v) failed: %v", path, err)
	}
	for _, d := range dir {
		if err := os.RemoveAll(filepath.Join(path, d.Name())); err != nil {
			return fmt.Errorf("RemoveAll(%v) failed: %v", filepath.Join(path, d.Name()), err)
		}
	}
	return nil
}

func rChown(path string, uid, gid uint32) error {
	return filepath.Walk(path, func(name string, info os.FileInfo, err error) error {
		if err == nil {
			err = os.Chown(name, int(uid), int(gid))
			if os.IsNotExist(err) {
				logrus.Debugf("failed to change ownership of %s: %s", name, err)
				return nil
			}
		}
		return err
	})
}

// Sanitize the given container's rootfs.
func sanitizeRootfs(id, rootfs string) string {

	// Docker containers on overlayfs have a rootfs under "/var/lib/docker/overlay2/<container-id>/merged".
	// However, Docker removes the "merged" directory during container stop and re-creates
	// it during container start. Thus, we can't rely on the presence of "merged" to
	// determine if a container was stopped or removed. Instead, we use the rootfs path up
	// to <container-id>.

	docker, err := dockerUtils.DockerConnect()
	if err != nil {
		return rootfs
	}
	defer docker.Disconnect()

	if docker.ContainerIsDocker(id) {
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
	for i := 0; i < len(shortest) && i < len(longest); i++ {
		if shortest[i] != longest[i] {
			return shortest[:i]
		}
	}

	return shortest
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
