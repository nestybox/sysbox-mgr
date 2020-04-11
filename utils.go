//
// Copyright: (C) 2019 Nestybox Inc.  All rights reserved.
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
	"syscall"

	"github.com/nestybox/sysbox-mgr/dockerVolMgr"
	intf "github.com/nestybox/sysbox-mgr/intf"
	"github.com/nestybox/sysbox-mgr/lib/dockerUtils"
	"github.com/nestybox/sysbox-mgr/subidAlloc"
	"github.com/nestybox/sysbox-mgr/volMgr"
	"github.com/opencontainers/runc/libcontainer/mount"
	"github.com/opencontainers/runc/libcontainer/user"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
	"golang.org/x/sys/unix"
)

const SHIFTFS_MAGIC int64 = 0x6a656a62

var progDeps = []string{"rsync", "modprobe"}

func cmdExists(name string) bool {
	cmd := exec.Command("/bin/sh", "-c", "command -v "+name)
	if err := cmd.Run(); err != nil {
		return false
	}
	return true
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
			sortedSubID = append(sortedSubID, user.SubID{"sysbox", int64(holeStart), int64(size)})
			return sortedSubID, nil
		}

		holeStart = uint64(id.SubID + id.Count)
	}

	holeEnd = max
	if holeEnd-holeStart < size {
		return sortedSubID, fmt.Errorf("failed to allocate %d subids in range %d, %d", size, min, max)
	}

	sortedSubID = append(sortedSubID, user.SubID{"sysbox", int64(holeStart), int64(size)})
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
	var reusePol subidAlloc.ReusePolicy

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

	logrus.Infof("Subid allocation range: start = %v, size = %v", subUidMin, subidRangeSize)

	if ctx.GlobalString("subid-policy") == "no-reuse" {
		reusePol = subidAlloc.NoReuse
		logrus.Infof("Subid allocation exhaust policy set to \"no-reuse\"")
	} else {
		reusePol = subidAlloc.Reuse
		logrus.Infof("Subid allocation exhaust policy set to \"reuse\"")
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

	subidAlloc, err := subidAlloc.New("sysbox", "exclusive", reusePol, subuidSrc, subgidSrc)
	if err != nil {
		return nil, err
	}

	return subidAlloc, nil
}

func setupDsVolMgr(ctx *cli.Context) (intf.VolMgr, error) {
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
			return nil, fmt.Errorf("host dir for docker store (%s) can't be on %v", hostDir, name)
		}
	}

	innerImgSharing := !ctx.GlobalBool("no-inner-docker-image-sharing")

	if innerImgSharing {
		logrus.Infof("Inner docker image sharing enabled.")
	} else {
		logrus.Infof("Inner docker image sharing disabled.")
	}

	return dockerVolMgr.New(hostDir, innerImgSharing)
}

func setupKsVolMgr(ctx *cli.Context) (intf.VolMgr, error) {

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
			return nil, fmt.Errorf("host dir for kubelet store (%s) can't be on %v", hostDir, name)
		}
	}

	return volMgr.New(hostDir)
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
	if err == nil && docker.IsDockerContainer(id) {
		if strings.Contains(rootfs, "overlay2") && filepath.Base(rootfs) == "merged" {
			return filepath.Dir(rootfs)
		}
	}

	return rootfs
}

// createPidFile writes the sysbox pid to a file. If the file already exists (e.g.,
// another sysbox instance is running), returns error.
func createPidFile(pidFile string) error {

	_, err := os.Stat(pidFile)
	if err == nil {
		return fmt.Errorf("%s exists", pidFile)
	} else if !os.IsNotExist(err) {
		return err
	}

	pidStr := fmt.Sprintf("%d\n", os.Getpid())
	if err := ioutil.WriteFile(pidFile, []byte(pidStr), 0400); err != nil {
		return fmt.Errorf("failed to write sysbox pid to file %s: %s", pidFile, err)
	}

	return nil
}

func destroyPidFile(pidFile string) error {
	return os.RemoveAll(pidFile)
}
