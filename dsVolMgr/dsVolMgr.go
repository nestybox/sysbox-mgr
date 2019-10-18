//
// Copyright: (C) 2019 Nestybox Inc.  All rights reserved.
//

// The docker-store volume manager creates and removes directories on the host that back
// the sys container's Docker storage area (typically "/var/lib/docker"). This functionality
// is needed in order to:
//
// * Remove the requirement for storing sysbox system container images in a filesystem
//   that supports Docker-in-Docker (e.g., btrfs).
//
// * Allow Docker-in-Docker when the outer docker is using uid-shifting
//   (via the shiftfs module). This is needed because the inner Docker mounts overlayfs on
//   top of the container images on `/var/lib/docker/`, but overlayfs does not work when
//   mounted on top of shiftfs, so shiftfs can't be mounted on `/var/lib/docker`.
//
// See sysbox github issue #46 (https://github.com/nestybox/sysbox/issues/46) for
// further details.

package dsVolMgr

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"

	"github.com/nestybox/sysbox-mgr/intf"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

// The docker storage directory can't be on the following filesystems, as docker inside
// the sys container uses overlayfs for its images and overlayfs can't be mounted on top
// of these.
const SHIFTFS_MAGIC int64 = 0x6a656a62

var unsupportedFs = map[string]int64{
	"tmpfs":     unix.TMPFS_MAGIC,
	"overlayfs": unix.OVERLAYFS_SUPER_MAGIC,
	"shiftfs":   SHIFTFS_MAGIC,
}

var checkUnsupportedFs = true // unit tests set this to false to ease testing

type volInfo struct {
	volPath   string // volume path in host
	mountPath string // container path where volume is mounted
	uid       uint32 // uid owner for container
	gid       uint32 // gid owner for container
	shiftUids bool   // uid(gid) shifting enabled for the volume
}

type mgr struct {
	hostDir            string
	disableDockerMount bool
	volTable           map[string]volInfo // cont id -> volume info
	mu                 sync.Mutex
}

// Creates a new instance of the docker-store volume manager.
// 'hostDir' is the directory on the host which the manager will use for its operations
func New(hostDir string, disableDockerMount bool) (intf.VolMgr, error) {
	if checkUnsupportedFs {
		var statfs syscall.Statfs_t
		if err := syscall.Statfs(hostDir, &statfs); err != nil {
			return nil, fmt.Errorf("failed to find filesystem info for %s", hostDir)
		}
		for name, magic := range unsupportedFs {
			if statfs.Type == magic {
				return nil, fmt.Errorf("host dir for docker store (%s) can't be on %v", hostDir, name)
			}
		}
	}
	if disableDockerMount {
		logrus.Infof("Auto-mounts over /var/lib/docker disabled (except when using uid-shifting); backing dir = %v", hostDir)
	} else {
		logrus.Infof("Auto-mounts over /var/lib/docker enabled; backing dir = %v", hostDir)
	}
	return &mgr{
		hostDir:            hostDir,
		disableDockerMount: disableDockerMount,
		volTable:           make(map[string]volInfo),
	}, nil
}

// Implements intf.VolMgr.CreateVol
func (dsm *mgr) CreateVol(id, rootfs, mountpoint string, uid, gid uint32, shiftUids bool) ([]specs.Mount, error) {
	var err error

	// Docker mount disabling is only allowed when uid shifting is off (sysbox issue #93).
	if dsm.disableDockerMount && !shiftUids {
		return []specs.Mount{}, nil
	}

	volPath := filepath.Join(dsm.hostDir, id)
	mountPath := filepath.Join(rootfs, mountpoint)

	mounts := []specs.Mount{}
	if _, err = os.Stat(volPath); err == nil {
		return mounts, fmt.Errorf("volume directory for container %v already exists", id)
	}

	// create volume info
	dsm.mu.Lock()
	if _, found := dsm.volTable[id]; found {
		dsm.mu.Unlock()
		return mounts, fmt.Errorf("volume for container %v already exists", id)
	}
	vi := volInfo{
		volPath:   volPath,
		mountPath: mountPath,
		uid:       uid,
		gid:       gid,
		shiftUids: shiftUids,
	}
	dsm.volTable[id] = vi
	dsm.mu.Unlock()

	defer func() {
		if err != nil {
			dsm.mu.Lock()
			delete(dsm.volTable, id)
			dsm.mu.Unlock()
		}
	}()

	if err = os.Mkdir(volPath, 0700); err != nil {
		return mounts, fmt.Errorf("failed to create volume for container %v: %v", id, err)
	}

	// Set the ownership of the newly created volume to match the given uid(gid); this
	// ensures that the container will have permission to access the volume. Note that by
	// doing this, we also ensure that sysbox-runc won't mount shiftfs on top of the
	// volume (which is important because Docker inside the sys container will mount
	// overlayfs on this volume and overlayfs can't be mounted on top of shiftfs).
	if err = os.Chown(volPath, int(uid), int(gid)); err != nil {
		os.RemoveAll(volPath)
		return mounts, fmt.Errorf("failed to set ownership of volume %v: %v", volPath, err)
	}

	// sync the contents of container's mountpoint (if any) to the newly created volume ("sync-in")
	if _, err := os.Stat(mountPath); err == nil {
		if err = dsm.rsyncVol(mountPath, volPath, uid, gid, shiftUids); err != nil {
			os.RemoveAll(volPath)
			return mounts, fmt.Errorf("volume sync-in failed: %v", err)
		}
	}

	m := specs.Mount{
		Source:      volPath,
		Destination: mountpoint,
		Type:        "bind",
		Options:     []string{"rbind", "rprivate"},
	}
	mounts = append(mounts, m)

	logrus.Debugf("Created docker store volume at %v", volPath)
	return mounts, nil
}

// Implements intf.VolMgr.DestroyVol
func (dsm *mgr) DestroyVol(id string) error {

	dsm.mu.Lock()
	vi, found := dsm.volTable[id]
	if !found {
		dsm.mu.Unlock()
		return fmt.Errorf("failed to find vol info for container %s", id)
	}
	volPath := vi.volPath
	dsm.mu.Unlock()

	if _, err := os.Stat(volPath); err != nil {
		return fmt.Errorf("failed to stat %v: %v", volPath, err)
	}

	if err := os.RemoveAll(volPath); err != nil {
		return fmt.Errorf("failed to remove %v: %v", volPath, err)
	}

	dsm.mu.Lock()
	delete(dsm.volTable, id)
	dsm.mu.Unlock()

	logrus.Debugf("Destroyed docker store volume at %v", volPath)
	return nil
}

// Implements intf.VolMgr.SyncOut
func (dsm *mgr) SyncOut(id string) error {

	dsm.mu.Lock()
	vi, found := dsm.volTable[id]
	if !found {
		dsm.mu.Unlock()
		return fmt.Errorf("failed to find vol info for container %s", id)
	}
	dsm.mu.Unlock()

	// mountPath is the sync-out target; if it does not exist, create it (but only if we
	// are going to be copying anything to it).
	if _, err := os.Stat(vi.mountPath); os.IsNotExist(err) {
		volIsEmpty, err := dirIsEmpty(vi.volPath)
		if err != nil {
			return fmt.Errorf("error while checking if %s is empty: %s", vi.volPath, err)
		}
		if !volIsEmpty {
			if err := os.MkdirAll(vi.mountPath, 0700); err != nil {
				return fmt.Errorf("failed to create directory %s: %s", vi.mountPath, err)
			}
		}
	}

	// if the sync-out target exists, perform the rsync
	if _, err := os.Stat(vi.mountPath); err == nil {
		if err := dsm.rsyncVol(vi.volPath, vi.mountPath, 0, 0, vi.shiftUids); err != nil {
			return fmt.Errorf("volume sync-out failed: %v", err)
		}
	}

	return nil
}

// rsyncVol performs an rsync from src to dest; if shiftUids is true, the rsync
// modifies the ownership of files copied to dest to match the givne uid(gid).
func (dsm *mgr) rsyncVol(src, dest string, uid, gid uint32, shiftUids bool) error {

	var cmd *exec.Cmd
	var stdout, stderr bytes.Buffer

	srcDir := src + "/"

	if shiftUids {
		chown := "--chown=" + strconv.FormatUint(uint64(uid), 10) + ":" + strconv.FormatUint(uint64(gid), 10)
		cmd = exec.Command("rsync", "-ravuq", "--delete", chown, srcDir, dest)
	} else {
		cmd = exec.Command("rsync", "-ravuq", "--delete", srcDir, dest)
	}

	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("failed to rsync %s to %s: %v %v\n", srcDir, dest, string(stdout.Bytes()), string(stderr.Bytes()))
	}

	logrus.Debugf("rsync'd %s to %s", srcDir, dest)
	return nil
}

func dirIsEmpty(name string) (bool, error) {
	f, err := os.Open(name)
	if err != nil {
		return false, err
	}
	defer f.Close()

	_, err = f.Readdirnames(1)
	if err == io.EOF {
		return true, nil
	}

	return false, err
}
