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
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/mrunalp/fileutils"
	"github.com/nestybox/sysbox-mgr/intf"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

// The docker storage directory can't be on the following filesystems, as docker inside
// the sys container uses overlayfs for its images and overlayfs can't be mounted on top
// of these.
var unsupportedFs = map[string]int64{
	"tmpfs":        unix.TMPFS_MAGIC,
	"overlayfs":    unix.OVERLAYFS_SUPER_MAGIC,
	"nbox_shiftfs": 0x6e627366,
}

var checkUnsupportedFs = true // unit tests set this to false to ease testing

type mgr struct {
	hostDir string
}

// Creates a new instance of the docker-store volume manager.
// 'hostDir' is the directory on the host which the manager will use for its operations
func New(hostDir string) (intf.VolMgr, error) {
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
	logrus.Debugf("New docker store volume manager; host dir = %v", hostDir)
	return &mgr{
		hostDir: hostDir,
	}, nil
}

// Implements intf.VolMgr.CreateVol
func (dsm *mgr) CreateVol(id string, rootfs string, mountpoint string, uid, gid uint32, shiftUids bool) ([]specs.Mount, error) {
	volPath := filepath.Join(dsm.hostDir, id)
	mountPath := filepath.Join(rootfs, mountpoint)
	mounts := []specs.Mount{}

	if _, err := os.Stat(volPath); err == nil {
		return mounts, fmt.Errorf("volume for container %v already exists", id)
	}

	if err := os.Mkdir(volPath, 0700); err != nil {
		return mounts, fmt.Errorf("failed to create volume for container %v: %v", id, err)
	}

	// Set the ownership of the newly created volume to match the given uid(gid); this
	// ensures that the container will have permission to access the volume. Note that by
	// doing this, we also ensure that sysbox-runc won't mount shiftfs on top of the
	// volume (which is important because Docker inside the sys container will mount
	// overlayfs on this volume and overlayfs can't be mounted on top of shiftfs).
	if err := os.Chown(volPath, int(uid), int(gid)); err != nil {
		return mounts, fmt.Errorf("failed to set ownership of volume %v: %v", volPath, err)
	}

	// copy contents of container's mountpoint (if any) to the newly created volume
	if _, err := os.Stat(mountPath); err == nil {
		if err := fileutils.CopyDirectory(mountPath, volPath); err != nil {
			os.RemoveAll(volPath)
			return mounts, fmt.Errorf("failed to copy container's %v to host volume %v: %v", mountPath, volPath, err)
		}
	}

	// If uid shifting is enabled in the sys container, manually shift the ownership of all
	// copied files & directories (since shiftfs won't be mounted on this volume).
	if shiftUids {
		err := filepath.Walk(volPath, func(path string, fi os.FileInfo, err error) error {
			if err == nil {
				if path != volPath {
					return shiftOwner(path, fi, uid, gid)
				}
			}
			return err
		})
		if err != nil {
			os.RemoveAll(volPath)
			return mounts, fmt.Errorf("failed to shift ownership on host vol %v: %v", volPath, err)
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
	volPath := filepath.Join(dsm.hostDir, id)

	if _, err := os.Stat(volPath); err != nil {
		if os.IsNotExist(err) {
			return nil
		} else {
			return fmt.Errorf("failed to stat %v: %v", volPath, err)
		}
	}

	if err := os.RemoveAll(volPath); err != nil {
		return fmt.Errorf("failed to remove %v: %v", volPath, err)
	}

	logrus.Debugf("Destroyed docker store volume at %v", volPath)
	return nil
}

func shiftOwner(path string, fi os.FileInfo, uid, gid uint32) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("failed to stat %v", path)
	}

	// shift uid ownership from N to uid + N; same for gid
	volUid := st.Uid + uid
	volGid := st.Gid + gid

	if err := os.Chown(path, int(volUid), int(volGid)); err != nil {
		return fmt.Errorf("failed to change uid(gid) from %v:%v to %v:%v for %v: %v",
			st.Uid, st.Gid, volUid, volGid, path, err)
	}

	return nil
}
