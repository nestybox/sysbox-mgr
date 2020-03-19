//
// Copyright: (C) 2019 Nestybox Inc.  All rights reserved.
//

// The volume manager manages a directory on the host that is bind-mounted into the sys
// container, typically to overcome problems that arise if those directories were to be on
// the sys container's rootfs (which typically uses overlayfs or shiftfs-on-overlayfs
// mounts when uid shifting is enabled). The bind-mount overcomes these problems since the
// source of the mount is a directory that is on the host's filesystem (typically ext4).
//
// The volume manager takes care of ensuring that the backing host directory has correct
// ownership to allow sys container root processes to access it, and also handles copying
// contents from the sys container to the bind-mount source and vice-versa when the
// container is started, stopped, or paused.

package volMgr

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"

	"github.com/nestybox/sysbox-mgr/intf"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"
)

type volInfo struct {
	volPath   string      // volume path in host
	mountPath string      // container path where volume is mounted
	uid       uint32      // uid owner for container
	gid       uint32      // gid owner for container
	shiftUids bool        // uid(gid) shifting enabled for the volume
	perm      os.FileMode // permissions for the volume
}

type vmgr struct {
	hostDir  string
	volTable map[string]volInfo // cont id -> volume info
	mu       sync.Mutex
}

// Creates a new instance of the volume manager.
// 'hostDir' is the directory on the host which the manager will use for its operations
func New(hostDir string) (intf.VolMgr, error) {
	return &vmgr{
		hostDir:  hostDir,
		volTable: make(map[string]volInfo),
	}, nil
}

// Implements intf.VolMgr.CreateVol
func (m *vmgr) CreateVol(id, rootfs, mountpoint string, uid, gid uint32, shiftUids bool, perm os.FileMode) ([]specs.Mount, error) {
	var err error

	volPath := filepath.Join(m.hostDir, id)
	mountPath := filepath.Join(rootfs, mountpoint)

	if _, err = os.Stat(volPath); err == nil {
		return nil, fmt.Errorf("volume dir for container %v already exists", id)
	}

	// create volume info
	m.mu.Lock()
	if _, found := m.volTable[id]; found {
		m.mu.Unlock()
		return nil, fmt.Errorf("volume for container %v already exists", id)
	}
	vi := volInfo{
		volPath:   volPath,
		mountPath: mountPath,
		uid:       uid,
		gid:       gid,
		shiftUids: shiftUids,
		perm:      perm,
	}
	m.volTable[id] = vi
	m.mu.Unlock()

	defer func() {
		if err != nil {
			m.mu.Lock()
			delete(m.volTable, id)
			m.mu.Unlock()
		}
	}()

	if err = os.Mkdir(volPath, perm); err != nil {
		return nil, fmt.Errorf("failed to create volume for container %v: %v", id, err)
	}

	// Set the ownership of the newly created volume to match the given uid(gid); this
	// ensures that the container will have permission to access the volume. Note that by
	// doing this, we also ensure that sysbox-runc won't mount shiftfs on top of the
	// volume.
	if err = os.Chown(volPath, int(uid), int(gid)); err != nil {
		os.RemoveAll(volPath)
		return nil, fmt.Errorf("failed to set ownership of volume %v: %v", volPath, err)
	}

	// sync the contents of container's mountpoint (if any) to the newly created volume ("sync-in")
	if _, err := os.Stat(mountPath); err == nil {
		if err = m.rsyncVol(mountPath, volPath, uid, gid, shiftUids); err != nil {
			os.RemoveAll(volPath)
			return nil, fmt.Errorf("volume sync-in failed: %v", err)
		}
	}

	mounts := []specs.Mount{
		{
			Source:      volPath,
			Destination: mountpoint,
			Type:        "bind",
			Options:     []string{"rbind", "rprivate"},
		},
	}

	logrus.Debugf("Created volume at %v", volPath)
	return mounts, nil
}

// Implements intf.VolMgr.DestroyVol
func (m *vmgr) DestroyVol(id string) error {

	m.mu.Lock()
	vi, found := m.volTable[id]
	if !found {
		m.mu.Unlock()
		return fmt.Errorf("failed to find vol info for container %s", id)
	}
	volPath := vi.volPath
	m.mu.Unlock()

	if _, err := os.Stat(volPath); err != nil {
		return fmt.Errorf("failed to stat %v: %v", volPath, err)
	}

	if err := os.RemoveAll(volPath); err != nil {
		return fmt.Errorf("failed to remove %v: %v", volPath, err)
	}

	m.mu.Lock()
	delete(m.volTable, id)
	m.mu.Unlock()

	logrus.Debugf("Destroyed volume at %v", volPath)
	return nil
}

// Implements intf.VolMgr.SyncOut
func (m *vmgr) SyncOut(id string) error {

	m.mu.Lock()
	vi, found := m.volTable[id]
	if !found {
		m.mu.Unlock()
		return fmt.Errorf("failed to find vol info for container %s", id)
	}
	m.mu.Unlock()

	// mountPath is the sync-out target; if it does not exist, create it (but only if we
	// are going to be copying anything to it).
	if _, err := os.Stat(vi.mountPath); os.IsNotExist(err) {
		volIsEmpty, err := dirIsEmpty(vi.volPath)
		if err != nil {
			return fmt.Errorf("error while checking if %s is empty: %s", vi.volPath, err)
		}
		if !volIsEmpty {
			if err := os.MkdirAll(vi.mountPath, vi.perm); err != nil {
				return fmt.Errorf("failed to create directory %s: %s", vi.mountPath, err)
			}
		}
	}

	// if the sync-out target exists, perform the rsync
	if _, err := os.Stat(vi.mountPath); err == nil {
		if err := m.rsyncVol(vi.volPath, vi.mountPath, 0, 0, vi.shiftUids); err != nil {
			return fmt.Errorf("volume sync-out failed: %v", err)
		}
	}

	return nil
}

// rsyncVol performs an rsync from src to dest; if shiftUids is true, the rsync
// modifies the ownership of files copied to dest to match the givne uid(gid).
func (m *vmgr) rsyncVol(src, dest string, uid, gid uint32, shiftUids bool) error {

	var cmd *exec.Cmd
	var stdout, stderr bytes.Buffer

	srcDir := src + "/"

	// Note: rsync uses file modification time and size to determine if a sync is
	// needed. This should be fine for sync'ing the sys container's directories given,
	// assuming the probability of files being different yet having the same size &
	// timestamp is low. If this assumption changes we could pass the `--checksum` option
	// to rsync, but this will slow the copy operation significantly.

	if shiftUids {
		chown := "--chown=" + strconv.FormatUint(uint64(uid), 10) + ":" + strconv.FormatUint(uint64(gid), 10)
		cmd = exec.Command("rsync", "-rauqH", "--delete", chown, srcDir, dest)
	} else {
		cmd = exec.Command("rsync", "-rauqH", "--delete", srcDir, dest)
	}

	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("failed to sync %s to %s: %v %v\n", srcDir, dest, string(stdout.Bytes()), string(stderr.Bytes()))
	}

	logrus.Debugf("sync'd %s to %s", srcDir, dest)
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
