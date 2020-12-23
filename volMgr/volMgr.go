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

// The volume manager manages a directory on the host that is bind-mounted into the sys
// container, typically to overcome problems that arise if those directories were to be on
// the sys container's rootfs (which typically uses overlayfs or shiftfs-on-overlayfs
// mounts when uid shifting is enabled). The bind-mount overcomes these problems since the
// source of the mount is a directory that is on the host's filesystem (typically ext4).
//
// The volume manager takes care of ensuring that the backing host directory has correct
// ownership to allow sys container root processes to access it, and also handles copying
// contents from the sys container rootfs to the backing dir when the container is started,
// and vice-versa when container is stopped or paused.

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

	"github.com/nestybox/sysbox-libs/formatter"
	"github.com/nestybox/sysbox-mgr/intf"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"
)

type volInfo struct {
	volPath   string      // volume path in host
	rootfs    string      // container rootfs
	mountPath string      // container path where volume is mounted
	uid       uint32      // uid owner for container
	gid       uint32      // gid owner for container
	shiftUids bool        // uid(gid) shifting enabled for the volume
	perm      os.FileMode // permissions for the volume
}

type vmgr struct {
	name     string
	hostDir  string
	sync     bool
	volTable map[string]volInfo // cont id -> volume info
	mu       sync.Mutex
}

// Creates a new instance of the volume manager.
// 'name' is the name for this volume manager.
// 'hostDir' is the directory on the host which the manager will use for its operations.
// 'sync' indicates if the volume contents should be sync'd with those of the mountpoint.
func New(name, hostDir string, sync bool) (intf.VolMgr, error) {
	return &vmgr{
		name:     name,
		hostDir:  hostDir,
		sync:     sync,
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
		rootfs:    rootfs,
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

	if m.sync {
		// sync the contents of container's mountpoint to the newly created volume ("sync-in")
		if _, err := os.Stat(mountPath); err == nil {
			if err = m.rsyncVol(mountPath, volPath, uid, gid, shiftUids); err != nil {
				os.RemoveAll(volPath)
				return nil, fmt.Errorf("volume sync-in failed: %v", err)
			}
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

	logrus.Debugf("%s: created volume for container %s",
		m.name, formatter.ContainerID{id})

	return mounts, nil
}

// Implements intf.VolMgr.DestroyVol
func (m *vmgr) DestroyVol(id string) error {

	m.mu.Lock()
	vi, found := m.volTable[id]
	if !found {
		m.mu.Unlock()
		return fmt.Errorf("failed to find vol info for container %s",
			formatter.ContainerID{id})
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

	logrus.Debugf("%s: destroyed volume for container %s",
		m.name, formatter.ContainerID{id})

	return nil
}

// Implements intf.VolMgr.SyncOut
func (m *vmgr) SyncOut(id string) error {

	if !m.sync {
		return nil
	}

	m.mu.Lock()
	vi, found := m.volTable[id]
	if !found {
		m.mu.Unlock()
		return fmt.Errorf("failed to find vol info for container %s",
			formatter.ContainerID{id})
	}
	m.mu.Unlock()

	// If the container's rootfs is gone, bail
	if _, err := os.Stat(vi.rootfs); os.IsNotExist(err) {
		logrus.Debugf("%s: volume sync-out for container %s skipped: target %s does not exist",
			m.name, formatter.ContainerID{id}, vi.rootfs)
		return nil
	}

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

	// If the sync-out target exists, perform the rsync
	if _, err := os.Stat(vi.mountPath); err == nil {
		if err := m.rsyncVol(vi.volPath, vi.mountPath, 0, 0, vi.shiftUids); err != nil {

			// For sync-outs, the operation may fail if the target is removed while
			// we are doing the copy. In this case we ignore the error since there
			// is no data loss (the data being sync'd out would have been removed
			// anyways).

			_, err2 := os.Stat(vi.mountPath)
			if err2 != nil && os.IsNotExist(err2) {
				logrus.Debugf("%s: volume sync-out for container %s skipped: target %s does not exist",
					m.name, formatter.ContainerID{id}, vi.mountPath)
				return nil
			}

			return fmt.Errorf("volume sync-out failed: %v", err)
		}
	}

	logrus.Debugf("%s: sync'd-out volume for container %s",
		m.name, formatter.ContainerID{id})

	return nil
}

// Implements intf.VolMgr.SyncOutAndDestroyAll
func (m *vmgr) SyncOutAndDestroyAll() {
	for id, _ := range m.volTable {
		if err := m.SyncOut(id); err != nil {
			logrus.Warnf("%s: failed to sync-out volumes for container %s: %s",
				m.name, formatter.ContainerID{id}, err)
		}
		if err := m.DestroyVol(id); err != nil {
			logrus.Warnf("%s: failed to destroy volumes for container %s: %s",
				m.name, formatter.ContainerID{id}, err)
		}
	}
}

// rsyncVol performs an rsync from src to dest; if shiftUids is true, the rsync
// modifies the ownership of files copied to dest to match the given uid(gid).
func (m *vmgr) rsyncVol(src, dest string, uid, gid uint32, shiftUids bool) error {

	var cmd *exec.Cmd
	var output bytes.Buffer

	srcDir := src + "/"

	// Note: rsync uses file modification time and size to determine if a sync is
	// needed. This should be fine for sync'ing the sys container's directories,
	// assuming the probability of files being different yet having the same size &
	// timestamp is low. If this assumption changes we could pass the `--checksum` option
	// to rsync, but this will slow the copy operation significantly.

	if shiftUids {
		chown := "--chown=" + strconv.FormatUint(uint64(uid), 10) + ":" + strconv.FormatUint(uint64(gid), 10)
		cmd = exec.Command("rsync", "-rauqlH", "--no-specials", "--no-devices", "--delete", chown, srcDir, dest)
	} else {
		cmd = exec.Command("rsync", "-rauqlH", "--no-specials", "--no-devices", "--delete", srcDir, dest)
	}

	cmd.Stdout = &output
	cmd.Stderr = &output

	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("failed to sync %s to %s: %v %v", srcDir, dest, string(output.Bytes()), err)
	}

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
