//
// Copyright 2019-2021 Nestybox, Inc.
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
	"strings"
	"sync"

	"github.com/nestybox/sysbox-libs/formatter"
	"github.com/nestybox/sysbox-libs/idShiftUtils"
	mount "github.com/nestybox/sysbox-libs/mount"
	overlayUtils "github.com/nestybox/sysbox-libs/overlayUtils"
	utils "github.com/nestybox/sysbox-libs/utils"
	"github.com/nestybox/sysbox-mgr/intf"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"
)

type volInfo struct {
	volPath     string      // volume path in host
	rootfs      string      // container rootfs
	mountPath   string      // container path where volume is mounted
	syncOutPath string      // container path for volume sync-out
	uid         uint32      // uid owner for container
	gid         uint32      // gid owner for container
	shiftUids   bool        // uid(gid) shifting enabled for the volume
	perm        os.FileMode // permissions for the volume
}

type vmgr struct {
	name     string
	hostDir  string
	sync     bool
	volTable map[string]volInfo // cont id -> volume info
	mu       sync.Mutex
}

type shiftType int

const (
	shiftUp shiftType = iota
	shiftDown
)

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
	if _, err = os.Stat(volPath); err == nil {
		return nil, fmt.Errorf("volume dir for container %v already exists", id)
	}

	mountPath := filepath.Join(rootfs, mountpoint)

	rootfsOnOvfs, rootfsOvfsUpper, err := isRootfsOnOverlayfs(rootfs)
	if err != nil {
		return nil, err
	}

	// When the container stops and we need to copy the volume contents back to
	// the container's rootfs. We call this "sync-out", and syncOutPath is the
	// path were we want to copy to.
	syncOutPath := mountPath

	// If the container rootfs is on overlayfs, the syncOutPath can't be the
	// overlayfs merged dir. That's because sysbox-runc may have remounted that
	// in the container's mount ns (e.g., when using id-mapping on the rootfs),
	// so sysbox-mgr won't have access to it. Instead the syncOutPath is the
	// overlayfs "upper" dir.
	if rootfsOnOvfs {
		syncOutPath = filepath.Join(rootfsOvfsUpper, mountpoint)
	}

	// create volume info
	m.mu.Lock()
	if _, found := m.volTable[id]; found {
		m.mu.Unlock()
		return nil, fmt.Errorf("volume for container %v already exists", id)
	}
	vi := volInfo{
		volPath:     volPath,
		rootfs:      rootfs,
		mountPath:   mountPath,
		syncOutPath: syncOutPath,
		uid:         uid,
		gid:         gid,
		shiftUids:   shiftUids,
		perm:        perm,
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

	if shiftUids {
		if err = os.Chown(volPath, int(uid), int(gid)); err != nil {
			os.RemoveAll(volPath)
			return nil, fmt.Errorf("failed to set ownership of volume %v: %v", volPath, err)
		}
	}

	if m.sync {
		// Sync the contents of container's mountpoint to the newly created volume ("sync-in")
		if _, err := os.Stat(mountPath); err == nil {
			if err = m.rsyncVol(mountPath, volPath, uid, gid, shiftUids, shiftUp); err != nil {
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

	// if the sync out target does not exist, create it (but only if we are going
	// to be copying anything to it).
	if _, err := os.Stat(vi.syncOutPath); os.IsNotExist(err) {
		volIsEmpty, err := dirIsEmpty(vi.volPath)
		if err != nil {
			return fmt.Errorf("error while checking if %s is empty: %s", vi.volPath, err)
		}
		if !volIsEmpty {
			if err := os.MkdirAll(vi.syncOutPath, vi.perm); err != nil {
				return fmt.Errorf("failed to create directory %s: %s", vi.syncOutPath, err)
			}
		}
	}

	// If the sync-out target exists, perform the rsync
	if _, err := os.Stat(vi.syncOutPath); err == nil {
		if err := m.rsyncVol(vi.volPath, vi.syncOutPath, vi.uid, vi.gid, vi.shiftUids, shiftDown); err != nil {

			// For sync-outs, the operation may fail if the target is removed while
			// we are doing the copy. In this case we ignore the error since there
			// is no data loss (the data being sync'd out would have been removed
			// anyways).

			_, err2 := os.Stat(vi.syncOutPath)
			if err2 != nil && os.IsNotExist(err2) {
				logrus.Debugf("%s: volume sync-out for container %s skipped: target %s does not exist",
					m.name, formatter.ContainerID{id}, vi.syncOutPath)
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

// rsyncVol performs an rsync from src to dest. If shiftUids is true, it also
// performs filesystem user-ID and group-ID shifting (via chown) using an
// offset specified via uid and gid.
//
// Note that depending no how much data is transferred, this operation can
// result in many file descriptors being opened by rsync, which the kernel may
// account to sysbox-mgr. Thus, the file open limit for sysbox-mgr should be
// very high / unlimited since the number of open files depends on how much data
// there is to copy and how many containers are active at a given time.
func (m *vmgr) rsyncVol(src, dest string, uid, gid uint32, shiftUids bool, shiftT shiftType) error {

	var cmd *exec.Cmd
	var output bytes.Buffer
	var usermap, groupmap string

	if shiftUids {
		srcUidList, srcGidList, err := idShiftUtils.GetDirIDs(src)
		if err != nil {
			return fmt.Errorf("failed to get user and group IDs for %s: %s", src, err)
		}

		// Get the usermap and groupmap options to pass to rsync
		usermap = rsyncIdMapOpt(srcUidList, uid, shiftT)
		groupmap = rsyncIdMapOpt(srcGidList, gid, shiftT)

		if usermap != "" {
			usermap = "--usermap=" + usermap
		}

		if groupmap != "" {
			groupmap = "--groupmap=" + groupmap
		}
	}

	// Note: rsync uses file modification time and size to determine if a sync is
	// needed. This should be fine for sync'ing the sys container's directories,
	// assuming the probability of files being different yet having the same size &
	// timestamp is low. If this assumption changes we could pass the `--checksum` option
	// to rsync, but this will slow the copy operation significantly.
	srcDir := src + "/"

	if usermap == "" && groupmap == "" {
		cmd = exec.Command("rsync", "-rauqlH", "--no-devices", "--delete", srcDir, dest)
	} else if usermap != "" && groupmap == "" {
		cmd = exec.Command("rsync", "-rauqlH", "--no-devices", "--delete", usermap, srcDir, dest)
	} else if usermap == "" && groupmap != "" {
		cmd = exec.Command("rsync", "-rauqlH", "--no-devices", "--delete", groupmap, srcDir, dest)
	} else {
		cmd = exec.Command("rsync", "-rauqlH", "--no-devices", "--delete", usermap, groupmap, srcDir, dest)
	}

	cmd.Stdout = &output
	cmd.Stderr = &output

	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("rsync %s to %s: %v %v", srcDir, dest, string(output.Bytes()), err)
	}

	return nil
}

func rsyncIdMapOpt(idList []uint32, offset uint32, shiftT shiftType) string {
	var destId uint32

	mapOpt := ""
	for _, srcId := range idList {
		if shiftT == shiftUp {
			destId = srcId + offset
		} else {
			destId = srcId - offset
		}
		mapOpt += fmt.Sprintf("%d:%d,", srcId, destId)
	}

	if mapOpt != "" {
		mapOpt = strings.TrimSuffix(mapOpt, ",")
	}

	return mapOpt
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

func isRootfsOnOverlayfs(rootfs string) (bool, string, error) {

	fsName, err := utils.GetFsName(rootfs)
	if err != nil {
		return false, "", err
	}

	if fsName != "overlayfs" {
		return false, "", nil
	}

	mounts, err := mount.GetMountsPid(uint32(os.Getpid()))
	if err != nil {
		return false, "", err
	}

	// If the rootfs is not a mountpoint, return false.
	mi, err := mount.GetMountAt(rootfs, mounts)
	if err != nil {
		return false, "", nil
	}

	ovfsMntOpts := overlayUtils.GetMountOpt(mi)
	ovfsUpperLayer := overlayUtils.GetUpperLayer(ovfsMntOpts)

	return true, ovfsUpperLayer, nil
}
