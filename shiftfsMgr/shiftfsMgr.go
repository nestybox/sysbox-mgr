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

// The shiftfs manager performs shiftfs marks/unmarks on the sys container's rootfs
// and other mountpoins (e.g., bind-mount sources).
//
// When multiple sys containers share bind-mounts, the shiftfs manager ensures that
// shiftfs is only marked once on the bind mount and that the mark is removed when the
// last container associated with it is destroyed.

package shiftfsMgr

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"

	uuid "github.com/google/uuid"
	"github.com/nestybox/sysbox-libs/formatter"
	intf "github.com/nestybox/sysbox-mgr/intf"
	"github.com/nestybox/sysbox-runc/libsysbox/shiftfs"
	"github.com/opencontainers/runc/libcontainer/configs"
	"github.com/sirupsen/logrus"
)

type mgr struct {
	workDir     string
	mreqCntrMap map[string][]string // Maps shiftfs mount request paths to the associated container(s) IDs.
	mpMreqMap   map[string]string   // Maps each shiftfs markpoint path to it's corresponding mount request path.
	mu          sync.Mutex
}

// Creates a new instance of the shiftfs manager
func New(sysboxLibDir string) (intf.ShiftfsMgr, error) {

	// Load the shiftfs module (if present in the kernel)
	exec.Command("modprobe", "shiftfs").Run()

	workDir := filepath.Join(sysboxLibDir, "shiftfs")

	if err := os.MkdirAll(workDir, 0700); err != nil {
		return nil, err
	}

	return &mgr{
		workDir:     workDir,
		mreqCntrMap: make(map[string][]string),
		mpMreqMap:   make(map[string]string),
	}, nil

}

// Creates a shiftfs "mark" mount over the given path list, to prepare them for
// uid-shifting. If "createMarkpoint" is true, then this function creates new
// mountpoint directories for each of the given paths, under the shiftfs-mgr
// work dir (e.g., /var/lib/sysbox/shiftfs/<uuid>), and mounts shiftfs with
// something equivalent to:
//
// mount -t shiftfs -o mark <mount-path> /var/lib/sysbox/shiftfs/<uuid>
//
// If createMarkpoint is false, then this function does something equivalent to:
//
// mount -t shiftfs -o mark <mount-path> <mount-path>
//
// Creating a separate markpoint is useful when the caller does not wish to set
// the shiftfs mark directly over the given paths, as doing so makes them
// implicitly "no-exec" and in addition can result in a security risk because it
// would allow unprivileged users to unshare their user-ns and mount shiftfs on
// those same paths, thereby gaining root access to them. Both of these issues
// are solve by placing the shiftfs mark over a separate markpoint directory
// under root-only access (such as /var/lib/sysbox).
//
// Returns the list of shiftfs markpoints.

func (sm *mgr) Mark(id string, mountReqs []configs.ShiftfsMount, createMarkpoint bool) ([]configs.ShiftfsMount, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	markpoints := []configs.ShiftfsMount{}

	for _, mntReq := range mountReqs {

		mntReqPath := mntReq.Source

		// if mount request path is in the mount-req-to-container map, add the container-id to the entry
		ids, found := sm.mreqCntrMap[mntReqPath]
		if found {
			ids = append(ids, id)
			sm.mreqCntrMap[mntReqPath] = ids

			// Get the markpoint for the mount request path and add it to the list
			// of markpoints we will return.
			for mp, mrp := range sm.mpMreqMap {
				if mrp == mntReqPath {
					markpoints = append(markpoints, configs.ShiftfsMount{Source: mp})
					break
				}
			}

			continue
		}

		// if shiftfs already marked, no action (some entity other than sysbox did the
		// marking; we don't track that)
		mounted, err := shiftfs.Mounted(mntReqPath)
		if err != nil {
			return nil, fmt.Errorf("error while checking for existing shiftfs mount on %s: %v", mntReqPath, err)
		}
		if mounted {
			markpoints = append(markpoints, mntReq)
			logrus.Debugf("skipped shiftfs mark on %s (already mounted)", mntReqPath)
			continue
		}

		markpoint := mntReqPath

		if createMarkpoint {
			mntUuid := uuid.New().String()
			markpoint = filepath.Join(sm.workDir, mntUuid)
			if err := os.Mkdir(markpoint, 0700); err != nil {
				return nil, err
			}
		}

		if err := shiftfs.Mark(mntReqPath, markpoint); err != nil {
			return nil, err
		}

		sm.mpMreqMap[markpoint] = mntReqPath
		sm.mreqCntrMap[mntReqPath] = []string{id}

		markpoints = append(markpoints, configs.ShiftfsMount{Source: markpoint})

		logrus.Debugf("marked shiftfs for %s at %s", mntReqPath, markpoint)
	}

	return markpoints, nil
}

func (sm *mgr) Unmark(id string, markpoints []configs.ShiftfsMount) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	for _, mp := range markpoints {
		markpoint := mp.Source

		// Lookup the mount request path for the given markpoint
		// we may not find it in the markpoint map if we skipped it in Mark()
		// (e.g., because it was already mounted by some other entity)
		mntReqPath, found := sm.mpMreqMap[markpoint]
		if !found {
			continue
		}

		// Lookup the containers associated with this mount request path
		ids, ok := sm.mreqCntrMap[mntReqPath]
		if !ok {
			logrus.Warnf("shiftfs unmark error: mount request path %s expected to be in container map but it's not.",
				mntReqPath)
			continue
		}

		// Remove matching container-id from mreqCntrMap entry
		ids, err := removeID(ids, id)
		if err != nil {
			return fmt.Errorf("did not find container id %s in mount-point map entry for %s",
				formatter.ContainerID{id}, mntReqPath)
		}

		// If after removal the mreqCntrMap entry is empty it means there are no more containers
		// associated with that mount, so we proceed to remove the shiftfs mark. Otherwise,
		// we simply update the mreqCntrMap entry.

		if len(ids) == 0 {
			if err := shiftfs.Unmount(markpoint); err != nil {
				return err
			}

			hasUuidMarkpoint := filepath.HasPrefix(markpoint, sm.workDir)

			if hasUuidMarkpoint {
				if err := os.Remove(markpoint); err != nil {
					return err
				}
			}

			delete(sm.mpMreqMap, markpoint)
			delete(sm.mreqCntrMap, mntReqPath)

			logrus.Debugf("unmarked shiftfs for %s at %s", mntReqPath, markpoint)

		} else {
			sm.mreqCntrMap[mntReqPath] = ids
		}
	}

	return nil
}

func (sm *mgr) UnmarkAll() {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	for mp := range sm.mpMreqMap {
		if err := shiftfs.Unmount(mp); err != nil {
			logrus.Warnf("failed to unmark shiftfs on %s: %s", mp, err)
		}

		hasUuidMarkpoint := filepath.HasPrefix(mp, sm.workDir)

		if hasUuidMarkpoint {
			if err := os.Remove(mp); err != nil {
				logrus.Warnf("failed to remove %s: %s", mp, err)
			}
		}

		logrus.Debugf("unmarked shiftfs on %s", mp)
		delete(sm.mpMreqMap, mp)
	}
}

// Removes element 'elem' from the given string slice
func removeID(ids []string, elem string) ([]string, error) {
	var (
		i     int
		id    string
		found bool = false
	)

	for i, id = range ids {
		if id == elem {
			found = true
			break
		}
	}

	if !found {
		return []string{}, fmt.Errorf("not found")
	}

	ids[i] = ids[len(ids)-1]
	return ids[:len(ids)-1], nil
}
