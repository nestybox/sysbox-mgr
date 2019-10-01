//
// Copyright: (C) 2019 Nestybox Inc.  All rights reserved.
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
	"sync"

	intf "github.com/nestybox/sysbox-mgr/intf"
	"github.com/nestybox/sysbox-runc/libsysbox/shiftfs"
	"github.com/opencontainers/runc/libcontainer/configs"
	"github.com/opencontainers/runc/libcontainer/mount"
	"github.com/sirupsen/logrus"
)

var testingMode bool = false

type mgr struct {
	mpMap map[string][]string // maps each shiftfs markpoint to all it's associated container(s)
	mu    sync.Mutex          // protects the mark point map
}

// Creates a new instance of the shiftfs manager
func New() (intf.ShiftfsMgr, error) {
	return &mgr{
		mpMap: make(map[string][]string),
	}, nil
}

func (sm *mgr) Mark(id string, mounts []configs.ShiftfsMount) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	for _, m := range mounts {

		// if mount in mpMap, add container-id to mpMap entry
		ids, found := sm.mpMap[m.Source]
		if found {
			ids = append(ids, id)
			sm.mpMap[m.Source] = ids
			continue
		}

		if !testingMode {

			// if shiftfs already marked, no action (some entity other than sysbox did the
			// marking; we don't track that)

			mounted, err := mount.MountedWithFs(m.Source, "shiftfs")
			if err != nil {
				return fmt.Errorf("error while checking for existing shiftfs mount on %s: %v", m.Source, err)
			}
			if mounted {
				logrus.Debugf("skipped shiftfs mark on %s (already mounted by some other entity)", m.Source)
				continue
			}
			if err := shiftfs.Mark(m.Source); err != nil {
				return err
			}
			logrus.Debugf("marked shiftfs on %s", m.Source)
		}

		sm.mpMap[m.Source] = []string{id}
	}

	return nil
}

func (sm *mgr) Unmark(id string, mount []configs.ShiftfsMount) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	for _, m := range mount {
		ids, found := sm.mpMap[m.Source]
		if !found {
			return fmt.Errorf("did not find shiftfs mount %s in mount-point map", m.Source)
		}

		// Remove matching container-id from mpMap entry
		ids, err := removeID(ids, id)
		if err != nil {
			return fmt.Errorf("did not find container id %s in mount-point map entry for %s", id, m.Source)
		}

		// If after removal the mpMap entry is empty it means there are no more containers
		// associated with that mount, so we proceed to remove the shiftfs mark. Otherwise,
		// we simply update the mpMap entry.
		if len(ids) == 0 {
			if !testingMode {
				if err := shiftfs.Unmount(m.Source); err != nil {
					return err
				}
				logrus.Debugf("unmarked shiftfs on %s", m.Source)
			}
			delete(sm.mpMap, m.Source)
		} else {
			sm.mpMap[m.Source] = ids
		}
	}

	return nil
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
