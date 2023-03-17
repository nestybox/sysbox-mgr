//
// Copyright 2022 Nestybox, Inc.
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

package rootfsCloner

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/nestybox/sysbox-libs/formatter"
	"github.com/nestybox/sysbox-libs/mount"
	"github.com/sirupsen/logrus"
)

const clonerDir string = "rootfs"

type cloneInfo struct {
	origRootfsMntInfo *mount.Info
	newRootfsDir      string
	ovfsMount         ovfsMntInfo
	bindMounts        []bindMnt
	chownUidOffset    int32
	chownGidOffset    int32
	bindToSelfActive  bool
}

type cloner struct {
	hostDir string
	clones  map[string]*cloneInfo // container-ID -> cloneInfo
	mu      sync.Mutex
}

type ovfsMntInfo struct {
	mergedDir string
	diffDir   string
	workDir   string
}

type bindMnt struct {
	src string
	dst string
}

func New(hostDir string) *cloner {
	return &cloner{
		hostDir: hostDir,
		clones:  make(map[string]*cloneInfo),
	}
}

func (c *cloner) CreateClone(id, origRootfs string) (string, error) {

	logrus.Debugf("Prep rootfs cloning for container %s", formatter.ContainerID{id})

	// Check if this is a redundant clone
	c.mu.Lock()
	_, found := c.clones[id]
	c.mu.Unlock()

	if found {
		return "", fmt.Errorf("redundant rootfs clone for container %s",
			formatter.ContainerID{id})
	}

	// Get the mount info for the orig rootfs
	allMounts, err := mount.GetMounts()
	if err != nil {
		return "", err
	}

	origRootfsMntInfo, err := mount.GetMountAt(origRootfs, allMounts)
	if err != nil {
		return "", fmt.Errorf("failed to get mount info for mount at %s: %s", origRootfs, err)
	}

	// We only support cloning of rootfs on overlayfs currently
	if origRootfsMntInfo.Fstype != "overlay" {
		return "", fmt.Errorf("rootfs cloning is only supported for overlayfs; rootfs at %s is not on overlayfs", origRootfs)
	}

	// Create the dir under which we will create the cloned rootfs
	origRootfsDir := filepath.Dir(origRootfs)
	newRootfsDir := filepath.Join(c.hostDir, clonerDir, id)

	perm, err := filePerm(origRootfsDir)
	if err != nil {
		return "", fmt.Errorf("failed to get permissions for %s: %s", origRootfsDir, err)
	}

	if err := os.MkdirAll(newRootfsDir, perm); err != nil {
		return "", err
	}

	ci := &cloneInfo{
		origRootfsMntInfo: origRootfsMntInfo,
		newRootfsDir:      newRootfsDir,
	}

	subdir := filepath.Join(newRootfsDir, "overlay2")

	ovfsMntInfo := ovfsMntInfo{
		mergedDir: filepath.Join(subdir, "merged"),
		diffDir:   filepath.Join(subdir, "diff"),
		workDir:   filepath.Join(subdir, "work"),
	}

	if err := createNewOvfsDir(ovfsMntInfo); err != nil {
		return "", err
	}

	ci.ovfsMount = ovfsMntInfo

	if err := mountClone(ci); err != nil {
		return "", fmt.Errorf("failed to mount clone for container %s: %s",
			formatter.ContainerID{id}, err)
	}

	c.mu.Lock()
	c.clones[id] = ci
	c.mu.Unlock()

	return ci.ovfsMount.mergedDir, nil
}

func (c *cloner) RemoveClone(id string) error {

	logrus.Debugf("Removing rootfs clone for container %s", formatter.ContainerID{id})

	c.mu.Lock()
	ci, found := c.clones[id]
	c.mu.Unlock()

	if !found {
		return fmt.Errorf("did not find rootfs clone info for container %s",
			formatter.ContainerID{id})
	}

	if err := unmountClone(ci); err != nil {
		return fmt.Errorf("failed to unmount clone for container %s: %s",
			formatter.ContainerID{id}, err)
	}

	if err := os.RemoveAll(ci.newRootfsDir); err != nil {
		return fmt.Errorf("failed to remove clone for container %s: %s",
			formatter.ContainerID{id}, err)
	}

	c.mu.Lock()
	delete(c.clones, id)
	c.mu.Unlock()

	return nil
}

func (c *cloner) ChownClone(id string, uidOffset, gidOffset int32) error {

	logrus.Debugf("Chown rootfs clone for container %s (%d:%d)", formatter.ContainerID{id}, uidOffset, gidOffset)

	c.mu.Lock()
	ci, found := c.clones[id]
	c.mu.Unlock()

	if !found {
		return fmt.Errorf("did not find rootfs clone info for container %s",
			formatter.ContainerID{id})
	}

	if err := doChown(ci, uidOffset, gidOffset); err != nil {
		return err
	}

	// Remember the chown offsets (so we can revert it)
	ci.chownUidOffset = uidOffset
	ci.chownGidOffset = gidOffset

	c.mu.Lock()
	c.clones[id] = ci
	c.mu.Unlock()

	return nil
}

func (c *cloner) RevertChown(id string) error {

	logrus.Debugf("Revert chown rootfs clone for container %s", formatter.ContainerID{id})

	c.mu.Lock()
	ci, found := c.clones[id]
	c.mu.Unlock()

	if !found {
		return fmt.Errorf("did not find rootfs clone info for container %s",
			formatter.ContainerID{id})
	}

	uidOffset := 0 - int32(ci.chownUidOffset)
	gidOffset := 0 - int32(ci.chownGidOffset)

	if err := doChown(ci, uidOffset, gidOffset); err != nil {
		return fmt.Errorf("failed to chown cloned rootfs for container %s: %s",
			formatter.ContainerID{id}, err)
	}

	c.mu.Lock()
	c.clones[id] = ci
	c.mu.Unlock()

	return nil
}

func (c *cloner) ContainerStopped(id string) error {

	c.mu.Lock()
	defer c.mu.Unlock()

	ci, found := c.clones[id]
	if !found {
		return fmt.Errorf("did not find rootfs clone info for container %s",
			formatter.ContainerID{id})
	}

	// Docker hack: when Docker stops the container, it will remove the ovfs
	// mount over the container's rootfs. This will cause it to remove the
	// bind-to-self mount we created on top of it (on purpose) rather than the
	// underlying ovfs mount. Variable bindToSelfActive tracks this, such that
	// the rootfs cloner is aware of this and won't remove that mount (since
	// Docker already removed it).

	ci.bindToSelfActive = false
	c.clones[id] = ci

	return nil
}

func (c *cloner) RemoveAll() {
	for id, _ := range c.clones {
		if err := c.RemoveClone(id); err != nil {
			logrus.Warnf("rootfsCloner cleanup error: failed to remove rootfs clone %s: %s",
				formatter.ContainerID{id}, err)
		}
	}
}
