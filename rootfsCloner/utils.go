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
	"strings"

	mapset "github.com/deckarep/golang-set"
	"github.com/nestybox/sysbox-runc/libcontainer/mount"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	sh "github.com/nestybox/sysbox-libs/idShiftUtils"
)

func createNewOvfsDir(info ovfsMntInfo) error {
	subdirs := []string{info.mergedDir, info.diffDir, info.workDir}

	for _, subdir := range subdirs {
		if err := os.MkdirAll(subdir, 0755); err != nil {
			return err
		}
	}

	return nil
}

func filePerm(path string) (os.FileMode, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return os.FileMode(0), err
	}
	return fi.Mode().Perm(), nil
}

// Creates the cloned rootfs overlayfs mounts and bind-mounts over the orig rootfs.
func mountClone(ci *cloneInfo) error {

	if err := setupBottomMount(ci); err != nil {
		return fmt.Errorf("failed to set up bottom ovfs mount: %v", err)
	}

	if err := setupTopMount(ci); err != nil {
		return fmt.Errorf("failed to set up top ovfs mount: %v", err)
	}

	if err := bindOrigRootfs(ci); err != nil {
		return fmt.Errorf("failed to bind mount over orig rootfs: %v", err)
	}

	if err := bindToSelfOrigRootfs(ci); err != nil {
		return fmt.Errorf("failed to bind-to-self over orig rootfs: %v", err)
	}

	ci.bindToSelfActive = true

	return nil
}

func unmountClone(ci *cloneInfo) error {

	if ci.bindToSelfActive {
		if err := unbindToSelfOrigRootfs(ci); err != nil {
			logrus.Errorf("failed to remove bind-to-self mount over orig rootfs: %s", err)
		}
	}

	if err := unbindOrigRootfs(ci); err != nil {
		logrus.Errorf("failed to remove bind mounts over orig rootfs: %s", err)
	}

	if err := removeTopMount(ci); err != nil {
		return fmt.Errorf("failed to remove top mount: %s", err)
	}

	if err := removeBottomMount(ci); err != nil {
		return fmt.Errorf("failed to remove bottom mount: %s", err)
	}

	return nil
}

// Sets up the overlayfs bottom mount; it uses the same lower layers as the
// original rootfs mount, but adds metacopy=on. Ths mount lives inside the
// sysbox data root directory (e.g., /var/lib/sysbox/rootfs/<id>/bottom/merged)
func setupBottomMount(ci *cloneInfo) error {

	mergedDir := ci.bottomMount.mergedDir
	diffDir := ci.bottomMount.diffDir
	workDir := ci.bottomMount.workDir

	// This gets us the orig rootfs ovfs mount options, and adds metacopy=on to them
	mntFlags, options, propFlags := getBottomMountOpt(ci.origRootfsMntInfo, []interface{}{"metacopy=on"})

	// Replace the original upperdir and workdir with the bottom mount ones
	tmpOpt := ""
	for _, opt := range strings.Split(options, ",") {
		if strings.Contains(opt, "upperdir=") {
			opt = "upperdir=" + diffDir
		} else if strings.Contains(opt, "workdir=") {
			opt = "workdir=" + workDir
		}
		tmpOpt += opt + ","
	}
	options = strings.TrimSuffix(tmpOpt, ",")

	if err := unix.Mount("overlay", mergedDir, "overlay", uintptr(mntFlags), options); err != nil {
		return fmt.Errorf("failed to mount overlayfs on %s: %s", mergedDir, err)
	}

	if err := unix.Mount("", mergedDir, "", uintptr(propFlags), ""); err != nil {
		return fmt.Errorf("failed to set mount prop flags on %s: %s", mergedDir, err)
	}

	return nil
}

// Removes the overlayfs bottom mount
func removeBottomMount(ci *cloneInfo) error {
	return unix.Unmount(ci.bottomMount.mergedDir, unix.MNT_DETACH)
}

// Sets up the overlayfs top mount; it uses the bottom mount's merged dir as its
// lower layer. This mount lives inside the sysbox data root directory (e.g.,
// /var/lib/sysbox/rootfs/<id>/top/merged) and serves as the container's rootfs.
func setupTopMount(ci *cloneInfo) error {

	lowerDir := ci.bottomMount.mergedDir
	diffDir := ci.topMount.diffDir
	workDir := ci.topMount.workDir
	mergedDir := ci.topMount.mergedDir

	// This gets us the orig rootfs ovfs mount options
	mntFlags, options, propFlags := getBottomMountOpt(ci.origRootfsMntInfo, []interface{}{""})

	// Replace the original ovfs lowerdir, upperdir, and workdir with the top mount ones
	tmpOpt := ""
	for _, opt := range strings.Split(options, ",") {
		if strings.Contains(opt, "lowerdir=") {
			opt = "lowerdir=" + lowerDir
		} else if strings.Contains(opt, "upperdir=") {
			opt = "upperdir=" + diffDir
		} else if strings.Contains(opt, "workdir=") {
			opt = "workdir=" + workDir
		}
		tmpOpt += opt + ","
	}
	options = strings.TrimSuffix(tmpOpt, ",")

	if err := unix.Mount("overlay", mergedDir, "overlay", uintptr(mntFlags), options); err != nil {
		return fmt.Errorf("failed to mount overlayfs on %s: %s", mergedDir, err)
	}

	if err := unix.Mount("", mergedDir, "", uintptr(propFlags), ""); err != nil {
		return fmt.Errorf("failed to set mount prop flags on %s: %s", mergedDir, err)
	}

	return nil
}

// Removes the overlayfs top mount
func removeTopMount(ci *cloneInfo) error {
	return unix.Unmount(ci.topMount.mergedDir, unix.MNT_DETACH)
}

// Bind-mounts the cloned rootfs over the original rootfs. Adds the new mounts
// to the cloneInfo struct.
func bindOrigRootfs(ci *cloneInfo) error {
	var origDiffDir, origWorkDir string
	var bindMounts []bindMnt

	mi := ci.origRootfsMntInfo
	vfsOpts := mi.VfsOpts
	origRootfs := mi.Mountpoint

	// Find the upperdir and workdir of the original rootfs ovfs mount
	for _, opt := range strings.Split(vfsOpts, ",") {
		if strings.Contains(opt, "upperdir=") {
			origDiffDir = strings.TrimPrefix(opt, "upperdir=")
		}
		if strings.Contains(opt, "workdir=") {
			origWorkDir = strings.TrimPrefix(opt, "workdir=")
		}
	}

	if origDiffDir == "" || origWorkDir == "" {
		return fmt.Errorf("failed to parse overlayfs mount options for mountpoint %s", origRootfs)
	}

	// Bind mount the top mount's merged and diff dirs over the orig rootfs;
	// these bind mounts are kept when the container is stopped, and only deleted
	// when the container is removed. They ensure that higher level operations that operate on
	// the container's original rootfs work (e.g., docker commit, docker build, docker cp).
	bindMounts = append(bindMounts, bindMnt{src: ci.topMount.mergedDir, dst: origRootfs})
	bindMounts = append(bindMounts, bindMnt{src: ci.topMount.diffDir, dst: origDiffDir})

	if err := bindMountOverOrigRootfs(bindMounts); err != nil {
		return err
	}

	ci.bindMounts = bindMounts
	return nil
}

func unbindOrigRootfs(ci *cloneInfo) error {

	for _, m := range ci.bindMounts {
		if _, err := os.Stat(m.dst); os.IsNotExist(err) {
			continue
		}
		if err := unix.Unmount(m.dst, unix.MNT_DETACH); err != nil {
			return err
		}
	}

	ci.bindMounts = nil
	return nil
}

func bindToSelfOrigRootfs(ci *cloneInfo) error {

	// Create a redundant bind-to-self mount over the original rootfs. This way,
	// if the higher level container manager (e.g., Docker) tries to unmount the
	// rootfs ovfs mount when the container stops, it will unmount the redundant
	// mount we just created.  This means the rootfs ovfs mount stays in place
	// when the container is stopped, and therefore won't be remounted when the
	// container restarts. Such a remounting would fail because of the bind
	// mounts that sysbox created over the ovfs diff and work dirs. This is a
	// hacky solution, but we could not find another one. All this will go away
	// once idmapped mounts are supported on overlayfs, at which point the
	// rootfsCloner won't be needed anymore.

	origRootfs := ci.origRootfsMntInfo.Mountpoint
	return unix.Mount(origRootfs, origRootfs, "", unix.MS_BIND|unix.MS_REC, "")
}

func unbindToSelfOrigRootfs(ci *cloneInfo) error {
	origRootfs := ci.origRootfsMntInfo.Mountpoint
	return unix.Unmount(origRootfs, unix.MNT_DETACH)
}

// Computes the lower overlayfs mount flags, mount options, and propagation flags.
func getBottomMountOpt(origRootfsMntInfo *mount.Info, wantOpts []interface{}) (int, string, int) {

	// Convert mount opts to a mapset; in the process replace the upperdir and
	// workdir options with the new ones.

	currVfsOpts := mapset.NewSet()
	for _, opt := range strings.Split(origRootfsMntInfo.VfsOpts, ",") {
		currVfsOpts.Add(opt)
	}

	currMntOpts := mapset.NewSet()
	for _, opt := range strings.Split(origRootfsMntInfo.Opts, ",") {
		currMntOpts.Add(opt)
	}

	// Add "metacopy=on" to the existing mount options
	wantVfsOpts := mapset.NewSetFromSlice(wantOpts)
	addVfsOpts := wantVfsOpts.Difference(currVfsOpts)

	// The vfs opts reported by mountinfo are a combination of per superblock
	// mount opts and the overlayfs-specific data; we need to separate these so
	// we can do the mount properly.
	properMntOpts := mapset.NewSetFromSlice([]interface{}{
		"ro", "rw", "nodev", "noexec", "nosuid", "noatime", "nodiratime", "relatime", "strictatime", "sync",
	})

	newMntOpts := currVfsOpts.Intersect(properMntOpts)

	newVfsOpts := currVfsOpts.Difference(properMntOpts)
	newVfsOpts = newVfsOpts.Union(addVfsOpts)

	// Convert the mount options to the mount flags
	newMntOptsString := []string{}
	for _, opt := range newMntOpts.ToSlice() {
		newMntOptsString = append(newMntOptsString, fmt.Sprintf("%s", opt))
	}
	mntFlags := mount.OptionsToFlags(newMntOptsString)

	// Convert the vfs option set to the mount data string
	newVfsOptsString := ""
	for i, opt := range newVfsOpts.ToSlice() {
		if i != 0 {
			newVfsOptsString += ","
		}
		newVfsOptsString += fmt.Sprintf("%s", opt)
	}

	// Set the mount propagation flags as they were in the original mount
	// (shared, slave, etc.)
	propFlags := 0

	if strings.Contains(origRootfsMntInfo.Optional, "shared") {
		propFlags |= unix.MS_SHARED
	} else if strings.Contains(origRootfsMntInfo.Optional, "master") {
		propFlags |= unix.MS_SLAVE
	} else if strings.Contains(origRootfsMntInfo.Optional, "unbindable") {
		propFlags |= unix.MS_UNBINDABLE
	} else {
		propFlags |= unix.MS_PRIVATE
	}

	return mntFlags, newVfsOptsString, propFlags
}

func bindMountOverOrigRootfs(bindMounts []bindMnt) error {
	var ferr error

	failed := false
	mounted := []string{}

	for _, m := range bindMounts {
		if err := unix.Mount(m.src, m.dst, "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
			failed = true
			ferr = fmt.Errorf("failed to bind mount %s to %s: %s", m.src, m.dst, err)
		}
		mounted = append(mounted, m.dst)
	}

	// Cleanup in case a bind-mount fails
	if failed {
		for _, m := range mounted {
			unix.Unmount(m, unix.MNT_DETACH)
		}
		return ferr
	}

	return nil
}

func doChown(ci *cloneInfo, uidOffset, gidOffset int32) error {

	if ci.bindToSelfActive {
		if err := unbindToSelfOrigRootfs(ci); err != nil {
			return err
		}
	}

	if err := unbindOrigRootfs(ci); err != nil {
		return err
	}

	if err := removeTopMount(ci); err != nil {
		return err
	}

	// chown the bottom ovfs mount (fast because metacopy=on is set on it)
	if err := sh.ShiftIdsWithChown(ci.bottomMount.mergedDir, uidOffset, gidOffset); err != nil {
		return fmt.Errorf("failed to chown cloned rootfs bottom mount at %s by offset %d, %d: %s",
			ci.bottomMount.mergedDir, uidOffset, gidOffset, err)
	}

	// chown the top ovfs mount (fast because the chown is on the diff dir, not on the merged dir)
	if err := sh.ShiftIdsWithChown(ci.topMount.diffDir, uidOffset, gidOffset); err != nil {
		return fmt.Errorf("failed to chown cloned rootfs top mount at %s by offset %d, %d: %s",
			ci.topMount.diffDir, uidOffset, gidOffset, err)
	}

	if err := setupTopMount(ci); err != nil {
		return err
	}

	if err := bindOrigRootfs(ci); err != nil {
		return err
	}

	if ci.bindToSelfActive {
		if err := bindToSelfOrigRootfs(ci); err != nil {
			return err
		}
	}

	return nil
}
