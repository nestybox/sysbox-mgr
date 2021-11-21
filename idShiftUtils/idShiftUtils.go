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

// Utilities for shifting user and group IDs on the file system

package idShiftUtils

import (
	"fmt"
	"os"
	"strconv"
	"syscall"

	"github.com/joshlf/go-acl"
	aclLib "github.com/joshlf/go-acl"
	"github.com/karrick/godirwalk"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	mapset "github.com/deckarep/golang-set"
)

type aclType int

const (
	aclTypeAccess aclType = iota
	aclTypeDefault
)

// Shifts the ACL type user and group IDs by the given offset
func shiftAclType(aclT aclType, path string, uidOffset, gidOffset int32) error {
	var facl aclLib.ACL
	var err error

	// Read the ACL
	if aclT == aclTypeDefault {
		facl, err = acl.GetDefault(path)
	} else {
		facl, err = acl.Get(path)
	}

	if err != nil {
		return fmt.Errorf("failed to get ACL for %s: %s", path, err)
	}

	// Shift the user and group ACLs (if any)
	newACL := aclLib.ACL{}
	aclShifted := false

	for _, e := range facl {

		// ACL_USER id shifting
		if e.Tag == aclLib.TagUser {
			uid, err := strconv.ParseUint(e.Qualifier, 10, 32)
			if err != nil {
				logrus.Warnf("failed to convert ACL qualifier for %v: %s", e, err)
				continue
			}

			targetUid := uint64(int32(uid) + uidOffset)
			e.Qualifier = strconv.FormatUint(targetUid, 10)
			aclShifted = true
		}

		// ACL_GROUP id shifting
		if e.Tag == aclLib.TagGroup {
			gid, err := strconv.ParseUint(e.Qualifier, 10, 32)
			if err != nil {
				logrus.Warnf("failed to convert ACL qualifier %v: %s", e, err)
				continue
			}

			targetGid := uint64(int32(gid) + gidOffset)
			e.Qualifier = strconv.FormatUint(targetGid, 10)
			aclShifted = true
		}

		newACL = append(newACL, e)
	}

	// Write back the modified ACL
	if aclShifted {

		logrus.Debugf("shifting ACLs for %s", path)

		if aclT == aclTypeDefault {
			err = acl.SetDefault(path, newACL)
		} else {
			err = acl.Set(path, newACL)
		}
		if err != nil {
			return fmt.Errorf("failed to set ACL %v for %s: %s", newACL, path, err)
		}

		logrus.Debugf("ACL shift for %s done", path)
	}

	return nil
}

// Shifts the ACL user and group IDs by the given offset, both for access and default ACLs
func shiftAclIds(path string, isDir bool, uidOffset, gidOffset int32) error {

	// Access list
	err := shiftAclType(aclTypeAccess, path, uidOffset, gidOffset)
	if err != nil {
		return err
	}

	// Default list (for directories only)
	if isDir {
		err = shiftAclType(aclTypeDefault, path, uidOffset, gidOffset)
		if err != nil {
			return err
		}
	}

	return nil
}

// "Shifts" ownership of user and group IDs on the given directory and files and directories
// below it by the given offset, using chown.
func ShiftIdsWithChown(baseDir string, uidOffset, gidOffset int32) error {

	hardLinks := []uint64{}

	err := godirwalk.Walk(baseDir, &godirwalk.Options{
		Callback: func(path string, de *godirwalk.Dirent) error {

			// When doing the chown, we don't follow symlinks as we want to change
			// the ownership of the symlinks themselves. We will chown the
			// symlink's target during the godirwalk (unless the symlink is
			// dangling in which case there is nothing to be done).

			fi, err := os.Lstat(path)
			if err != nil {
				return err
			}

			st, ok := fi.Sys().(*syscall.Stat_t)
			if !ok {
				return fmt.Errorf("failed to convert to syscall.Stat_t")
			}

			// If a file has multiple hardlinks, change its ownership once
			if st.Nlink >= 2 {
				for _, linkInode := range hardLinks {
					if linkInode == st.Ino {
						return nil
					}
				}

				hardLinks = append(hardLinks, st.Ino)
			}

			targetUid := int32(st.Uid) + uidOffset
			targetGid := int32(st.Gid) + gidOffset

			logrus.Debugf("chown %s from %d:%d to %d:%d", path, st.Uid, st.Gid, targetUid, targetGid)

			err = unix.Lchown(path, int(targetUid), int(targetGid))
			if err != nil {
				return fmt.Errorf("chown %s to %d:%d failed: %s", path, targetUid, targetGid, err)
			}

			// Chowning the file is not sufficient; we also need to shift user and group IDs in
			// the Linux access control list (ACL) for the file

			if fi.Mode()&os.ModeSymlink == 0 {
				if err := shiftAclIds(path, fi.IsDir(), uidOffset, gidOffset); err != nil {
					return fmt.Errorf("failed to shift ACL for %s: %s", path, err)
				}
			}

			return nil
		},

		ErrorCallback: func(path string, err error) godirwalk.ErrorAction {

			fi, err := os.Lstat(path)
			if err != nil {
				return godirwalk.Halt
			}

			// Ignore errors due to chown on dangling symlinks (they often occur in container image layers)
			if fi.Mode()&os.ModeSymlink == os.ModeSymlink {
				return godirwalk.SkipNode
			}

			return godirwalk.Halt
		},

		Unsorted: true, // Speeds up the directory tree walk
	})

	return err
}

// Returns the lists of user and group IDs for all files and directories at or
// below the given path.
func GetDirIDs(baseDir string) ([]uint32, []uint32, error) {

	uidSet := mapset.NewSet()
	gidSet := mapset.NewSet()

	err := godirwalk.Walk(baseDir, &godirwalk.Options{
		Callback: func(path string, de *godirwalk.Dirent) error {

			fi, err := os.Lstat(path)
			if err != nil {
				return err
			}

			st, ok := fi.Sys().(*syscall.Stat_t)
			if !ok {
				return fmt.Errorf("failed to convert to syscall.Stat_t")
			}

			uidSet.Add(st.Uid)
			gidSet.Add(st.Gid)

			return nil
		},

		Unsorted: true, // Speeds up the directory tree walk
	})

	if err != nil {
		return nil, nil, err
	}

	uidList := []uint32{}
	for _, id := range uidSet.ToSlice() {
		val := id.(uint32)
		uidList = append(uidList, val)
	}

	gidList := []uint32{}
	for _, id := range gidSet.ToSlice() {
		val := id.(uint32)
		gidList = append(gidList, val)
	}

	return uidList, gidList, nil
}
