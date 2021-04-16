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
)

type OffsetType int

const (
	OffsetAdd OffsetType = iota
	OffsetSub
)

type aclType int

const (
	aclTypeAccess aclType = iota
	aclTypeDefault
)

// Shifts the ACL type user and group IDs by the given offset
func shiftAclType(aclT aclType, file *os.File, uidOffset, gidOffset uint32, offsetDir OffsetType) error {
	var facl aclLib.ACL
	var err error

	// Read the ACL
	if aclT == aclTypeDefault {
		facl, err = acl.FGetDefault(file)
	} else {
		facl, err = acl.FGet(file)
	}

	if err != nil {
		return fmt.Errorf("failed to get ACL for %s: %s", file.Name(), err)
	}

	// Shift the user and group ACLs (if any)
	newACL := aclLib.ACL{}

	for _, e := range facl {

		// ACL_USER id shifting
		if e.Tag == aclLib.TagUser {
			uid, err := strconv.ParseUint(e.Qualifier, 10, 32)
			if err != nil {
				logrus.Warnf("failed to convert ACL qualifier for %v: %s", e, err)
				continue
			}

			if offsetDir == OffsetAdd {
				uid = uid + uint64(uidOffset)
			} else {
				uid = uid - uint64(uidOffset)
			}

			e.Qualifier = strconv.FormatUint(uid, 10)
		}

		// ACL_GROUP id shifting
		if e.Tag == aclLib.TagGroup {
			gid, err := strconv.ParseUint(e.Qualifier, 10, 32)
			if err != nil {
				logrus.Warnf("failed to convert ACL qualifier %v: %s", e, err)
				continue
			}

			if offsetDir == OffsetAdd {
				gid = gid + uint64(gidOffset)
			} else {
				gid = gid - uint64(gidOffset)
			}

			e.Qualifier = strconv.FormatUint(gid, 10)
		}

		newACL = append(newACL, e)
	}

	// Write back the modified ACL
	if len(newACL) > 1 {
		if aclT == aclTypeDefault {
			err = acl.FSetDefault(file, newACL)
		} else {
			err = acl.FSet(file, newACL)
		}
		if err != nil {
			return fmt.Errorf("failed to set ACL %v for %s: %s", newACL, file.Name(), err)
		}
	}

	return nil
}

// Shifts the ACL user and group IDs by the given offset, both for access and default ACLs
func shiftAclIds(path string, isDir bool, uidOffset, gidOffset uint32, offsetDir OffsetType) error {

	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	// Access list
	err = shiftAclType(aclTypeAccess, file, uidOffset, gidOffset, offsetDir)
	if err != nil {
		return err
	}

	// Default list (for directories only)
	if isDir {
		err = shiftAclType(aclTypeDefault, file, uidOffset, gidOffset, offsetDir)
		if err != nil {
			return err
		}
	}

	return nil
}

// "Shifts" ownership of user and group IDs on the given directory and files and directories
// below it by the given offset, using chown.
func ShiftIdsWithChown(baseDir string, uidOffset, gidOffset uint32, offsetDir OffsetType) error {

	hardLinks := []uint64{}

	err := godirwalk.Walk(baseDir, &godirwalk.Options{
		Callback: func(path string, de *godirwalk.Dirent) error {
			var targetUid, targetGid uint32

			// When doing the chown, we don't follow symlinks as we want to change
			// the ownership of the symlinks themselves. We will chown the
			// symlink's target during the godirwalk (wunless the symlink is
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

			if offsetDir == OffsetAdd {
				targetUid = st.Uid + uidOffset
				targetGid = st.Gid + gidOffset
			} else {
				targetUid = st.Uid - uidOffset
				targetGid = st.Gid - gidOffset
			}

			logrus.Debugf("chown %s from %d:%d to %d:%d", path, st.Uid, st.Gid, targetUid, targetGid)

			err = unix.Lchown(path, int(targetUid), int(targetGid))
			if err != nil {
				return fmt.Errorf("chown %s to %d:%d failed: %s", path, targetUid, targetGid, err)
			}

			// Chowning the file is not sufficient; we also need to shift user and group IDs in
			// the Linux access control list (ACL) for the file

			if fi.Mode()&os.ModeSymlink == 0 {
				if err := shiftAclIds(path, fi.IsDir(), uidOffset, gidOffset, offsetDir); err != nil {
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
