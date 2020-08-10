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

//
// sysbox-mgr interfaces
//

package intf

import (
	"os"

	"github.com/opencontainers/runc/libcontainer/configs"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// The SubidAlloc interface defines the interface exposed by the entity that
// performs or subuid and subgid allocations
type SubidAlloc interface {

	// Allocates an unused range of 'size' uids and gids for the container with the given 'id'.
	// Max supported 'size' is 2^32.
	// Possible errors are nil, "exhausted", or "invalid-size".
	Alloc(id string, size uint64) (uint32, uint32, error)

	// Free releases a previously allocated uid and gid range for the container with the
	// given 'id'. Possible errors are nil and "not-found" (if the container with the
	// given 'id' has no allocations).
	Free(id string) error
}

// The VolMgr interface defines the interface exposed by the sysbox-mgr entities that
// manage the creation of volumes on the host that are bind-mounted into the sys
// container.
type VolMgr interface {

	// Creates a volume for the sys container with the given 'id'. This function
	// returns an OCI mount spec (which is passed back to sysbox-runc to setup the actual mount).
	// 'rootfs' is the absolute path the container's rootfs.
	// 'mountpoint' is the volume's mountpoint (relative to the container's rootfs)
	// 'uid' and 'gid' are the uid(gid) of the container root process in the host's namespace.
	// 'shiftUids' indicates if sysbox-runc is using uid-shifting for the container.
	// 'perm' indicates the permissions for the created volume.
	CreateVol(id, rootfs, mountpoint string, uid, gid uint32, shiftUids bool, perm os.FileMode) ([]specs.Mount, error)

	// Destroys a volume for the container with the given 'id'.
	DestroyVol(id string) error

	// Sync the contents of the volume back to container's rootfs
	SyncOut(id string) error

	// Sync and destroys all volumes (best effort, ignore errors)
	SyncOutAndDestroyAll()
}

// The ShiftfsMgr interface defines the interface exposed by the sysbox-mgr shiftfs manager
type ShiftfsMgr interface {

	// Add shiftfs marks on the given mountpoints
	Mark(id string, mounts []configs.ShiftfsMount) error

	// Remove shiftfs marks associated with the given container
	Unmark(id string, mount []configs.ShiftfsMount) error

	// Remove shiftfs marks associated with all containers (best effort, ignore errors)
	UnmarkAll()
}
