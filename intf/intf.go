//
// sysbox-mgr interfaces
//

package intf

import specs "github.com/opencontainers/runtime-spec/specs-go"

// The SubidAlloc interface defines the interface exposed by the entity that
// performs or subuid and subgid allocations
type SubidAlloc interface {

	// Allocates an unused range of 'size' uids and gids for the container with the given
	// 'id'; possible errors are nil, "exhausted", or "invalid-size". Max supported 'size' is 2^32.
	Alloc(id string, size uint64) (uint32, uint32, error)

	// Free releases a previously allocated uid and gid range for the container with the
	// given 'id'. Possible errors are nil and "not-found" (if the container with the
	// given 'id' has no allocations).
	Free(id string) error
}

// The VolMgr interface defines the interface exposed by the sysbox-mgr entities that
// manage the creation of volumes for the sys container.
type VolMgr interface {

	// Creates a volume for the sys container with the given 'id'. This function
	// returns an OCI mount spec (which is passed back to sysbox-runc to setup the actual mount).
	// 'rootfs' is the absolute path the container's rootfs.
	// 'mountpoint' is the container's mountpoint (relative to it's rootfs)
	// 'uid' and 'gid' are the uid(gid) of the container root process in the host's namespace.
	// 'shiftUids' indicates if sysbox-runc is using uid-shifting for the container.
	CreateVol(id string, rootfs string, mountpoint string, uid, gid uint32, shiftUids bool) ([]specs.Mount, error)

	// Destroys a volume for the container with the given 'id'.
	DestroyVol(id string) error
}
