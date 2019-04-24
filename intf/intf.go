//
// sysvisor-mgr interfaces
//

package intf

// The SubidAlloc interface defines the interface exposed by the entity that
// performs or subuid and subgid allocations
type SubidAlloc interface {

	// Allocates an unused range of 'size' uids and gids; possible errors are
	// nil, "exhausted", or "invalid-size". Max supported size is 2^32.
	Alloc(size uint64) (uint32, uint32, error)

	// Free releases a previously allocated uid and gid range; the given uid and gid must
	// be obtained from a previous successful call to Alloc(); possible errors are nil or
	// "not-found" (if the given uid or gid is not from a prior call to Alloc())
	Free(uid, gid uint32) error
}
