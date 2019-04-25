//
// sysvisor-mgr interfaces
//

package intf

// The SubidAlloc interface defines the interface exposed by the entity that
// performs or subuid and subgid allocations
type SubidAlloc interface {

	// Allocates an unused range of 'size' uids and gids for the container with the given
	// 'id'; possible errors are nil, "exhausted", or "invalid-size". Max supported 'size' is
	// 2^32.
	Alloc(id string, size uint64) (uint32, uint32, error)

	// Free releases a previously allocated uid and gid range for the container with the
	// given 'id'. Possible errors are nil and "not-found" (if the container with the
	// given 'id' has no allocations).
	Free(id string) error
}
