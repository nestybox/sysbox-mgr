package interfaces

//
// sysvisor-mgr interfaces
//

// The IDAllocator interface defines the interface exposed by the entity that
// performs or uid or gid allocations
type IDAllocator interface {
	// Allocates an unused range of 'size' uids and gids; possible errors are
	// nil, "id-exhausted", or "invalid-size"
	Alloc(size uint32) (uint32, error)

	// Free releases a previously allocated id range; the given 'id' must
	// be one previously returned by a successful call to Alloc() (otherwise,
	// this function returns a "not-found" error)
	Free(id uint32) error
}
