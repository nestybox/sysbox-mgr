// Simple but non-performant implementation of the idAllocator interface.
//
// This implementation allocates ranges (e.g. uids or gids) from the subid range
// associated with a given user.
//
// The allocation is done by linearly searching for the first range that is large enough
// to satisfy the allocation and which is currently unused. An allocation map tracks
// ranges that are used.
//
// When no range is found, the allocator supports two policies: reuse allocated ranges, in
// which the allocator returns a used range that meets the size and increases a reference
// count for the range; or don't reuse allocated ranges, in which the allocation fails.
//
// Fragmentation:
//
// Because the allocation algorithm searches for the first unused range that satisfies the
// allocation (rather than the best fit), it's subject to fragmentation *if* allocations
// vary in size. This should not be the case though, because sysvisor-run normally
// allocates ranges of 64k.
//
// Performance:
//
// The search for an unused range is linear and runs in O(n), where n is the size of the
// user's subid range.
//
// Limitations:
//
// * The re-use policy algorithm relies on finding a used range which matches the size of
//   the current allocation request in order to increase the refcount on the used range. A
//   match is guarantee to exist if the allocations are always of the same size (which is
//   normally the case for allocations from sysvisor-runc). However, if allocations vary
//   in size, the re-use policy may not find a used range that matches the size of the
//   current allocation request and the allocation will fail. Fixing this requires a more
//   sophisticated allocation algorighm (e.g., buddy allocator).

package idAlloc

import (
	"errors"
	"fmt"
	"io"
	"sync"

	intf "github.com/nestybox/sysvisor/sysvisor-mgr/interfaces"
	"github.com/opencontainers/runc/libcontainer/user"
)

// The reuse policy indicates how to deal with allocs when the allocMap is full
type ReusePolicy int

const (
	Reuse   ReusePolicy = iota // reuse allocated ids
	NoReuse                    // do not re-use (allocation fails with error = "id-exhausted")
)

// mapEntry is an entry in the id allocation map
type mapEntry struct {
	size   uint32
	refcnt uint32
}

// Up to 2^32 concurrent re-allocations of the same id range
const maxRefcnt = 0xffffffff

// idAlloc class; implements the UidAllocator interface
type idAlloc struct {
	subid       []user.SubID        // subid range(s) for user
	allocMap    map[uint32]mapEntry // tracks allocated ranges; keyed by range start
	mu          sync.Mutex          // guards the allocMap on concurrent accesses
	reusePolicy ReusePolicy
}

// max returns the larger of x or y.
func max(x, y uint32) uint32 {
	if x < y {
		return y
	}
	return x
}

// min returns the smaller of x or y.
func min(x, y uint32) uint32 {
	if x > y {
		return y
	}
	return x
}

// find an unused subid range of the given size in the alloc map
func (id *idAlloc) findUnusedSubID(size uint32) (idRange, error) {

	// sort the alloc map ranges
	ranges := make([]idRange, 0, len(id.allocMap))
	for k, v := range id.allocMap {
		ranges = append(ranges, idRange{k, v.size})
	}
	sorted := sortIDRanges(ranges)

	// a user may have multiple subid ranges in /etc/subuid(gid); search in all
	for _, subidRange := range id.subid {
		rstart := uint32(subidRange.SubID)
		rsize := uint32(subidRange.Count)

		r := findUnusedRange(rstart, rsize, size, sorted)
		if r.size != 0 {
			return idRange{r.start, size}, nil
		}
	}

	return idRange{0, 0}, errors.New("id-exhausted")
}

// realloc allocates a used range of 'size' ids (i.e., a range that is present in the
// allocMap). This function assumes that id.mu is locked.
func (id *idAlloc) realloc(size uint32) (uint32, error) {

	type info struct{ start, size, refcnt uint32 }

	// find all used ranges of the given size
	ranges := make([]info, 0, len(id.allocMap))
	for k, v := range id.allocMap {
		if v.size == size {
			ranges = append(ranges, info{k, v.size, v.refcnt})
		}
	}

	// NOTE: since sysvisor-runc always allocates ranges of 64k always, the loop above will
	// always find a range and the 'if' below will never be entered. But if this assumption
	// changes (i.e., sysvisor-runc alloc requests vary in size), then we may enter the
	// following 'if', which would not be ideal. Fixing this would require a more
	// sophisticated allocation algorithm that handles varying size allocs with refcounts
	// (e.g., buddy allocator).
	if len(ranges) == 0 {
		return 0, errors.New("id-exhausted")
	}

	// find the range with the lowest ref count
	var lcnt uint32 = maxRefcnt
	var lrange info

	for _, r := range ranges {
		if r.refcnt < lcnt {
			lcnt = r.refcnt
			lrange = r
		}
	}

	// perform the realloc
	entry := id.allocMap[lrange.start]
	if entry.refcnt == maxRefcnt {
		return 0, errors.New("id-exhausted")
	}
	entry.refcnt++
	id.allocMap[lrange.start] = entry

	return lrange.start, nil
}

// New creates an idAlloc object
func New(userName string, reuse ReusePolicy, subidSrc io.Reader) (intf.IDAllocator, error) {

	// read subuid range for userName; if not found, return nil, error
	filter := func(entry user.SubID) bool {
		return entry.Name == userName
	}

	subid, err := user.ParseSubIDFilter(subidSrc, filter)
	if err != nil {
		return nil, err
	}

	if len(subid) == 0 {
		return nil, fmt.Errorf("could not find sub-id info for user %s", userName)
	}

	// sanity check
	if subid[0].Name != userName {
		return nil, fmt.Errorf("mismatch error parsing sub-id info for user %s", userName)
	}

	return &idAlloc{
		subid:       subid,
		allocMap:    make(map[uint32]mapEntry),
		reusePolicy: reuse,
	}, nil
}

// Alloc allocates an unused range of 'size' ids.
func (id *idAlloc) Alloc(size uint32) (uint32, error) {

	if size == 0 {
		return 0, errors.New("invalid-size")
	}

	id.mu.Lock()
	defer id.mu.Unlock()

	r, err := id.findUnusedSubID(size)
	if err == nil {
		id.allocMap[r.start] = mapEntry{r.size, 1}
		return r.start, nil
	}

	if err.Error() != "id-exhausted" || id.reusePolicy != Reuse {
		return 0, err
	}

	return id.realloc(size)
}

// Free releases a previously allocated id range; the given 'start' must be the start of a
// range previously returned by a successful call to Alloc().
func (id *idAlloc) Free(start uint32) error {

	id.mu.Lock()
	defer id.mu.Unlock()

	entry, found := id.allocMap[start]
	if !found {
		return errors.New("not-found")
	}

	entry.refcnt--
	if entry.refcnt > 0 {
		id.allocMap[start] = entry
		return nil
	}

	delete(id.allocMap, start)
	return nil
}
