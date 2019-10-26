//
// Copyright: (C) 2019 Nestybox Inc.  All rights reserved.
//

// sub user-id and sub group-id allocator
//
// The subidAlloc class allocates portions of the subuid and subgid ranges associated
// with a given user. It implements the intf.SubidAlloc interface.
//
// An subid object is created with New(), allocations are performed with Alloc(), and
// freeing is performed with Free().
//
// The initial subuid and subgid range from which to perform the allocation is obtained
// from the sources passed to New(). See that function for details. The max supported
// allocation range is 4GB.
//
// Internally, it uses the buddyAlloc package to manage the allocations. Allocations are
// done in O(log2(n)). Freeing is done in O(n). See buddyAlloc for details.
//
// The subidAlloc object supports a "reuse" allocation setting, which is set when the object is
// created. If set to "no-reuse", allocation fails if the entire range is currently
// allocated. If set to "reuse", the allocator tries to reuse a currently allocated block
// and increases a reference count on the block. When the block is freed, the reference
// count is decreased; when it reaches 0 the block is deallocated.
//
// The allocation of subuid and subgid are done independently of each other (i.e.,
// the returned range may not be the same for each if the initial subuid and subgid
// ranges differ).

package subidAlloc

import (
	"errors"
	"fmt"
	"io"
	"sync"

	mapset "github.com/deckarep/golang-set"
	intf "github.com/nestybox/sysbox-mgr/intf"
	"github.com/nestybox/sysbox-mgr/lib/buddyAlloc"
	"github.com/nestybox/sysbox-runc/libcontainer/user"
	"github.com/sirupsen/logrus"
)

const (
	allocBlkSize uint32 = 65536 // min uid(gid) allocation range
)

// The reuse policy indicates how to deal with allocs when the subuid(gid) range is exhausted
type ReusePolicy int

const (
	Reuse   ReusePolicy = iota // reuse allocated subuid(gids)
	NoReuse                    // do not re-use (allocation fails with error = "exhausted")
)

// subidAlloc class (implements the UidAllocator interface)
type subidAlloc struct {
	idRanges []user.SubID        // subuid range(s)
	idAllocs []*buddyAlloc.Buddy // subid allocator(s) (one per contiguous subuid range)
	allocMap map[string]uint32   // table of container Ids and associated uid/gid allocs
	mu       sync.Mutex          // protects allocMap
}

func toBuddyPolicy(p ReusePolicy) buddyAlloc.ReusePolicy {
	var bp buddyAlloc.ReusePolicy

	switch p {
	case Reuse:
		bp = buddyAlloc.Reuse
		break
	default:
		bp = buddyAlloc.NoReuse
		break
	}

	return bp
}

// New creates an subidAlloc object
//
// userName is the Linux user whose subid/gid ranges will be used
// reuse is the reuse policy for subid/gid
// subuidSrc and subgidSrc contain the subid/gid ranges for the system
func New(userName string, reuse ReusePolicy, subuidSrc, subgidSrc io.Reader) (intf.SubidAlloc, error) {

	filter := func(entry user.SubID) bool {
		return entry.Name == userName
	}

	// read subuid range(s) for userName
	uidRanges, err := user.ParseSubIDFilter(subuidSrc, filter)
	if err != nil {
		return nil, err
	}

	if len(uidRanges) == 0 {
		return nil, fmt.Errorf("could not find subuid info for user %s", userName)
	}

	// read subgid range(s) for userName
	gidRanges, err := user.ParseSubIDFilter(subgidSrc, filter)
	if err != nil {
		return nil, err
	}

	if len(gidRanges) == 0 {
		return nil, fmt.Errorf("could not find subgid info for user %s", userName)
	}

	// we need at least one matching subuid and subgid range
	ranges := getCommonRanges(uidRanges, gidRanges)
	if len(ranges) == 0 {
		return nil, fmt.Errorf("could not find matching subuid and subgids range for user %s", userName)
	}

	// create the allocator
	sub := &subidAlloc{
		idRanges: ranges,
		idAllocs: make([]*buddyAlloc.Buddy, len(ranges)),
		allocMap: make(map[string]uint32),
	}

	// for each subid range that is large enough, create a buddy allocator
	for i, subid := range sub.idRanges {
		if subid.Count >= int64(allocBlkSize) {
			sub.idAllocs[i], err = buddyAlloc.New(allocBlkSize, uint64(subid.Count), toBuddyPolicy(reuse))
			if err != nil {
				return nil, fmt.Errorf("failed to create allocator object: %v", err)
			}
		}
	}

	if len(sub.idAllocs) == 0 {
		return nil, fmt.Errorf("did not find a large enough subuid range for user %s (need %v)", userName, allocBlkSize)
	}

	return sub, nil
}

func getCommonRanges(uidRanges, gidRanges []user.SubID) []user.SubID {

	uidRangeSet := mapset.NewSet()
	for _, uidRange := range uidRanges {
		uidRangeSet.Add(uidRange)
	}

	gidRangeSet := mapset.NewSet()
	for _, gidRange := range gidRanges {
		gidRangeSet.Add(gidRange)
	}

	commonSet := uidRangeSet.Intersect(gidRangeSet)

	common := []user.SubID{}
	for elem := range commonSet.Iter() {
		subid := elem.(user.SubID)
		common = append(common, subid)
	}

	return common
}

func (sub *subidAlloc) allocID(size uint64) (uint32, error) {

	// search in all of the subid ranges of the user
	for i, idAlloc := range sub.idAllocs {
		if idAlloc != nil {
			start, err := idAlloc.Alloc(size)
			if err == nil {
				// the allocator allocates from 0; we need to adjust this to the subid start
				subid := uint32(sub.idRanges[i].SubID) + uint32(start)
				return subid, nil
			}
			if err.Error() != "exhausted" {
				return 0, err
			}
		}
	}

	return 0, errors.New("exhausted")
}

func (sub *subidAlloc) freeID(subid uint32) error {

	for i, idAlloc := range sub.idAllocs {
		if idAlloc != nil {
			// the allocator allocates from 0; we need to adjust this to the subid start
			adjSubid := subid - uint32(sub.idRanges[i].SubID)
			err := idAlloc.Free(uint64(adjSubid))
			if err == nil {
				return nil
			}
		}
	}

	return errors.New("not-found")
}

// Implements intf.SubidAlloc.Alloc
func (sub *subidAlloc) Alloc(id string, size uint64) (uint32, uint32, error) {

	sub.mu.Lock()
	if _, found := sub.allocMap[id]; found {
		sub.mu.Unlock()
		return 0, 0, fmt.Errorf("exhausted")
	}
	sub.mu.Unlock()

	subid, err := sub.allocID(size)
	if err != nil {
		return 0, 0, err
	}

	sub.mu.Lock()
	sub.allocMap[id] = subid
	sub.mu.Unlock()

	logrus.Debugf("Alloc(%v, %v) = %v, %v", id, size, subid, subid)

	return subid, subid, nil
}

// Implements intf.SubidAlloc.Free
func (sub *subidAlloc) Free(id string) error {

	sub.mu.Lock()
	subid, found := sub.allocMap[id]
	if !found {
		sub.mu.Unlock()
		return fmt.Errorf("not-found")
	}
	sub.mu.Unlock()

	err := sub.freeID(subid)
	if err != nil {
		return err
	}

	sub.mu.Lock()
	delete(sub.allocMap, id)
	sub.mu.Unlock()

	logrus.Debugf("Free(%v)", id)

	return nil
}
