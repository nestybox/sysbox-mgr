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

	intf "github.com/nestybox/sysvisor/sysvisor-mgr/intf"
	"github.com/nestybox/sysvisor/sysvisor-mgr/lib/buddyAlloc"
	"github.com/opencontainers/runc/libcontainer/user"
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

type allocInfo struct {
	uid uint32
	gid uint32
}

// subidAlloc class (implements the UidAllocator interface)
type subidAlloc struct {
	subuids   []user.SubID         // subuid range(s)
	subgids   []user.SubID         // subgid range(s)
	uidAllocs []*buddyAlloc.Buddy  // uid allocator(s) (one per contiguous subuid range)
	gidAllocs []*buddyAlloc.Buddy  // gid allocator(s) (one per contiguous subuid range)
	allocMap  map[string]allocInfo // table of container Ids and associated uid/gid allocs
	mu        sync.Mutex           // protects allocMap
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
// userName is the Linux user whose subid/gid ranges
// reuse is the reuse policy for subid/gid
// subuidSrc and subgidSrc contain the subid/gid ranges for the system
func New(userName string, reuse ReusePolicy, subuidSrc, subgidSrc io.Reader) (intf.SubidAlloc, error) {

	filter := func(entry user.SubID) bool {
		return entry.Name == userName
	}

	// read subuid range(s) for userName
	subuids, err := user.ParseSubIDFilter(subuidSrc, filter)
	if err != nil {
		return nil, err
	}

	if len(subuids) == 0 {
		return nil, fmt.Errorf("could not find subuid info for user %s", userName)
	}

	// read subgid range(s) for userName
	subgids, err := user.ParseSubIDFilter(subgidSrc, filter)
	if err != nil {
		return nil, err
	}

	if len(subgids) == 0 {
		return nil, fmt.Errorf("could not find subgid info for user %s", userName)
	}

	// create the allocator
	sub := &subidAlloc{
		subuids:   subuids,
		subgids:   subgids,
		uidAllocs: make([]*buddyAlloc.Buddy, len(subuids)),
		gidAllocs: make([]*buddyAlloc.Buddy, len(subgids)),
		allocMap:  make(map[string]allocInfo),
	}

	// for each subuid range that is large enough, create a buddy allocator
	for i, subuid := range subuids {
		if subuid.Count >= int64(allocBlkSize) {
			sub.uidAllocs[i], err = buddyAlloc.New(allocBlkSize, uint64(subuid.Count), toBuddyPolicy(reuse))
			if err != nil {
				return nil, fmt.Errorf("failed to create allocator object: %v", err)
			}
		}
	}

	// for each subgid range that is large enough, create a buddy allocator
	for i, subgid := range subgids {
		if subgid.Count >= int64(allocBlkSize) {
			sub.gidAllocs[i], err = buddyAlloc.New(allocBlkSize, uint64(subgid.Count), toBuddyPolicy(reuse))
			if err != nil {
				return nil, fmt.Errorf("failed to create allocator object: %v", err)
			}
		}
	}

	if len(sub.uidAllocs) == 0 {
		return nil, fmt.Errorf("did not find a large enough subuid range for user %s (need %v)", userName, allocBlkSize)
	}

	if len(sub.gidAllocs) == 0 {
		return nil, fmt.Errorf("did not find a large enough subgid range for user %s (need %v)", userName, allocBlkSize)
	}

	return sub, nil
}

func (sub *subidAlloc) allocUid(size uint64) (uint32, error) {

	// search in all of the subuid ranges of the user
	for i, uidAlloc := range sub.uidAllocs {
		if uidAlloc != nil {
			start, err := uidAlloc.Alloc(size)
			if err == nil {
				// the allocator allocates from 0; we need to adjust this to the subuid	start
				subuid := uint32(sub.subuids[i].SubID) + uint32(start)
				return subuid, nil
			}
			if err.Error() != "exhausted" {
				return 0, err
			}
		}
	}

	return 0, errors.New("exhausted")
}

func (sub *subidAlloc) allocGid(size uint64) (uint32, error) {

	// search in all of the subgid ranges of the user
	for i, gidAlloc := range sub.gidAllocs {
		if gidAlloc != nil {
			start, err := gidAlloc.Alloc(size)
			if err == nil {
				// the allocator allocates from 0; we need to adjust this to the subgid	start
				subgid := uint32(sub.subgids[i].SubID) + uint32(start)
				return subgid, nil
			}
			if err.Error() != "exhausted" {
				return 0, err
			}
		}
	}

	return 0, errors.New("exhausted")
}

func (sub *subidAlloc) freeUid(uid uint32) error {

	for i, uidAlloc := range sub.uidAllocs {
		if uidAlloc != nil {
			// the allocator allocates from 0; we need to adjust this to the subuid start
			subuid := uid - uint32(sub.subuids[i].SubID)
			err := uidAlloc.Free(uint64(subuid))
			if err == nil {
				return nil
			}
		}
	}

	return errors.New("not-found")
}

func (sub *subidAlloc) freeGid(gid uint32) error {

	for i, gidAlloc := range sub.gidAllocs {
		if gidAlloc != nil {
			subgid := gid - uint32(sub.subgids[i].SubID)
			err := gidAlloc.Free(uint64(subgid))
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

	uid, err := sub.allocUid(size)
	if err != nil {
		return 0, 0, err
	}

	gid, err := sub.allocGid(size)
	if err != nil {
		return 0, 0, err
	}

	sub.mu.Lock()
	sub.allocMap[id] = allocInfo{uid, gid}
	sub.mu.Unlock()

	logrus.Debugf("Alloc(%v, %v) = %v, %v", id, size, uid, gid)

	return uid, gid, nil
}

// Implements intf.SubidAlloc.Free
func (sub *subidAlloc) Free(id string) error {

	sub.mu.Lock()
	alloc, found := sub.allocMap[id]
	if !found {
		sub.mu.Unlock()
		return fmt.Errorf("not-found")
	}
	sub.mu.Unlock()

	err := sub.freeUid(alloc.uid)
	if err != nil {
		return err
	}

	err = sub.freeGid(alloc.gid)
	if err != nil {
		return err
	}

	sub.mu.Lock()
	delete(sub.allocMap, id)
	sub.mu.Unlock()

	logrus.Debugf("Free(%v)", id)

	return nil
}
