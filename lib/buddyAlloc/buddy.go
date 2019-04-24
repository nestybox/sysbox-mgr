// Implementation of a generic buddy allocator.
//
// The Buddy class represents a buddy allocator which is initialized with an initial
// range and allows a user to allocate and free arbitrarily sized portions of that range.
//
// An Buddy object is created with New(), allocations are performed with Alloc(), and
// freeing is performed with Free().
//
// Internally, allocations are done in units of blocks. A block is a contiguous range that
// is a multiple of a minimum block size. The minimum block size (minBlkSize) is
// configurable when a Buddy object is created. A larger min block size improves
// allocation & freeing performance but increases fragmentation. A smaller min block size
// reduces fragmentation but also reduces performance.
//
// The max supported allocation range is 2^64 - minBlkSize.
//
// Allocations are done in O(log2(n)). Freeing is done in O(n) (due to a lookup in a
// map that stores prior allocations and their block size).
//
// The Buddy object supports a "reuse" allocation setting, which is set when the object is
// created. If set to "no-reuse", allocation fails if the entire range is currently
// allocated. If set to "reuse", the allocator tries to reuse a currently allocated block
// and increases a reference count on the block. When the block is freed, the reference
// count is decreased; when it reaches 0 the block is deallocated.

package buddyAlloc

import (
	"errors"
	"fmt"
	"math"
	"sync"
)

// The reuse policy indicates how to deal with allocs when there are no more free blocks
type ReusePolicy int

const (
	Reuse   ReusePolicy = iota // reuse allocated blocks
	NoReuse                    // do not re-use (allocation fails with error = "exhausted")
)

// Buddy allocator limits
const (
	minBlkLimit   = 4096           // min allocation unit
	maxBlkLimit   = math.MaxUint32 // max allocation unit
	maxOrderLimit = 32             // ratio maxRange/minBlkSize <= 2^32
	maxRefcnt     = 0xffffffff     // max re-allocations of the same block
)

// mapEntry is an entry in the allocation map
type mapEntry struct {
	size   uint64
	refcnt uint32
}

// Buddy represents an instance of a buddy allocator
type Buddy struct {
	minBlkSize  uint32
	maxOrder    int
	maxRange    uint64              // max alloc range (minBlkSize * 2^maxOrder)
	freeList    []blockList         // list of block lists (one list per order)
	allocMap    map[uint64]mapEntry // tracks allocations
	reusePolicy ReusePolicy
	mu          sync.Mutex
}

func New(minBlkSize uint32, maxRange uint64, reusePolicy ReusePolicy) (*Buddy, error) {

	if minBlkSize < minBlkLimit || minBlkSize > maxBlkLimit {
		return nil, fmt.Errorf("minBlkSize must be between (%v, %v); got %v", minBlkLimit, maxBlkLimit, minBlkSize)
	}

	if !isPowerOfTwo(uint64(minBlkSize)) {
		return nil, fmt.Errorf("minBlkSize must be a power of 2; got %v", minBlkSize)
	}

	if maxRange < uint64(minBlkSize) {
		return nil, fmt.Errorf("maxRange must be >= minBlkSize; got %v and %v", maxRange, minBlkSize)
	}

	maxBlocks := maxRange / uint64(minBlkSize)
	maxOrder := int(math.Log(float64(maxBlocks)) / math.Log(2)) // log2(maxBlocks)

	if maxOrder > maxOrderLimit {
		return nil, fmt.Errorf("The ratio maxRange:minBlkSize is too high; must be <= 2^%v; got 2^%v", maxOrderLimit, maxOrder)
	}

	if reusePolicy != Reuse && reusePolicy != NoReuse {
		return nil, fmt.Errorf("invalid policy")
	}

	// the nominal range must be a multiple of the min block size; thus it may be less than
	// the given maxRange (unless the given maxRange = minBlkSize * 2^n, where n is between
	// (0, maxOrderLimit))
	nomMaxRange := uint64(minBlkSize) * exp2(uint32(maxOrder))

	b := &Buddy{
		minBlkSize:  minBlkSize,
		maxOrder:    maxOrder,
		maxRange:    nomMaxRange,
		freeList:    make([]blockList, maxOrder+1),
		allocMap:    make(map[uint64]mapEntry),
		reusePolicy: reusePolicy,
	}

	initBlk := block{0, b.maxRange - 1}
	b.freeList[maxOrder].add(initBlk)

	return b, nil
}

// getBlkSize normalizes size to a multiple of the min block size
func (b *Buddy) getBlkSize(size uint64) uint64 {
	numBlocks := uint64(math.Ceil(float64(size) / float64(b.minBlkSize)))
	return numBlocks * uint64(b.minBlkSize)
}

// getOrder computes the order for the given size (which must be > 0)
func (b *Buddy) getOrder(size uint64) int {
	numBlocks := math.Ceil(float64(size) / float64(b.minBlkSize))
	return int(math.Ceil(math.Log(numBlocks) / math.Log(2)))
}

// realloc allocates a used block of the given size. This
// function assumes the buddy.mu lock is held.
func (b *Buddy) realloc(blkSize uint64) (uint64, error) {

	type blkInfo struct {
		start  uint64
		size   uint64
		refcnt uint32
	}

	// find all allocated blocks of the given size
	blocks := make([]blkInfo, 0, len(b.allocMap))
	for k, v := range b.allocMap {
		if v.size == blkSize {
			blocks = append(blocks, blkInfo{k, v.size, v.refcnt})
		}
	}

	// no blocks of the given size found, we can't reallocate
	if len(blocks) == 0 {
		return 0, errors.New("exhausted")
	}

	// find the block with the lowest ref count
	var lcnt uint32 = maxRefcnt
	var lblk blkInfo

	for _, blk := range blocks {
		if blk.refcnt < lcnt {
			lcnt = blk.refcnt
			lblk = blk
		}
	}

	// perform the realloc by increasing the block's refcnt
	entry := b.allocMap[lblk.start]
	if entry.refcnt == maxRefcnt {
		return 0, errors.New("exhausted")
	}
	entry.refcnt++
	b.allocMap[lblk.start] = entry

	return lblk.start, nil
}

// Alloc allocates an unused range of the given size.
func (b *Buddy) Alloc(size uint64) (uint64, error) {
	var list *blockList
	var blk block
	var i int

	if size == 0 {
		return 0, fmt.Errorf("invalid-size")
	}

	if size > b.maxRange {
		return 0, fmt.Errorf("exhausted")
	}

	order := b.getOrder(size)
	blkSize := b.getBlkSize(size)

	b.mu.Lock()
	defer b.mu.Unlock()

	// search for a free block in list for the order; if found, we are done

	list = &b.freeList[order]
	if len(*list) > 0 {
		blk := list.remove()
		b.allocMap[blk.start] = mapEntry{blkSize, 1}
		return blk.start, nil
	}

	// if not found, search higher order lists
	for i = order + 1; i < len(b.freeList); i++ {
		list := &b.freeList[i]
		if len(*list) == 0 {
			continue
		}
		break
	}

	// if search found no free blocks, apply reuse policy or bail
	if i == len(b.freeList) {
		if b.reusePolicy == Reuse {
			return b.realloc(blkSize)
		} else {
			return 0, fmt.Errorf("exhausted")
		}
	}

	// now we need to remove the larger block and iteratively divide it until we find the
	// block size we need
	list = &b.freeList[i]
	blk = list.remove()

	for i--; i >= order; i-- {
		// divide blk into two equal halves
		blkl := block{blk.start, blk.start + (blk.end-blk.start)/2}
		blku := block{blk.start + (blk.end-blk.start+1)/2, blk.end}

		// add it to current order list
		list = &b.freeList[i]
		list.add(blkl)
		list.add(blku)

		// prepare for next iter
		blk = list.remove()
	}

	b.allocMap[blk.start] = mapEntry{blkSize, 1}
	return blk.start, nil
}

// Free deallocates a range of the given size.
func (b *Buddy) Free(start uint64) error {
	var list *blockList

	b.mu.Lock()
	defer b.mu.Unlock()

	entry, found := b.allocMap[start]
	if !found {
		return fmt.Errorf("not-found")
	}

	// if the refcnt > 0, then we simply decrease the refcnt
	entry.refcnt--
	if entry.refcnt > 0 {
		b.allocMap[start] = entry
		return nil
	}

	// refcnt at 0, so free the range; search for buddies and iteratively merge them and
	// insert them in higher order lists

	blkSize := entry.size
	order := b.getOrder(blkSize)

	blk := block{start, start + blkSize - 1}
	for i := order; i < len(b.freeList); i++ {
		list = &b.freeList[i]

		idx, err := list.getBuddy(blk)
		if err != nil {
			break
		}

		buddy := list.removeAtIndex(idx)
		blk = mergeBlocks(blk, buddy)
	}

	// insert block in appropriate list
	list.add(blk)

	delete(b.allocMap, start)
	return nil
}

// getBuddy searches the given list for the buddy of the given block; if found, returns
// the buddy's position (i.e., index) in the list. Param 'order' is the list's order.
func getBuddy(list *blockList, blk block) (uint64, error) {
	var buddyStart uint64

	blkSize := blk.end - blk.start + 1

	if blk.start%(blkSize*2) == 0 {
		// buddy is odd range in pair
		buddyStart = blk.end + 1
	} else {
		// buddy is even range in pair
		buddyStart = blk.start - blkSize
	}

	buddy := block{buddyStart, buddyStart + blkSize - 1}

	// search in list (linear search as list is unordered)
	for i, b := range *list {
		if b.start == buddy.start {
			return uint64(i), nil
		}
	}

	return 0, errors.New("not-found")
}
