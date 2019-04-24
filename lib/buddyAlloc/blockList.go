package buddyAlloc

import "errors"

// blockList is a list of free blocks
type blockList []block

// add block to end of list
func (l *blockList) add(b block) {
	*l = append(*l, b)
}

// remove block from front of list
func (l *blockList) remove() block {
	s := *l
	b := s[0]
	*l = s[1:]
	return b
}

// remove block at given index
func (l *blockList) removeAtIndex(idx uint64) block {
	s := *l
	blk := s[idx]
	s[idx] = s[len(s)-1]
	*l = s[:len(s)-1]
	return blk
}

// getBuddy searches the list for the buddy of the given block; if found, returns
// the buddy's position (i.e., index) in the list. Param 'order' is the list's order.
func (l *blockList) getBuddy(blk block) (uint64, error) {
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
	for i, b := range *l {
		if b.start == buddy.start {
			return uint64(i), nil
		}
	}

	return 0, errors.New("not-found")
}
