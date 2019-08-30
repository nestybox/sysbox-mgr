//
// Copyright: (C) 2019 Nestybox Inc.  All rights reserved.
//

package buddyAlloc

// block represents a free block
type block struct {
	start, end uint64
}

// merge the given contiguous blocks into one
func mergeBlocks(b1, b2 block) block {
	start := min(b1.start, b2.start)
	end := max(b1.end, b2.end)
	return block{start, end}
}
