//
// Copyright: (C) 2019 Nestybox Inc.  All rights reserved.
//

package buddyAlloc

import "math"

func isPowerOfTwo(num uint64) bool {
	return num != 0 && num&(num-1) == 0
}

func nextPowerOfTwo(num uint64) uint64 {
	var count uint

	if isPowerOfTwo(num) {
		return num
	}

	n := num
	for n > 0 {
		n >>= 1
		count += 1
	}

	return 1 << count
}

func exp2(num uint32) uint64 {
	return uint64(math.Exp2(float64(num)))
}

// max returns the larger of x or y.
func max(x, y uint64) uint64 {
	if x < y {
		return y
	}
	return x
}

// min returns the smaller of x or y.
func min(x, y uint64) uint64 {
	if x > y {
		return y
	}
	return x
}

func remove(slice []int, i int) []int {
	slice[i] = slice[len(slice)-1]
	return slice[:len(slice)-1]
}
