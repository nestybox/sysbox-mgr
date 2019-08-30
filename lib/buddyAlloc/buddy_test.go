//
// Copyright: (C) 2019 Nestybox Inc.  All rights reserved.
//

package buddyAlloc

import (
	"math"
	"math/rand"
	"testing"
)

func TestGetBlkSize(t *testing.T) {

	buddy, err := New(4096, 4096, NoReuse)
	if err != nil {
		t.Errorf("New() failed: %v", err)
	}

	var tests = []struct {
		size uint64
		want uint64
	}{
		{0, 0},
		{1, 4096},
		{4095, 4096},
		{4096, 4096},
		{4097, 4096 * 2},
		{8191, 4096 * 2},
		{8192, 4096 * 2},
		{8193, 4096 * 3},
	}

	for _, test := range tests {
		got := buddy.getBlkSize(test.size)
		if got != test.want {
			t.Errorf("getBlkSize(%v): got %v, want %v", test.size, got, test.want)
		}
	}
}

func TestGetOrder(t *testing.T) {

	minBlkSize := uint32(65536)
	maxRange := uint64(math.MaxUint32 + 1) // 4GB

	buddy, err := New(minBlkSize, maxRange, NoReuse)
	if err != nil {
		t.Errorf("New() failed: %v", err)
	}

	var tests = []struct {
		size uint64
		want int
	}{
		{1, 0},
		{2, 0},
		{65535, 0},
		{65536, 0},
		{65537, 1},
		{math.MaxUint32 + 1, 16},
	}

	for _, test := range tests {
		got := buddy.getOrder(test.size)
		if got != test.want {
			t.Errorf("getOrder(%v): got %v, want %v", test.size, got, test.want)
		}
	}
}

func TestBuddyLimits(t *testing.T) {

	// minBlkSize is lower than supported limit
	_, err := New(1024, 4096, NoReuse)
	if err == nil {
		t.Errorf("New() minBlkSize limit failed: expect error, got nil")
	}

	// minBlkSize is not power of 2
	_, err = New(4098, 65536, NoReuse)
	if err == nil {
		t.Errorf("New() minBlkSize power of 2 failed: expect error, got nil")
	}

	// rangeSize is less than minBlkSize
	_, err = New(8192, 4096, NoReuse)
	if err == nil {
		t.Errorf("New() maxRange failed: expect error, got nil")
	}

	// rangeSize:minBlkSize ratio violation
	_, err = New(4096, math.MaxUint64, NoReuse)
	if err == nil {
		t.Errorf("New() rangeSize:minBlkSize ratio failed: expect error, got nil")
	}
}

func TestMaxRange(t *testing.T) {

	minBlkSize := uint32(4096)
	maxRange := uint64(10000)

	buddy, err := New(minBlkSize, maxRange, NoReuse)
	if err != nil {
		t.Errorf("New() failed: %v", err)
	}

	if buddy.maxRange != 8192 {
		t.Errorf("Max range failed: got %v; want %v", buddy.maxRange, 8192)
	}
}

func printFreeList(t *testing.T, b *Buddy) {
	t.Logf("")
	for i := b.maxOrder; i >= 0; i-- {
		t.Logf("freeList[%v] = %v\n", i, b.freeList[i])
	}
	t.Logf("allocMap = %v\n", b.allocMap)
}

type allocTest struct {
	size    uint64
	wantID  uint64
	wantErr string
}

func testAlloc(t *testing.T, buddy *Buddy, tests []allocTest) {
	var errStr string

	for _, test := range tests {
		got, gotErr := buddy.Alloc(test.size)

		if gotErr == nil {
			errStr = ""
		} else {
			errStr = gotErr.Error()
		}

		if errStr != test.wantErr || got != test.wantID {
			t.Errorf("Alloc(%v) failed: got = %v, err = %v; want = %v, want-err = %v",
				test.size, got, errStr, test.wantID, test.wantErr)
		}
	}
}

func TestAllocBasic(t *testing.T) {

	minBlkSize := uint32(65536)
	maxRange := uint64(math.MaxUint32 + 1) // 4GB

	buddy, err := New(minBlkSize, maxRange, NoReuse)
	if err != nil {
		t.Errorf("New() failed: %v", err)
	}

	var tests = []allocTest{
		// size, start, error
		{0, 0, "invalid-size"},
		{65536, 0, ""},
		{65536, 65536, ""},
		{65536, 65536 * 2, ""},
		{65536, 65536 * 3, ""},
		{1, 65536 * 4, ""},
		{1, 65536 * 5, ""},
	}

	testAlloc(t, buddy, tests)
}

func TestAllocExhausted(t *testing.T) {

	minBlkSize := uint32(65536)
	maxRange := uint64(minBlkSize * 4)

	buddy, err := New(minBlkSize, maxRange, NoReuse)
	if err != nil {
		t.Errorf("New() failed: %v", err)
	}

	var tests = []allocTest{
		// size, start, error
		{65536, 0, ""},
		{65536, 65536, ""},
		{65536, 65536 * 2, ""},
		{65536, 65536 * 3, ""},
		{1, 0, "exhausted"},
	}

	testAlloc(t, buddy, tests)
}

func TestRealloc(t *testing.T) {

	minBlkSize := uint32(65536)
	maxRange := uint64(minBlkSize * 16)

	buddy, err := New(minBlkSize, maxRange, Reuse)
	if err != nil {
		t.Errorf("New() failed: %v", err)
	}

	// allocate until full and store alloc 'start' in an alloc map

	allocMap := make(map[uint64]uint64) // [start]size
	for i := 1; i <= 16; i++ {
		start, err := buddy.Alloc(65536)
		if err != nil {
			t.Errorf("Alloc() failed: %v", err)
		}
		if _, ok := allocMap[start]; ok {
			t.Errorf("Alloc() returned duplicate start: %v", start)
		}
		allocMap[start] = 65536
	}

	// reallocate and check that returned 'start' was reused (i.e., should be in the
	// allocMap)

	for i := 1; i <= 16; i++ {
		start, err := buddy.Alloc(65536)
		if err != nil {
			t.Errorf("Alloc() failed: %v", err)
		}

		if _, ok := allocMap[start]; !ok {
			t.Errorf("Alloc() did not reuse a prior range: got start %v; want one of %v", start, allocMap)
		}

		delete(allocMap, start)
	}
}

func TestFree(t *testing.T) {

	minBlkSize := uint32(65536)
	maxRange := uint64(minBlkSize * 16)

	buddy, err := New(minBlkSize, maxRange, NoReuse)
	if err != nil {
		t.Errorf("New() failed: %v", err)
	}

	allocMap := make(map[uint64]uint64) // [start]size

	for i := 1; i <= 16; i++ {
		size := uint64(rand.Intn(65536))
		start, err := buddy.Alloc(size)
		if err != nil {
			t.Errorf("Alloc() failed: %v", err)
		}
		if _, ok := allocMap[start]; ok {
			t.Errorf("Alloc() returned duplicate start: %v", start)
		}
		allocMap[start] = 65536
	}

	for start, _ := range allocMap {
		err := buddy.Free(start)
		if err != nil {
			t.Errorf("Free(%v) failed: %v", start, err)
		}
	}

	// since all allocs were freed, the freelist corresponding to the highest order should
	// be the only one populated; verify this. Also, the allocMap should be empty.

	maxOrder := 4 // maxRange is (minBlkSize * 16) = (minBlkSize * 2^4)

	list := buddy.freeList[maxOrder]
	blk := block{0, buddy.maxRange - 1}
	if list[0] != blk {
		t.Errorf("Free() failed: freelist[4] has %v; want {0, %v}", list, buddy.maxRange-1)
	}
	for i := 0; i < maxOrder; i++ {
		list := buddy.freeList[i]
		if len(list) > 0 {
			t.Errorf("Free() failed: freeList[%v] has %v; should be empty.", i, list)
		}
	}
	if len(buddy.allocMap) != 0 {
		t.Errorf("Free() failed: allocMap should be empty; has %v", buddy.allocMap)
	}

}

func TestFreeEmpty(t *testing.T) {

	minBlkSize := uint32(65536)
	maxRange := uint64(minBlkSize * 16)

	buddy, err := New(minBlkSize, maxRange, NoReuse)
	if err != nil {
		t.Errorf("New() failed: %v", err)
	}

	if err := buddy.Free(0); err.Error() != "not-found" {
		t.Errorf("Free(0) failed: got %v; want invalid-start", err)
	}
}
