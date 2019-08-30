//
// Copyright: (C) 2019 Nestybox Inc.  All rights reserved.
//

package subidAlloc

import (
	"strings"
	"testing"

	"github.com/nestybox/sysbox-mgr/intf"
)

type allocTest struct {
	id      string
	size    uint64
	wantUid uint32
	wantGid uint32
	wantErr string
}

func testAlloc(t *testing.T, subidAlloc intf.SubidAlloc, tests []allocTest) {

	for _, test := range tests {
		gotUid, gotGid, gotErr := subidAlloc.Alloc(test.id, test.size)

		var errStr string
		if gotErr == nil {
			errStr = ""
		} else {
			errStr = gotErr.Error()
		}

		if errStr != test.wantErr || gotUid != test.wantUid || gotGid != test.wantGid {

			if errStr == "" {
				errStr = "(no-error)"
			}
			if test.wantErr == "" {
				test.wantErr = "(no-error)"
			}

			t.Errorf("Alloc(%v, %v) failed: got = %v,%v,%v; want = %v,%v,%v",
				test.id, test.size, gotUid, gotGid, errStr, test.wantUid, test.wantGid, test.wantErr)
		}
	}
}

func TestAllocBasic(t *testing.T) {

	subuidCfg := strings.NewReader(`testUser:0:655360`) // range = 65530 * 10
	subgidCfg := strings.NewReader(`testUser:0:655360`)

	subidAlloc, err := New("testUser", NoReuse, subuidCfg, subgidCfg)
	if err != nil {
		t.Errorf("failed to create allocator: %v", err)
		return
	}

	var tests = []allocTest{
		// id, size, wantUid, wantGid, wantErr
		{"1", 65536, 0, 0, ""},
		{"2", 65536, 65536, 65536, ""},
		{"3", 65536, (65536 * 2), (65536 * 2), ""},
		{"4", 65536, (65536 * 3), (65536 * 3), ""},
	}

	testAlloc(t, subidAlloc, tests)
}

func TestAllocRangeLimit(t *testing.T) {

	subuidCfg := strings.NewReader(`testUser:0:655360`) // range = 65530 * 10
	subgidCfg := strings.NewReader(`testUser:0:655360`)

	subidAlloc, err := New("testUser", NoReuse, subuidCfg, subgidCfg)
	if err != nil {
		t.Errorf("failed to create allocator: %v", err)
		return
	}

	var tests = []allocTest{
		// id, size, wantUid, wantGid, wantErr
		{"1", 655361, 0, 0, "exhausted"}, // exceeds range by 1
		{"2", 524289, 0, 0, "exhausted"}, // exceeds nominal range by 1
		{"3", 0, 0, 0, "invalid-size"},
		{"4", 524288, 0, 0, ""}, // matches nominal range
	}

	testAlloc(t, subidAlloc, tests)
}

func TestAllocReuse(t *testing.T) {

	subuidCfg := strings.NewReader(`testUser:65536:131072`)
	subgidCfg := strings.NewReader(`testUser:65536:131072`)

	subidAlloc, err := New("testUser", Reuse, subuidCfg, subgidCfg)
	if err != nil {
		t.Errorf("failed to create allocator: %v", err)
		return
	}

	// tracks allocated ranges
	allocMap := make(map[uint32]uint64)

	// initial allocs
	for i := 0; i < 2; i++ {
		id := string(i)
		size := uint64(65536)
		subuid, _, err := subidAlloc.Alloc(id, size)
		if err != nil {
			t.Errorf("Alloc(%v, %v) failed: %v", id, size, err)
			return
		}
		allocMap[subuid] = size
	}

	// re-alloc and verify ranges are re-used
	for i := 2; i < 4; i++ {
		id := string(i)
		size := uint64(65536)
		subuid, _, err := subidAlloc.Alloc(id, size)
		if err != nil {
			t.Errorf("Alloc(%v, %v) failed: %v", id, size, err)
			return
		}
		if _, ok := allocMap[subuid]; !ok {
			t.Errorf("Alloc(%v, %v) reuse failed: got %v", id, size, subuid)
			return
		}
	}
}

func TestAllocNoReuse(t *testing.T) {

	subuidCfg := strings.NewReader(`testUser:65536:131072`)
	subgidCfg := strings.NewReader(`testUser:65536:131072`)

	subidAlloc, err := New("testUser", NoReuse, subuidCfg, subgidCfg)
	if err != nil {
		t.Errorf("failed to create allocator: %v", err)
		return
	}

	var tests = []allocTest{
		// id, size, wantUid, wantGid, wantErr
		{"1", 1, 65536, 65536, ""},
		{"2", 1, 131072, 131072, ""},
		{"3", 1, 0, 0, "exhausted"},
	}

	testAlloc(t, subidAlloc, tests)
}

func TestAllocErrors(t *testing.T) {

	subuidCfg := strings.NewReader(`testUser:0:655360`) // range = 65530 * 10
	subgidCfg := strings.NewReader(`testUser:0:655360`)

	subidAlloc, err := New("testUser", NoReuse, subuidCfg, subgidCfg)
	if err != nil {
		t.Errorf("failed to create allocator: %v", err)
		return
	}

	var tests = []allocTest{
		// id, size, wantUid, wantGid, wantErr
		{"1", 65536, 0, 0, ""},
		{"1", 65536, 0, 0, "exhausted"},
	}

	testAlloc(t, subidAlloc, tests)
}

func TestFreeBasic(t *testing.T) {
	var err error

	subuidCfg := strings.NewReader(`testUser:65536:131072`)
	subgidCfg := strings.NewReader(`testUser:65536:131072`)

	subidAlloc, err := New("testUser", NoReuse, subuidCfg, subgidCfg)
	if err != nil {
		t.Errorf("failed to create allocator: %v", err)
		return
	}

	// allocate until exhaustion
	var tests = []allocTest{
		{"1", 65536, 65536, 65536, ""},
		{"2", 65536, 131072, 131072, ""},
		{"3", 1, 0, 0, "exhausted"},
	}

	testAlloc(t, subidAlloc, tests)

	// free a range
	if err := subidAlloc.Free("1"); err != nil {
		t.Errorf("Free() returned %v; want no-err", err)
	}

	// reallocate to verify that free worked
	tests = []allocTest{
		{"1", 65536, 65536, 65536, ""},
	}

	testAlloc(t, subidAlloc, tests)
}

func TestFreeErrors(t *testing.T) {

	subuidCfg := strings.NewReader(`testUser:0:65536`)
	subgidCfg := strings.NewReader(`testUser:0:65536`)

	subidAlloc, err := New("testUser", NoReuse, subuidCfg, subgidCfg)
	if err != nil {
		t.Errorf("failed to create allocator: %v", err)
		return
	}

	var tests = []allocTest{
		{"1", 65536, 0, 0, ""},
		{"2", 1, 0, 0, "exhausted"},
	}

	testAlloc(t, subidAlloc, tests)

	if err := subidAlloc.Free("1"); err != nil {
		t.Errorf("FreeUid() returned %v; want no-err", err)
	}

	if err := subidAlloc.Free("1"); err == nil {
		t.Errorf("FreeUid() returned %v; want not-found", err)
	}
}

func TestAllocInvalidUser(t *testing.T) {

	subuidCfg := strings.NewReader(`testUser:0:131072`)
	subgidCfg := strings.NewReader(`testUser:0:131072`)

	_, err := New("anotherUser", NoReuse, subuidCfg, subgidCfg)
	if err == nil {
		t.Errorf("idAlloc.New(): want error, got no error")
		return
	}
}

func TestConcurrency(t *testing.T) {

	// configure range large enough to allow 32 concurrent uid allocations, each for 65536
	subuidCfg := strings.NewReader(`testUser:0:2097152`)
	subgidCfg := strings.NewReader(`testUser:0:2097152`)

	subidAlloc, err := New("testUser", NoReuse, subuidCfg, subgidCfg)
	if err != nil {
		t.Errorf("failed to create allocator: %v", err)
		return
	}

	// spawn multiple goroutines, each of which calls AllocUid and reports back the range &
	// error they got
	numWorkers := 32
	allocSize := uint64(65536)

	type allocResp struct {
		uid, gid uint32
		err      error
	}

	ch := make(chan allocResp, numWorkers)

	for i := 0; i < numWorkers; i++ {
		id := string(i)
		go func(subidAlloc intf.SubidAlloc, id string, size uint64) {
			uid, gid, err := subidAlloc.Alloc(id, size)
			ch <- allocResp{uid, gid, err}
		}(subidAlloc, id, allocSize)
	}

	// wait for each goroutine to report back and verify they each got
	// an exclusive uid range

	type pair struct{ uid, gid uint32 }
	subidMap := make(map[pair]bool)

	for i := 0; i < numWorkers; i++ {
		resp := <-ch
		if resp.err != nil {
			t.Errorf("goroutine alloc failed: %v", resp.err)
		}
		p := pair{resp.uid, resp.gid}
		if _, ok := subidMap[p]; ok {
			t.Errorf("conflicting alloc for uid & gid: %v", p)
		}
		subidMap[p] = true
	}

	// spawn multiple goroutines, each of which calls Free and reports back the error they
	// got

	ch2 := make(chan error, numWorkers)

	for i := 0; i < numWorkers; i++ {
		id := string(i)
		go func(subidAlloc intf.SubidAlloc, id string) {
			ch2 <- subidAlloc.Free(id)
		}(subidAlloc, id)
	}

	// once all goroutines have done this, check that err = nil
	for i := 0; i < numWorkers; i++ {
		err := <-ch2
		if err != nil {
			t.Errorf("goroutine free failed: %v", err)
		}
	}

	// reallocate to ensure freeing worked
	for i := 0; i < numWorkers; i++ {
		id := string(i)
		_, _, err := subidAlloc.Alloc(id, allocSize)
		if err != nil {
			t.Errorf("AllocUid(%v, %v) failed: %v", id, allocSize, err)
			return
		}
	}
}

func TestAllocLimits(t *testing.T) {

	subuidCfg := strings.NewReader(`testUser:0:4294967296`)
	subgidCfg := strings.NewReader(`testUser:0:4294967296`)

	subidAlloc, err := New("testUser", NoReuse, subuidCfg, subgidCfg)
	if err != nil {
		t.Errorf("failed to create allocator: %v", err)
		return
	}

	var tests = []allocTest{
		// id, size, wantUid, wantGid, wantErr
		{"1", 4294967296, 0, 0, ""},
		{"2", 4294967296, 0, 0, "exhausted"},
	}

	testAlloc(t, subidAlloc, tests)

	subuidCfg = strings.NewReader(`testUser:0:0`)
	subgidCfg = strings.NewReader(`testUser:0:0`)

	subidAlloc, err = New("testUser", NoReuse, subuidCfg, subgidCfg)
	if err != nil {
		t.Errorf("failed to create allocator: %v", err)
		return
	}

	tests = []allocTest{
		// id, size, wantUid, wantGid, wantErr
		{"3", 1, 0, 0, "exhausted"},
	}

	testAlloc(t, subidAlloc, tests)
}

func TestAllocMultiRange(t *testing.T) {

	subuidCfg := strings.NewReader(`testUser:0:65536
                                   testUser:524288:65536`)

	subgidCfg := strings.NewReader(`testUser:1048576:65536
                                   testUser:1572864:65536`)

	subidAlloc, err := New("testUser", NoReuse, subuidCfg, subgidCfg)
	if err != nil {
		t.Errorf("failed to create allocator: %v", err)
		return
	}

	var tests = []allocTest{
		// id, size, wantUid, wantGid, wantErr
		{"1", 65536, 0, 1048576, ""},
		{"2", 65536, 524288, 1572864, ""},
		{"3", 65536, 0, 0, "exhausted"},
	}

	testAlloc(t, subidAlloc, tests)
}
