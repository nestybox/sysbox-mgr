//
// Copyright: (C) 2019 Nestybox Inc.  All rights reserved.
//

package subidAlloc

import (
	"strings"
	"testing"

	"github.com/nestybox/sysbox-mgr/intf"
	"github.com/nestybox/sysbox-runc/libcontainer/user"
)

type allocTest struct {
	id      string
	size    uint64
	mode    string
	wantUid uint32
	wantGid uint32
	wantErr string
}

func testAlloc(t *testing.T, subidAlloc intf.SubidAlloc, tests []allocTest) {

	for _, test := range tests {
		gotUid, gotGid, gotErr := subidAlloc.Alloc(test.id, test.size, test.mode)

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

			t.Errorf("Alloc(%v, %v, %v) failed: got = %v,%v,%v; want = %v,%v,%v",
				test.id, test.size, test.mode, gotUid, gotGid, errStr, test.wantUid, test.wantGid, test.wantErr)
		}
	}
}

func TestAllocBasic(t *testing.T) {

	subuidCfg := strings.NewReader(`testUser:0:655360`) // range = 65530 * 10
	subgidCfg := strings.NewReader(`testUser:0:655360`)

	subidAlloc, err := New("testUser", "exclusive", NoReuse, subuidCfg, subgidCfg)
	if err != nil {
		t.Errorf("failed to create allocator: %v", err)
		return
	}

	var tests = []allocTest{
		// id, size, wantUid, wantGid, wantErr
		{"1", 65536, "", 0, 0, ""},
		{"2", 65536, "", 65536, 65536, ""},
		{"3", 65536, "", (65536 * 2), (65536 * 2), ""},
		{"4", 65536, "", (65536 * 3), (65536 * 3), ""},
	}

	testAlloc(t, subidAlloc, tests)
}

func TestAllocRangeLimit(t *testing.T) {

	subuidCfg := strings.NewReader(`testUser:0:655360`) // range = 65530 * 10
	subgidCfg := strings.NewReader(`testUser:0:655360`)

	subidAlloc, err := New("testUser", "exclusive", NoReuse, subuidCfg, subgidCfg)
	if err != nil {
		t.Errorf("failed to create allocator: %v", err)
		return
	}

	var tests = []allocTest{
		// id, size, wantUid, wantGid, wantErr
		{"1", 655361, "", 0, 0, "exhausted"}, // exceeds range by 1
		{"2", 524289, "", 0, 0, "exhausted"}, // exceeds nominal range by 1
		{"3", 0, "", 0, 0, "invalid-size"},
		{"4", 524288, "", 0, 0, ""}, // matches nominal range
	}

	testAlloc(t, subidAlloc, tests)
}

func TestAllocReuse(t *testing.T) {

	subuidCfg := strings.NewReader(`testUser:65536:131072`)
	subgidCfg := strings.NewReader(`testUser:65536:131072`)

	subidAlloc, err := New("testUser", "exclusive", Reuse, subuidCfg, subgidCfg)
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
		mode := ""
		subuid, _, err := subidAlloc.Alloc(id, size, mode)
		if err != nil {
			t.Errorf("Alloc(%v, %v, %v) failed: %v", id, size, mode, err)
			return
		}
		allocMap[subuid] = size
	}

	// re-alloc and verify ranges are re-used
	for i := 2; i < 4; i++ {
		id := string(i)
		size := uint64(65536)
		mode := ""
		subuid, _, err := subidAlloc.Alloc(id, size, mode)
		if err != nil {
			t.Errorf("Alloc(%v, %v, %v) failed: %v", id, size, mode, err)
			return
		}
		if _, ok := allocMap[subuid]; !ok {
			t.Errorf("Alloc(%v, %v, %v) reuse failed: got %v", id, size, mode, subuid)
			return
		}
	}
}

func TestAllocNoReuse(t *testing.T) {

	subuidCfg := strings.NewReader(`testUser:65536:131072`)
	subgidCfg := strings.NewReader(`testUser:65536:131072`)

	subidAlloc, err := New("testUser", "exclusive", NoReuse, subuidCfg, subgidCfg)
	if err != nil {
		t.Errorf("failed to create allocator: %v", err)
		return
	}

	var tests = []allocTest{
		// id, size, wantUid, wantGid, wantErr
		{"1", 1, "", 65536, 65536, ""},
		{"2", 1, "", 131072, 131072, ""},
		{"3", 1, "", 0, 0, "exhausted"},
	}

	testAlloc(t, subidAlloc, tests)
}

func TestAllocErrors(t *testing.T) {

	subuidCfg := strings.NewReader(`testUser:0:655360`) // range = 65530 * 10
	subgidCfg := strings.NewReader(`testUser:0:655360`)

	subidAlloc, err := New("testUser", "exclusive", NoReuse, subuidCfg, subgidCfg)
	if err != nil {
		t.Errorf("failed to create allocator: %v", err)
		return
	}

	var tests = []allocTest{
		// id, size, wantUid, wantGid, wantErr
		{"1", 65536, "", 0, 0, ""},
		{"1", 65536, "", 0, 0, "exhausted"},
	}

	testAlloc(t, subidAlloc, tests)
}

func TestFreeBasic(t *testing.T) {
	var err error

	subuidCfg := strings.NewReader(`testUser:65536:131072`)
	subgidCfg := strings.NewReader(`testUser:65536:131072`)

	subidAlloc, err := New("testUser", "exclusive", NoReuse, subuidCfg, subgidCfg)
	if err != nil {
		t.Errorf("failed to create allocator: %v", err)
		return
	}

	// allocate until exhaustion
	var tests = []allocTest{
		{"1", 65536, "", 65536, 65536, ""},
		{"2", 65536, "", 131072, 131072, ""},
		{"3", 1, "", 0, 0, "exhausted"},
	}

	testAlloc(t, subidAlloc, tests)

	// free a range
	if err := subidAlloc.Free("1"); err != nil {
		t.Errorf("Free() returned %v; want no-err", err)
	}

	// reallocate to verify that free worked
	tests = []allocTest{
		{"1", 65536, "", 65536, 65536, ""},
	}

	testAlloc(t, subidAlloc, tests)
}

func TestFreeErrors(t *testing.T) {

	subuidCfg := strings.NewReader(`testUser:0:65536`)
	subgidCfg := strings.NewReader(`testUser:0:65536`)

	subidAlloc, err := New("testUser", "exclusive", NoReuse, subuidCfg, subgidCfg)
	if err != nil {
		t.Errorf("failed to create allocator: %v", err)
		return
	}

	var tests = []allocTest{
		{"1", 65536, "", 0, 0, ""},
		{"2", 1, "", 0, 0, "exhausted"},
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

	_, err := New("anotherUser", "exclusive", NoReuse, subuidCfg, subgidCfg)
	if err == nil {
		t.Errorf("idAlloc.New(): want error, got no error")
		return
	}
}

func TestConcurrency(t *testing.T) {

	// configure range large enough to allow 32 concurrent uid allocations, each for 65536
	subuidCfg := strings.NewReader(`testUser:0:2097152`)
	subgidCfg := strings.NewReader(`testUser:0:2097152`)

	subidAlloc, err := New("testUser", "exclusive", NoReuse, subuidCfg, subgidCfg)
	if err != nil {
		t.Errorf("failed to create allocator: %v", err)
		return
	}

	// spawn multiple goroutines, each of which calls AllocUid and reports back the range
	// and error they got
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
			uid, gid, err := subidAlloc.Alloc(id, size, "")
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
		_, _, err := subidAlloc.Alloc(id, allocSize, "")
		if err != nil {
			t.Errorf("AllocUid(%v, %v) failed: %v", id, allocSize, err)
			return
		}
	}
}

func TestAllocLimits(t *testing.T) {

	subuidCfg := strings.NewReader(`testUser:0:4294967296`)
	subgidCfg := strings.NewReader(`testUser:0:4294967296`)

	subidAlloc, err := New("testUser", "exclusive", NoReuse, subuidCfg, subgidCfg)
	if err != nil {
		t.Errorf("failed to create allocator: %v", err)
		return
	}

	var tests = []allocTest{
		// id, size, wantUid, wantGid, wantErr
		{"1", 4294967296, "", 0, 0, ""},
		{"2", 4294967296, "", 0, 0, "exhausted"},
	}

	testAlloc(t, subidAlloc, tests)

	subuidCfg = strings.NewReader(`testUser:0:0`)
	subgidCfg = strings.NewReader(`testUser:0:0`)

	subidAlloc, err = New("testUser", "exclusive", NoReuse, subuidCfg, subgidCfg)
	if err != nil {
		t.Errorf("failed to create allocator: %v", err)
		return
	}

	tests = []allocTest{
		// id, size, wantUid, wantGid, wantErr
		{"3", 1, "", 0, 0, "exhausted"},
	}

	testAlloc(t, subidAlloc, tests)
}

func TestAllocMultiRange(t *testing.T) {

	subuidCfg := strings.NewReader(`testUser:0:65536
                                   testUser:524288:65536`)

	subgidCfg := strings.NewReader(`testUser:0:65536
                                   testUser:524288:65536`)

	subidAlloc, err := New("testUser", "exclusive", NoReuse, subuidCfg, subgidCfg)
	if err != nil {
		t.Errorf("failed to create allocator: %v", err)
		return
	}

	var tests = []allocTest{
		// id, size, wantUid, wantGid, wantErr
		{"1", 65536, "", 0, 0, ""},
		{"2", 65536, "", 524288, 524288, ""},
		{"3", 65536, "", 0, 0, "exhausted"},
	}

	testAlloc(t, subidAlloc, tests)
}

func TestGetCommonRanges(t *testing.T) {

	uidRanges := []user.SubID{{"1", 0, 5}, {"2", 7, 3}, {"3", 10, 6}, {"4", 20, 1}}
	gidRanges := []user.SubID{{"1", 1, 5}, {"2", 7, 3}, {"3", 10, 7}, {"4", 20, 1}}

	want := []user.SubID{{"2", 7, 3}, {"4", 20, 1}}
	got := getCommonRanges(uidRanges, gidRanges)

	if len(want) != len(got) {
		t.Errorf("getCommonRanges(%v, %v) failed; want %v; got %v", uidRanges, gidRanges, want, got)
	}

	for _, w := range want {
		found := false
		for _, g := range got {
			if w == g {
				found = true
			}
		}
		if !found {
			t.Errorf("getCommonRanges(%v, %v) failed; want %v; got %v", uidRanges, gidRanges, want, got)
		}
	}
}

func TestAllocCommonRange(t *testing.T) {

	subuidCfg := strings.NewReader(`testUser:0:65536
                                   testUser:524288:65536`)

	subgidCfg := strings.NewReader(`testUser:65536:65536
		                             testUser:0:65536`)

	subidAlloc, err := New("testUser", "exclusive", NoReuse, subuidCfg, subgidCfg)
	if err != nil {
		t.Errorf("failed to create allocator: %v", err)
	}

	var tests = []allocTest{
		// id, size, wantUid, wantGid, wantErr
		{"1", 65536, "", 0, 0, ""},
		{"2", 65536, "", 0, 0, "exhausted"},
	}

	testAlloc(t, subidAlloc, tests)

	subuidCfg = strings.NewReader(`testUser:0:65536
                                  testUser:524288:65536`)

	subgidCfg = strings.NewReader(`testUser:65536:65536
                                  testUser:231072:65536`)

	subidAlloc, err = New("testUser", "exclusive", NoReuse, subuidCfg, subgidCfg)
	if err == nil {
		t.Errorf("subidAlloc() passed; expected failure")
	}
}

func TestIdentityMode(t *testing.T) {

	subuidCfg := strings.NewReader(`testUser:0:655360`) // range = 65530 * 10
	subgidCfg := strings.NewReader(`testUser:0:655360`)

	subidAlloc, err := New("testUser", "identity", NoReuse, subuidCfg, subgidCfg)
	if err != nil {
		t.Errorf("failed to create allocator: %v", err)
		return
	}

	var tests = []allocTest{
		// id, size, wantUid, wantGid, wantErr
		{"1", 65536, "", 0, 0, ""},
		{"2", 65536, "", 0, 0, ""},
		{"3", 65536, "", 0, 0, ""},
		{"4", 65536, "", 0, 0, ""},
	}

	testAlloc(t, subidAlloc, tests)

	// free all ranges
	ids := []string{"1", "2", "3", "4"}
	for _, id := range ids {
		if err := subidAlloc.Free(id); err != nil {
			t.Errorf("Free() returned %v; want no-err", err)
		}
	}

	// reallocate to verify the free worked
	testAlloc(t, subidAlloc, tests)

	// reallocate for container id "1" and verify this fails
	_, _, err = subidAlloc.Alloc("1", 65536, "")
	if err == nil {
		t.Errorf("Alloc() returned no error; want \"exhausted\"")
	}

}

func TestExclusiveModeOverride(t *testing.T) {

	// Configure subid allocator in exclusive mode but issue allocs with identity-mode

	subuidCfg := strings.NewReader(`testUser:0:655360`) // range = 65530 * 10
	subgidCfg := strings.NewReader(`testUser:0:655360`)

	subidAlloc, err := New("testUser", "exclusive", NoReuse, subuidCfg, subgidCfg)
	if err != nil {
		t.Errorf("failed to create allocator: %v", err)
		return
	}

	var tests = []allocTest{
		// id, size, wantUid, wantGid, wantErr
		{"1", 65536, "", 0, 0, ""},
		{"2", 65536, "", 65536, 65536, ""},
		{"3", 65536, "identity", 0, 0, ""},
		{"4", 65536, "", (65536 * 2), (65536 * 2), ""},
		{"5", 65536, "exclusive", (65536 * 3), (65536 * 3), ""},
		{"6", 65536, "identity", 0, 0, ""},
	}

	testAlloc(t, subidAlloc, tests)

	// free all ranges
	ids := []string{"1", "2", "3", "4", "5", "6"}
	for _, id := range ids {
		if err := subidAlloc.Free(id); err != nil {
			t.Errorf("Free() returned %v; want no-err", err)
		}
	}

	// reallocate to verify the free worked
	testAlloc(t, subidAlloc, tests)
}

func TestIdentityModeOverride(t *testing.T) {

	// Configure subid allocator in identity mode but issue allocs with exclusive-mode

	subuidCfg := strings.NewReader(`testUser:0:655360`) // range = 65530 * 10
	subgidCfg := strings.NewReader(`testUser:0:655360`)

	subidAlloc, err := New("testUser", "identity", NoReuse, subuidCfg, subgidCfg)
	if err != nil {
		t.Errorf("failed to create allocator: %v", err)
		return
	}

	var tests = []allocTest{
		// id, size, wantUid, wantGid, wantErr
		{"1", 65536, "", 0, 0, ""},
		{"2", 65536, "", 0, 0, ""},
		{"3", 65536, "exclusive", 0, 0, ""},
		{"4", 65536, "", 0, 0, ""},
		{"5", 65536, "exclusive", 65536, 65536, ""},
		{"6", 65536, "exclusive", (65536 * 2), (65536 * 2), ""},
		{"7", 65536, "identity", 0, 0, ""},
	}

	testAlloc(t, subidAlloc, tests)

	// free all ranges
	ids := []string{"1", "2", "3", "4", "5", "6", "7"}
	for _, id := range ids {
		if err := subidAlloc.Free(id); err != nil {
			t.Errorf("Free() returned %v; want no-err", err)
		}
	}

	// reallocate to verify the free worked
	testAlloc(t, subidAlloc, tests)
}
