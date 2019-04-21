package idAlloc

import (
	"strings"
	"testing"

	intf "github.com/nestybox/sysvisor/sysvisor-mgr/interfaces"
)

type allocTest struct {
	size    uint32
	wantID  uint32
	wantErr string
}

func testAlloc(t *testing.T, idAllocator intf.IDAllocator, tests []allocTest) {
	var errStr string

	for _, test := range tests {
		gotID, gotErr := idAllocator.Alloc(test.size)

		if gotErr == nil {
			errStr = "no-err"
		} else {
			errStr = gotErr.Error()
		}

		if errStr != test.wantErr || gotID != test.wantID {
			t.Errorf("Alloc(%v) failed: got = %v, err = %v; want = %v, want-err = %v",
				test.size, gotID, errStr, test.wantID, test.wantErr)
		}
	}

}

func TestAllocBasic(t *testing.T) {
	subidCfg := `testUser:10:90
                testUser:200:10`
	fakeSubid := strings.NewReader(subidCfg)

	idAllocator, err := New("testUser", NoReuse, fakeSubid)
	if err != nil {
		t.Errorf("failed to create allocator: %v", err)
	}

	var tests = []allocTest{
		// size, want, wantErr
		{100, 0, "id-exhausted"},
		{30, 10, "no-err"},
		{60, 40, "no-err"},
		{5, 200, "no-err"},
		{5, 205, "no-err"},
		{1, 0, "id-exhausted"},
		{0, 0, "invalid-size"},
	}

	testAlloc(t, idAllocator, tests)
}

func TestAllocReuse(t *testing.T) {
	subidCfg := `testUser:0:100`
	fakeSubid := strings.NewReader(subidCfg)

	idAllocator, err := New("testUser", Reuse, fakeSubid)
	if err != nil {
		t.Errorf("failed to create allocator: %v", err)
	}

	var tests = []allocTest{
		// size, want, wantErr
		{50, 0, "no-err"},
		{50, 50, "no-err"},
		{50, 0, "no-err"},
		{50, 50, "no-err"},
	}

	testAlloc(t, idAllocator, tests)
}

func TestAllocNoReuse(t *testing.T) {
	subidCfg := `testUser:0:100`
	fakeSubid := strings.NewReader(subidCfg)

	idAllocator, err := New("testUser", NoReuse, fakeSubid)
	if err != nil {
		t.Errorf("failed to create allocator: %v", err)
	}

	var tests = []allocTest{
		// size, want, wantErr
		{50, 0, "no-err"},
		{50, 50, "no-err"},
		{1, 0, "id-exhausted"},
	}

	testAlloc(t, idAllocator, tests)
}

func TestFreeBasic(t *testing.T) {
	var err error

	subidCfg := `testUser:0:100`
	fakeSubid := strings.NewReader(subidCfg)

	idAllocator, err := New("testUser", NoReuse, fakeSubid)
	if err != nil {
		t.Errorf("failed to create allocator: %v", err)
	}

	// allocate until exhaustion
	var tests = []allocTest{
		{50, 0, "no-err"},
		{50, 50, "no-err"},
		{1, 0, "id-exhausted"},
	}

	testAlloc(t, idAllocator, tests)

	// free a range
	if err := idAllocator.Free(0); err != nil {
		t.Errorf("Free() returned %v; want no-err", err)
	}

	// reallocate to verify that free worked
	tests = []allocTest{
		{50, 0, "no-err"},
	}

	testAlloc(t, idAllocator, tests)
}

func TestAllocInvalidUser(t *testing.T) {
	subidCfg := `testUser:10:90`
	fakeSubid := strings.NewReader(subidCfg)

	_, err := New("anotherUser", NoReuse, fakeSubid)
	if err == nil {
		t.Errorf("idAlloc.New(): want error, got no error")
	}
}

func TestAllocRefcnt(t *testing.T) {

	subidCfg := `testUser:100:100`
	fakeSubid := strings.NewReader(subidCfg)

	idAllocator, err := New("testUser", Reuse, fakeSubid)
	if err != nil {
		t.Errorf("failed to create allocator: %v", err)
	}

	// allocate twice on same range (should increase refcnt to 2)
	var tests = []allocTest{
		{100, 100, "no-err"},
		{100, 100, "no-err"},
	}

	testAlloc(t, idAllocator, tests)

	// check refcount
	idAlloc, ok := idAllocator.(*idAlloc)
	if !ok {
		t.Errorf("failed to type-switch allocator")
	}

	me := idAlloc.allocMap[100]
	if me.size != 100 || me.refcnt != 2 {
		t.Errorf("alloc map refcnt error: want {100, 2}, got %v", me)
	}

	// free one allocation (should decrease refcnt to 1)
	if err := idAllocator.Free(100); err != nil {
		t.Errorf("Free() failed: %v", err)
	}

	me = idAlloc.allocMap[100]
	if me.size != 100 || me.refcnt != 1 {
		t.Errorf("alloc map refcnt error: want {100, 1}, got %v", me)
	}

	// free again and re-check
	if err := idAllocator.Free(100); err != nil {
		t.Errorf("Free() failed: %v", err)
	}

	me, ok = idAlloc.allocMap[100]
	if ok {
		t.Errorf("alloc map refcnt error: entry should have been deleted, got %v", me)
	}
}

func TestConcurrency(t *testing.T) {

	// create id allocator
	subidCfg := `testUser:100:100`
	fakeSubid := strings.NewReader(subidCfg)

	idAllocator, err := New("testUser", Reuse, fakeSubid)
	if err != nil {
		t.Errorf("failed to create allocator: %v", err)
	}

	// spawn multiple goroutines, each of which calls Alloc and reports back the range &
	// error they got

	numWorkers := 10
	allocSize := uint32(10)

	type allocResp struct {
		start uint32
		err   error
	}

	ch := make(chan allocResp, numWorkers)

	for i := 0; i < numWorkers; i++ {
		go func(idAlloc intf.IDAllocator, size uint32) {
			start, err := idAlloc.Alloc(size)
			ch <- allocResp{start, err}
		}(idAllocator, allocSize)
	}

	// once all goroutines have done this, check that err = nil on all and each got an
	// exclusive range

	respMap := make(map[uint32]bool)

	for i := 0; i < numWorkers; i++ {
		resp := <-ch
		if resp.err != nil {
			t.Errorf("goroutine alloc failed: %v", resp.err)
		}
		if _, ok := respMap[resp.start]; ok {
			t.Errorf("conflicting alloc start: %d", resp.start)
		}
		respMap[resp.start] = true
	}

	// spawn multiple goroutines, each of which calls Free and reports back the error they
	// got

	ch2 := make(chan error, numWorkers)

	for s := range respMap {
		go func(idAlloc intf.IDAllocator, start uint32) {
			ch2 <- idAlloc.Free(start)
		}(idAllocator, s)
	}

	// once all goroutines have done this, check that err = nil
	for range respMap {
		err := <-ch2
		if err != nil {
			t.Errorf("goroutine free failed: %v", err)
		}
	}

	// check that allocMap is empty
	idAlloc, ok := idAllocator.(*idAlloc)
	if !ok {
		t.Errorf("failed to type-switch allocator")
	}

	if len(idAlloc.allocMap) != 0 {
		t.Errorf("alloc map is not empty; got %v", idAlloc.allocMap)
	}
}

func TestFreeErrors(t *testing.T) {
	// TODO
}
