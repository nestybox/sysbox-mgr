
package shiftfsMgr

import (
	"testing"

	"github.com/opencontainers/runc/libcontainer/configs"
)

func init() {
	testingMode = true
}

type mountTest struct {
	id     string
	mounts []configs.ShiftfsMount
}

func isEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}

func TestShiftfsMgrBasic(t *testing.T) {

	mgrIf, _ := New()
	mgr := mgrIf.(*mgr)

	// Generare some shiftfs mark requests
	test := []mountTest{
		{
			id: "testCont1",
			mounts: []configs.ShiftfsMount{
				{"/a/b/c", false},
				{"/d/e/f/g", false},
			},
		},
		{
			id: "testCont2",
			mounts: []configs.ShiftfsMount{
				{"/a/b/c", false},
				{"/x/y/z", false},
			},
		},
		{
			id: "testCont3",
			mounts: []configs.ShiftfsMount{
				{"/i/h/j", false},
				{"/x/y/z", false},
				{"/a/b/c", false},
			},
		},
	}

	for _, mt := range test {
		if err := mgr.Mark(mt.id, mt.mounts); err != nil {
			t.Errorf("failed to mark mounts: %v", err)
		}
	}

	// verify the shiftfsMgr mpMap looks good
	keys := []string{"/a/b/c", "/d/e/f/g", "/x/y/z", "/i/h/j"}
	val := [][]string{
		{"testCont1", "testCont2", "testCont3"},
		{"testCont1"},
		{"testCont2", "testCont3"},
		{"testCont3"},
	}

	for i, k := range keys {
		ids := mgr.mpMap[k]
		if !isEqual(ids, val[i]) {
			t.Errorf("error: mpMap[%s] = %v; want mpMap[%s] = %v", k, ids, k, val[i])
		}
	}

	// Generare some shiftfs unmark requests
	for _, mt := range test {
		if err := mgr.Unmark(mt.id, mt.mounts); err != nil {
			t.Errorf("failed to unmark mounts: %v", err)
		}
	}

	if len(mgr.mpMap) != 0 {
		t.Errorf("error: mpMap is not empty; it is %v", mgr.mpMap)
	}
}

func TestShiftfsMgrErrors(t *testing.T) {

	mgrIf, _ := New()
	mgr := mgrIf.(*mgr)

	// Generare some shiftfs mark requests
	test := []mountTest{
		{
			id: "testCont1",
			mounts: []configs.ShiftfsMount{
				{"/a/b/c", false},
				{"/d/e/f/g", false},
			},
		},
		{
			id: "testCont2",
			mounts: []configs.ShiftfsMount{
				{"/a/b/c", false},
				{"/x/y/z", false},
			},
		},
		{
			id: "testCont3",
			mounts: []configs.ShiftfsMount{
				{"/i/h/j", false},
				{"/x/y/z", false},
				{"/a/b/c", false},
			},
		},
	}

	for _, mt := range test {
		if err := mgr.Mark(mt.id, mt.mounts); err != nil {
			t.Errorf("failed to mark mounts: %v", err)
		}
	}

	//
	// Verify error cases are handled correctly
	//

	// Incorrect mounts (expected to be ignored by shiftfs mgr)
	mounts := []configs.ShiftfsMount{
		{
			Source:   "/c/t/v",
			Readonly: false,
		},
	}
	if err := mgr.Unmark("testCont1", mounts); err != nil {
		t.Errorf("expected unmark of unknown mount to be ignored but it failed")
	}

	// Incorrect container id
	mounts = []configs.ShiftfsMount{
		{
			Source:   "/a/b/c",
			Readonly: false,
		},
	}
	if err := mgr.Unmark("dummy", mounts); err == nil {
		t.Errorf("expected unmark to fail but it passed")
	}

}
