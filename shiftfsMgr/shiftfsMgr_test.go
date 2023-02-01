//
// Copyright 2019-2021 Nestybox, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package shiftfsMgr

import (
	"io"
	"io/ioutil"
	"os"
	"testing"

	"github.com/nestybox/sysbox-libs/mount"
	"github.com/nestybox/sysbox-libs/shiftfs"
	utils "github.com/nestybox/sysbox-libs/utils"
	"github.com/opencontainers/runc/libcontainer/configs"
)

var sysboxLibDir string = "/var/lib/sysbox"

type mountTest struct {
	id     string
	mounts []configs.ShiftfsMount
}

func hostSupportsShiftfs() bool {
	modSupported, err := utils.KernelModSupported("shiftfs")
	if err != nil {
		return false
	}
	return modSupported
}

func setupTest() (string, error) {
	dir, err := ioutil.TempDir("/mnt/scratch", "shiftfsMgrTest")
	if err != nil {
		return "", err
	}

	return dir, nil
}

func cleanupTest(dir string) {
	os.RemoveAll(dir)
}

func dirIsEmpty(name string) (bool, error) {
	f, err := os.Open(name)
	if err != nil {
		return false, err
	}
	defer f.Close()

	_, err = f.Readdirnames(1)
	if err == io.EOF {
		return true, nil
	}

	return false, err
}

func mountTestEqual(a, b []mountTest) bool {
	if len(a) != len(b) {
		return false
	}

	for i, _ := range a {
		if a[i].id != b[i].id {
			return false
		}

		if len(a[i].mounts) != len(b[i].mounts) {
			return false
		}

		for j, _ := range a[i].mounts {
			if a[i].mounts[j] != b[i].mounts[j] {
				return false
			}
		}
	}

	return true
}

func TestShiftfsMgrBasic(t *testing.T) {

	if !hostSupportsShiftfs() {
		t.Skip("skipping test (shiftfs not supported).")
	}

	tdir, err := setupTest()
	if err != nil {
		t.Errorf("error: setupTest() failed: %s", err)
	}

	mgrIf, _ := New(sysboxLibDir)
	mgr := mgrIf.(*mgr)

	// Generare some shiftfs mark requests
	testIn := []mountTest{
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

	for _, mt := range testIn {
		for _, m := range mt.mounts {
			if err := os.MkdirAll(m.Source, 0755); err != nil {
				t.Error(err)
			}
		}
	}

	testOut := []mountTest{}

	for _, mt := range testIn {

		mp, err := mgr.Mark(mt.id, mt.mounts, false)
		if err != nil {
			t.Errorf("error: failed to mark mounts: %v", err)
		}

		entry := mountTest{
			id:     mt.id,
			mounts: mp,
		}

		testOut = append(testOut, entry)
	}

	// Verify the shiftfs marks are present
	allMounts, err := mount.GetMounts()
	if err != nil {
		t.Error(err)
	}

	for _, mt := range testOut {
		for _, m := range mt.mounts {
			marked, err := shiftfs.Mounted(m.Source, allMounts)
			if err != nil {
				t.Error(err)
			}
			if !marked {
				t.Errorf("error: shiftfs mark expected on %s, but none found.", m.Source)
			}
		}
	}

	if !mountTestEqual(testIn, testOut) {
		t.Errorf("error: markpoint mismatch: got %v, want %v", testOut, testIn)
	}

	// verify the shiftfsMgr mreqCntrMap looks good
	uniqueMnts := []string{"/a/b/c", "/d/e/f/g", "/x/y/z", "/i/h/j"}
	cntrs := [][]string{
		{"testCont1", "testCont2", "testCont3"},
		{"testCont1"},
		{"testCont2", "testCont3"},
		{"testCont3"},
	}

	for i, k := range uniqueMnts {
		ids := mgr.mreqCntrMap[k]
		if !utils.StringSliceEqual(ids, cntrs[i]) {
			t.Errorf("error: mreqCntrMap[%s] = %v; want mreqCntrMap[%s] = %v", k, ids, k, cntrs[i])
		}
	}

	// Generate shiftfs unmark requests
	for _, mt := range testOut {
		if err := mgr.Unmark(mt.id, mt.mounts); err != nil {
			t.Errorf("error: failed to unmark mounts: %v", err)
		}
	}

	// Verify the shiftfs marks were removed
	allMounts, err = mount.GetMounts()
	if err != nil {
		t.Error(err)
	}

	for _, mt := range testOut {
		for _, m := range mt.mounts {
			marked, err := shiftfs.Mounted(m.Source, allMounts)
			if err != nil {
				t.Error(err)
			}
			if marked {
				t.Errorf("error: shiftfs mark not expected on %s, but found.", m.Source)
			}
		}
	}

	// verify the shiftfMgr mreqCntrMap is clean now
	if len(mgr.mreqCntrMap) != 0 {
		t.Errorf("error: mreqCntrMap is not empty; it is %v", mgr.mreqCntrMap)
	}

	// verify work dir is clean
	empty, err := dirIsEmpty(mgr.workDir)
	if err != nil {
		t.Error(err)
	}
	if !empty {
		t.Errorf("error: dir %s is expected to be empty but it's not.", mgr.workDir)
	}

	cleanupTest(tdir)
}

func TestShiftfsMgrCreateMarkpoint(t *testing.T) {

	if !hostSupportsShiftfs() {
		t.Skip("skipping test (shiftfs not supported).")
	}

	tdir, err := setupTest()
	if err != nil {
		t.Errorf("error: setupTest() failed: %s", err)
	}

	mgrIf, _ := New(sysboxLibDir)
	mgr := mgrIf.(*mgr)

	// Generare some shiftfs mark requests
	testIn := []mountTest{
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

	for _, mt := range testIn {
		for _, m := range mt.mounts {
			if err := os.MkdirAll(m.Source, 0755); err != nil {
				t.Error(err)
			}
		}
	}

	testOut := []mountTest{}

	for _, mt := range testIn {

		// createMarkpoint = true
		mp, err := mgr.Mark(mt.id, mt.mounts, true)
		if err != nil {
			t.Errorf("error: failed to mark mounts: %v", err)
		}

		entry := mountTest{
			id:     mt.id,
			mounts: mp,
		}

		testOut = append(testOut, entry)
	}

	// Verify the shiftfs marks are present
	allMounts, err := mount.GetMounts()
	if err != nil {
		t.Error(err)
	}

	for _, mt := range testOut {
		for _, m := range mt.mounts {
			marked, err := shiftfs.Mounted(m.Source, allMounts)
			if err != nil {
				t.Error(err)
			}
			if !marked {
				t.Errorf("error: shiftfs mark expected on %s, but none found.", m.Source)
			}
		}
	}

	// The markpoints are expected to differ from the original mounts
	if mountTestEqual(testIn, testOut) {
		t.Errorf("error: markpoint mismatch: got %v, want %v", testOut, testIn)
	}

	// But there should be as many markpoints returned as passed to Mark()
	if len(testOut) != len(testIn) {
		t.Errorf("error: markpoint length mismatch: got %d, want %d", len(testOut), len(testIn))
	}

	// Verify the shiftfsMgr mreqCntrMap looks good
	uniqueMnts := []string{"/a/b/c", "/d/e/f/g", "/x/y/z", "/i/h/j"}
	cntrs := [][]string{
		{"testCont1", "testCont2", "testCont3"},
		{"testCont1"},
		{"testCont2", "testCont3"},
		{"testCont3"},
	}

	for i, k := range uniqueMnts {
		ids := mgr.mreqCntrMap[k]
		if !utils.StringSliceEqual(ids, cntrs[i]) {
			t.Errorf("error: mreqCntrMap[%s] = %v; want mreqCntrMap[%s] = %v", k, ids, k, cntrs[i])
		}
	}

	// Verify the created markpoints are as expected (there should be as many as
	// the length of slice "uniqueMnts" above").
	markpoints, _ := ioutil.ReadDir(mgr.workDir)
	if len(markpoints) != len(uniqueMnts) {
		t.Errorf("error: incorrect number of markpoints (expected %d); markpoints = %v", len(uniqueMnts), markpoints)
	}

	// Generate shiftfs unmark requests
	for _, mt := range testOut {
		if err := mgr.Unmark(mt.id, mt.mounts); err != nil {
			t.Errorf("error: failed to unmark mounts: %v", err)
		}
	}

	if len(mgr.mreqCntrMap) != 0 {
		t.Errorf("error: mreqCntrMap is not empty; it is %v", mgr.mreqCntrMap)
	}

	if len(mgr.mpMreqMap) != 0 {
		t.Errorf("error: mpMreqMap is not empty; it is %v", mgr.mpMreqMap)
	}

	// verify work dir is clean
	empty, err := dirIsEmpty(mgr.workDir)
	if err != nil {
		t.Error(err)
	}
	if !empty {
		t.Errorf("error: dir %s is expected to be empty but it's not.", mgr.workDir)
	}

	cleanupTest(tdir)
}

func TestShiftfsMgrMarkIgnore(t *testing.T) {

	if !hostSupportsShiftfs() {
		t.Skip("skipping test (shiftfs not supported).")
	}

	tdir, err := setupTest()
	if err != nil {
		t.Errorf("error: setupTest() failed: %s", err)
	}

	mgrIf, _ := New(sysboxLibDir)
	mgr := mgrIf.(*mgr)

	// Generare some shiftfs mark requests
	testIn := []mountTest{
		{
			id: "testCont1",
			mounts: []configs.ShiftfsMount{
				{"/a/b/c", false},
				{"/d/e/f/g", false},
			},
		},
	}

	// Create the mark request dirs and pre-mark them with shiftfs; since they
	// are premarked, the shiftfsMgr should not try to mark them.
	for _, mt := range testIn {
		for _, m := range mt.mounts {
			if err := os.MkdirAll(m.Source, 0755); err != nil {
				t.Error(err)
			}
			if err := shiftfs.Mark(m.Source, m.Source); err != nil {
				t.Error(err)
			}
		}
	}

	testOut := []mountTest{}

	for _, mt := range testIn {

		// createMarkpoint = true
		mp, err := mgr.Mark(mt.id, mt.mounts, true)
		if err != nil {
			t.Errorf("error: failed to mark mounts: %v", err)
		}

		entry := mountTest{
			id:     mt.id,
			mounts: mp,
		}

		testOut = append(testOut, entry)
	}

	// Verify the shiftfs marks are remain (shiftfsMgr should not have touched them)
	allMounts, err := mount.GetMounts()
	if err != nil {
		t.Error(err)
	}

	for _, mt := range testOut {
		for _, m := range mt.mounts {
			marked, err := shiftfs.Mounted(m.Source, allMounts)
			if err != nil {
				t.Error(err)
			}
			if !marked {
				t.Errorf("error: shiftfs mark expected on %s, but none found.", m.Source)
			}
		}
	}

	// Verify the returned markpoints are identical to the given mounts
	if !mountTestEqual(testIn, testOut) {
		t.Errorf("error: markpoint mismatch: got %v, want %v", testOut, testIn)
	}

	// Generate shiftfs unmark requests
	for _, mt := range testOut {
		if err := mgr.Unmark(mt.id, mt.mounts); err != nil {
			t.Errorf("error: failed to unmark mounts: %v", err)
		}
	}

	// Verify the shiftfs marks were not removed (since they were not added by shiftfsMgr)
	allMounts, err = mount.GetMounts()
	if err != nil {
		t.Error(err)
	}

	for _, mt := range testOut {
		for _, m := range mt.mounts {
			marked, err := shiftfs.Mounted(m.Source, allMounts)
			if err != nil {
				t.Error(err)
			}
			if !marked {
				t.Errorf("error: shiftfs mark expected on %s, but not found.", m.Source)
			}
		}
	}

	// verify work dir is clean
	empty, err := dirIsEmpty(mgr.workDir)
	if err != nil {
		t.Error(err)
	}
	if !empty {
		t.Errorf("error: dir %s is expected to be empty but it's not.", mgr.workDir)
	}

	// Remove shiftfs marks
	for _, mt := range testIn {
		for _, m := range mt.mounts {
			if err := shiftfs.Unmount(m.Source); err != nil {
				t.Error(err)
			}
		}
	}

	cleanupTest(tdir)
}

func TestShiftfsMgrUnmarkAll(t *testing.T) {

	if !hostSupportsShiftfs() {
		t.Skip("skipping test (shiftfs not supported).")
	}

	tdir, err := setupTest()
	if err != nil {
		t.Errorf("error: setupTest() failed: %s", err)
	}

	mgrIf, _ := New(sysboxLibDir)
	mgr := mgrIf.(*mgr)

	// Generate some shiftfs mark requests
	testIn := []mountTest{
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

	for _, mt := range testIn {
		for _, m := range mt.mounts {
			if err := os.MkdirAll(m.Source, 0755); err != nil {
				t.Error(err)
			}
		}
	}

	for _, mt := range testIn {
		if _, err := mgr.Mark(mt.id, mt.mounts, true); err != nil {
			t.Errorf("error: failed to mark mounts: %v", err)
		}
	}

	mgr.UnmarkAll()

	// verify work dir is clean (implies shiftfs marks were removed)
	empty, err := dirIsEmpty(mgr.workDir)
	if err != nil {
		t.Error(err)
	}
	if !empty {
		t.Errorf("error: dir %s is expected to be empty but it's not.", mgr.workDir)
	}

	cleanupTest(tdir)
}
