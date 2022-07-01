//
// Copyright 2019-2020 Nestybox, Inc.
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

package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/opencontainers/runc/libcontainer/user"
	"golang.org/x/sys/unix"
)

func compareSubidRanges(t *testing.T, want, got []user.SubID) {
	if len(got) != len(want) {
		t.Errorf("AllocSubidRange(): want %v, got %v", want, got)
	}
	for i, _ := range want {
		if got[i] != want[i] {
			t.Errorf("AllocSubidRange(): want %v, got %v", want, got)
		}
	}
}

func TestAllocSubidRange(t *testing.T) {

	var subID, got, want []user.SubID
	var min uint64 = 100000
	var max uint64 = 600100000
	var err error

	// at end of range
	subID = []user.SubID{
		{"user1", 100000, 65536},
		{"user2", 165536, 65536},
	}
	got, err = allocSubidRange(subID, 65536, min, max)
	if err != nil {
		t.Errorf("AllocSubidRange(): %v", err)
	}
	want = append(subID, user.SubID{"sysbox", 231072, 65536})
	compareSubidRanges(t, want, got)

	// at beginning of range
	subID = []user.SubID{
		{"user2", 165536, 65536},
	}
	got, err = allocSubidRange(subID, 65536, min, max)
	if err != nil {
		t.Errorf("AllocSubidRange(): %v", err)
	}
	want = append(subID, user.SubID{"sysbox", 100000, 65536})
	compareSubidRanges(t, want, got)

	// in middle of range
	subID = []user.SubID{
		{"user1", 100000, 65536},
		{"user2", 231072, 65536},
	}
	got, err = allocSubidRange(subID, 65536, min, max)
	if err != nil {
		t.Errorf("AllocSubidRange(): %v", err)
	}
	want = append(subID, user.SubID{"sysbox", 165536, 65536})
	compareSubidRanges(t, want, got)

	// with overlapping ranges
	subID = []user.SubID{
		{"user1", 100000, 65536},
		{"user2", 100000, 65536},
		{"user3", 165536, 65536},
	}
	got, err = allocSubidRange(subID, 65536, min, max)
	if err != nil {
		t.Errorf("AllocSubidRange(): %v", err)
	}
	want = append(subID, user.SubID{"sysbox", 231072, 65536})
	compareSubidRanges(t, want, got)

	// more overlapping ranges
	subID = []user.SubID{
		{"user1", 100000, 65536},
		{"user2", 120000, 65536},
		{"user3", 165536, 65536},
	}
	got, err = allocSubidRange(subID, 65536, min, max)
	if err != nil {
		t.Errorf("AllocSubidRange(): %v", err)
	}
	want = append(subID, user.SubID{"sysbox", 231072, 65536})
	compareSubidRanges(t, want, got)

	// empty range
	subID = []user.SubID{}
	got, err = allocSubidRange(subID, 65536, min, max)
	if err != nil {
		t.Errorf("AllocSubidRange(): %v", err)
	}
	want = append(subID, user.SubID{"sysbox", 100000, 65536})
	compareSubidRanges(t, want, got)

	// not enought ids
	max = 165536
	subID = []user.SubID{
		{"user1", 100000, 65536},
	}
	got, err = allocSubidRange(subID, 65536, min, max)
	if err == nil {
		t.Errorf("AllocSubidRange(): expected alloc error, got no error")
	}

	max = 165536
	subID = []user.SubID{
		{"user1", 100000, 4096},
	}
	got, err = allocSubidRange(subID, 65536, min, max)
	if err == nil {
		t.Errorf("AllocSubidRange(): expected alloc error, got no error")
	}

	// off-by-one tests
	max = 165536
	subID = []user.SubID{
		{"user1", 100000, 65536},
	}
	got, err = allocSubidRange(subID, 1, min, max)
	if err == nil {
		t.Errorf("AllocSubidRange(): expected alloc error, got no error")
	}

	subID = []user.SubID{
		{"user1", 100000, 65535},
	}
	got, err = allocSubidRange(subID, 1, min, max)
	if err != nil {
		t.Errorf("AllocSubidRange(): %v", err)
	}
	want = append(subID, user.SubID{"sysbox", 165535, 1})
	compareSubidRanges(t, want, got)

	// invalid min/max/size
	min = 100000
	max = 100000
	subID = []user.SubID{}
	got, err = allocSubidRange(subID, 1, min, max)
	if err == nil {
		t.Errorf("AllocSubidRange(): expected alloc error, got no error")
	}

	subID = []user.SubID{}
	got, err = allocSubidRange(subID, 0, min, max)
	if err == nil {
		t.Errorf("AllocSubidRange(): expected alloc error, got no error")
	}

	// un-sorted ranges
	subID = []user.SubID{
		{"user1", 100000, 65536},
		{"user2", 231072, 65536},
		{"user3", 165536, 65536},
		{"user4", 362144, 65536},
	}
	got, err = allocSubidRange(subID, 65536, min, max)
	if err != nil {
		t.Errorf("AllocSubidRange(): %v", err)
	}
	want = append(subID, user.SubID{"sysbox", 296608, 65536})
	compareSubidRanges(t, want, got)
}

func verifyFileData(path string, data []byte) error {

	fileData, err := ioutil.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read file %s: %v", path, err)
	}

	if bytes.Compare(fileData, data) != 0 {
		return fmt.Errorf("file data mismatch: want %s, got %s", string(data), string(fileData))
	}

	return nil
}

func testConfigSubidRangeHelper(subidFilePre, subidFilePost string, size, min, max uint64) error {

	f, err := ioutil.TempFile("", "testConfigSubidRange*")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %v", err)
	}
	defer os.RemoveAll(f.Name())

	if err := ioutil.WriteFile(f.Name(), []byte(subidFilePre), 0644); err != nil {
		return fmt.Errorf("failed to write file %s: %v", f.Name(), err)
	}

	if err := configSubidRange(f.Name(), size, min, max); err != nil {
		return fmt.Errorf("configSubidRange(): error = %s", err)
	}

	verifyFileData(f.Name(), []byte(subidFilePost))

	return nil
}

func TestConfigSubidRange(t *testing.T) {

	var subidFilePre, subidFilePost string

	// at end of range
	subidFilePre = `user1:100000:65536
user2:165536:65536`
	subidFilePost = `user1:100000:65536
user2:165536:65536
sysbox:231072:268435456
`
	if err := testConfigSubidRangeHelper(subidFilePre, subidFilePost, 268435456, 100000, 600100000); err != nil {
		t.Errorf(err.Error())
	}

	// at beginning of range
	subidFilePre = `user2:165536:65536`
	subidFilePost = `sysbox:100000:65536
user2:165536:65536`

	if err := testConfigSubidRangeHelper(subidFilePre, subidFilePost, 65536, 100000, 600100000); err != nil {
		t.Errorf(err.Error())
	}

	// in the middle of range
	subidFilePre = `user1:100000:65536
user2:231072:65536`
	subidFilePost = `user1:100000:65536
sysbox:165536:65536
user2:231072:65536`

	if err := testConfigSubidRangeHelper(subidFilePre, subidFilePost, 65536, 100000, 600100000); err != nil {
		t.Errorf(err.Error())
	}

	// not enought ids
	subidFilePre = `user1:100000:65536`
	if err := testConfigSubidRangeHelper(subidFilePre, subidFilePost, 600034465, 100000, 600100000); err == nil {
		t.Errorf("configSubidRange(): expected alloc error, got no error")
	}

	// do not disturb existing sysbox entry
	subidFilePre = `user1:100000:65536
sysbox:231072,65536
user3:296608:65536`

	subidFilePost = subidFilePre

	if err := testConfigSubidRangeHelper(subidFilePre, subidFilePost, 65536, 100000, 600100000); err != nil {
		t.Errorf(err.Error())
	}

	// replace redundant sysbox entries with one entry
	subidFilePre = `user1:100000:65536
sysbox:231072,65536
user3:165536:65536
sysbox:362144,65536`

	subidFilePost = `user1:100000:65536
user3:165536:65536
sysbox:231072,65536`

	if err := testConfigSubidRangeHelper(subidFilePre, subidFilePost, 65536, 100000, 600100000); err != nil {
		t.Errorf(err.Error())
	}
}

func testGetSubidLimitsHelper(fileData string, want []uint64) error {

	f, err := ioutil.TempFile("", "testGetSubidLimits*")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %v", err)
	}

	if err := ioutil.WriteFile(f.Name(), []byte(fileData), 0644); err != nil {
		return fmt.Errorf("failed to write file %s: %v", f.Name(), err)
	}

	limits, err := getSubidLimits(f.Name())
	if err != nil {
		return fmt.Errorf("getSubidLimits(): error = %s", err)
	}

	if len(limits) != 4 {
		return fmt.Errorf("getSubidLimits(): limits length incorrect: want 4, got %d", len(limits))
	}

	for i := 0; i < 4; i++ {
		if limits[i] != want[i] {
			return fmt.Errorf("getSubidLimits(): failed: got %v, want %v", limits, want)
		}
	}

	if err := os.Remove(f.Name()); err != nil {
		return fmt.Errorf("failed to remove file %s", f.Name())
	}

	return nil
}

func TestGetSubidLimits(t *testing.T) {

	// fake login.defs data
	fileData := `# some comments
some data
SUB_UID_MIN    100000
some data
SUB_UID_MAX\t 600100000
some data
SUB_GID_MIN 100000
some data
SUB_GID_MAX\t\t 2147483648
# some more comments`

	want := []uint64{100000, 600100000, 100000, 2147483648}
	if err := testGetSubidLimitsHelper(fileData, want); err != nil {
		t.Errorf(err.Error())
	}

	// login.defs file without uid(gid) limits
	fileData = `# some comments
some data
# some more comments`

	want = []uint64{100000, 4294967295, 100000, 4294967295}
	if err := testGetSubidLimitsHelper(fileData, want); err != nil {
		t.Errorf(err.Error())
	}
}

func TestGetLibModMounts(t *testing.T) {

	var utsname unix.Utsname
	if err := unix.Uname(&utsname); err != nil {
		t.Errorf("cfgLibModMount: uname failed: %v", err)
	}

	n := bytes.IndexByte(utsname.Release[:], 0)
	path := filepath.Join("/lib/modules/", string(utsname.Release[:n]))
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return // skip test
	}

	mounts, err := getLibModMounts()
	if err != nil {
		t.Errorf("cfgLibModMount: returned error: %v", err)
	}
	m := mounts[0]
	if (m.Destination != path) || (m.Source != path) || (m.Type != "bind") {
		t.Errorf("cfgLibModMount: failed basic mount test")
	}
}
