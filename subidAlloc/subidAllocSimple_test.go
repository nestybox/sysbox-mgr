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

	subuidCfg := strings.NewReader(`testUser:100000:655360`)
	subgidCfg := strings.NewReader(`testUser:100000:655360`)

	subidAlloc, err := New("testUser", subuidCfg, subgidCfg)
	if err != nil {
		t.Errorf("failed to create allocator: %v", err)
		return
	}

	var tests = []allocTest{
		// id, size, wantUid, wantGid, wantErr
		{"1", 65536, 100000, 100000, ""},
		{"2", 65536, 165536, 165536, ""},
		{"3", 65536, 231072, 231072, ""},
	}

	testAlloc(t, subidAlloc, tests)
}

func TestAllocInvalidUser(t *testing.T) {

	subuidCfg := strings.NewReader(`testUser:0:131072`)
	subgidCfg := strings.NewReader(`testUser:0:131072`)

	_, err := New("anotherUser", subuidCfg, subgidCfg)
	if err == nil {
		t.Errorf("idAlloc.New(): want error, got no error")
		return
	}
}

func TestAllocMultiRange(t *testing.T) {

	// Two common ranges; allocator picks the first one large enough (100000:196608 = 3 blocks)
	subuidCfg := strings.NewReader(`testUser:100000:196608
                                   testUser:524288:196608`)

	subgidCfg := strings.NewReader(`testUser:100000:196608
                                   testUser:524288:196608`)

	subidAlloc, err := New("testUser", subuidCfg, subgidCfg)
	if err != nil {
		t.Errorf("failed to create allocator: %v", err)
		return
	}

	var tests = []allocTest{
		// id, size, wantUid, wantGid, wantErr
		{"1", 65536, 100000, 100000, ""},
		{"2", 65536, 165536, 165536, ""},
		{"3", 65536, 231072, 231072, ""},
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

	subuidCfg := strings.NewReader(`testUser:100000:65536
                                   testUser:524288:65536`)

	subgidCfg := strings.NewReader(`testUser:165536:65536
		                             testUser:100000:65536`)

	subidAlloc, err := New("testUser", subuidCfg, subgidCfg)
	if err != nil {
		t.Errorf("failed to create allocator: %v", err)
	}

	// Same container ID twice -> returns the same exclusive block
	var tests = []allocTest{
		// id, size, wantUid, wantGid, wantErr
		{"1", 65536, 100000, 100000, ""},
		{"1", 65536, 100000, 100000, ""},
	}

	testAlloc(t, subidAlloc, tests)

	// No common ranges -> New() should fail
	subuidCfg = strings.NewReader(`testUser:100000:65536
                                  testUser:524288:65536`)

	subgidCfg = strings.NewReader(`testUser:165536:65536
                                  testUser:331072:65536`)

	subidAlloc, err = New("testUser", subuidCfg, subgidCfg)
	if err == nil {
		t.Errorf("subidAlloc() passed; expected failure")
	}
}

func TestAllocExhausted(t *testing.T) {

	// Range has room for exactly 2 blocks (2 * 65536 = 131072)
	subuidCfg := strings.NewReader(`testUser:100000:131072`)
	subgidCfg := strings.NewReader(`testUser:100000:131072`)

	subidAlloc, err := New("testUser", subuidCfg, subgidCfg)
	if err != nil {
		t.Errorf("failed to create allocator: %v", err)
		return
	}

	var tests = []allocTest{
		{"1", 65536, 100000, 100000, ""},
		{"2", 65536, 165536, 165536, ""},
		{"3", 65536, 0, 0, "exhausted: no more subid blocks available (max 2 containers)"},
	}

	testAlloc(t, subidAlloc, tests)
}

func TestAllocFreeReuse(t *testing.T) {

	subuidCfg := strings.NewReader(`testUser:100000:131072`)
	subgidCfg := strings.NewReader(`testUser:100000:131072`)

	alloc, err := New("testUser", subuidCfg, subgidCfg)
	if err != nil {
		t.Errorf("failed to create allocator: %v", err)
		return
	}

	// Allocate 2 containers (fills all blocks)
	uid1, _, err := alloc.Alloc("c1", 65536)
	if err != nil || uid1 != 100000 {
		t.Errorf("Alloc(c1) failed: got uid=%v, err=%v; want uid=100000", uid1, err)
	}

	uid2, _, err := alloc.Alloc("c2", 65536)
	if err != nil || uid2 != 165536 {
		t.Errorf("Alloc(c2) failed: got uid=%v, err=%v; want uid=165536", uid2, err)
	}

	// All blocks used; next alloc should fail
	_, _, err = alloc.Alloc("c3", 65536)
	if err == nil {
		t.Errorf("Alloc(c3) should have failed (exhausted)")
	}

	// Free c1 and allocate c3 -> should reuse c1's block
	if err := alloc.Free("c1"); err != nil {
		t.Errorf("Free(c1) failed: %v", err)
	}

	uid3, _, err := alloc.Alloc("c3", 65536)
	if err != nil || uid3 != 100000 {
		t.Errorf("Alloc(c3) after Free(c1) failed: got uid=%v, err=%v; want uid=100000 (reused block)", uid3, err)
	}

	// Free non-existent container should error
	if err := alloc.Free("nonexistent"); err == nil {
		t.Errorf("Free(nonexistent) should have failed")
	}
}
