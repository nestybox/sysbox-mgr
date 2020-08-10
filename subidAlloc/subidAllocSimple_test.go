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

	subuidCfg := strings.NewReader(`testUser:0:655360`)
	subgidCfg := strings.NewReader(`testUser:0:655360`)

	subidAlloc, err := New("testUser", subuidCfg, subgidCfg)
	if err != nil {
		t.Errorf("failed to create allocator: %v", err)
		return
	}

	var tests = []allocTest{
		// id, size, wantUid, wantGid, wantErr
		{"1", 65536, 0, 0, ""},
		{"2", 65536, 0, 0, ""},
		{"3", 65536, 0, 0, ""},
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

	subuidCfg := strings.NewReader(`testUser:0:65536
                                   testUser:524288:65536`)

	subgidCfg := strings.NewReader(`testUser:0:65536
                                   testUser:524288:65536`)

	subidAlloc, err := New("testUser", subuidCfg, subgidCfg)
	if err != nil {
		t.Errorf("failed to create allocator: %v", err)
		return
	}

	var tests = []allocTest{
		// id, size, wantUid, wantGid, wantErr
		{"1", 65536, 0, 0, ""},
		{"2", 65536, 0, 0, ""},
		{"3", 65536, 0, 0, ""},
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

	subidAlloc, err := New("testUser", subuidCfg, subgidCfg)
	if err != nil {
		t.Errorf("failed to create allocator: %v", err)
	}

	var tests = []allocTest{
		// id, size, wantUid, wantGid, wantErr
		{"1", 65536, 0, 0, ""},
		{"1", 65536, 0, 0, ""},
	}

	testAlloc(t, subidAlloc, tests)

	subuidCfg = strings.NewReader(`testUser:0:65536
                                  testUser:524288:65536`)

	subgidCfg = strings.NewReader(`testUser:65536:65536
                                  testUser:231072:65536`)

	subidAlloc, err = New("testUser", subuidCfg, subgidCfg)
	if err == nil {
		t.Errorf("subidAlloc() passed; expected failure")
	}
}
