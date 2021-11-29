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

// Unit tests for idShiftUtils package

package idShiftUtils

import (
	"io/ioutil"
	"os"
	"testing"

	aclLib "github.com/joshlf/go-acl"
)

func TestShiftAclIds(t *testing.T) {

	testDir, err := ioutil.TempDir("", "shiftAclTest")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(testDir)

	// Access ACL to be set on testDir
	aclUserEntry := aclLib.Entry{
		Tag:       aclLib.TagUser,
		Qualifier: "1001",
		Perms:     7,
	}

	aclGroupEntry := aclLib.Entry{
		Tag:       aclLib.TagGroup,
		Qualifier: "1005",
		Perms:     4,
	}

	aclMaskEntry := aclLib.Entry{
		Tag:   aclLib.TagMask,
		Perms: 7,
	}

	// Default ACL to be set on testDir
	aclDef := aclLib.ACL{
		aclLib.Entry{
			Tag:   aclLib.TagUserObj,
			Perms: 7,
		},
		aclLib.Entry{
			Tag:   aclLib.TagGroupObj,
			Perms: 0,
		},
		aclLib.Entry{
			Tag:   aclLib.TagOther,
			Perms: 0,
		},
		aclLib.Entry{
			Tag:       aclLib.TagUser,
			Qualifier: "1002",
			Perms:     5,
		},
		aclLib.Entry{
			Tag:       aclLib.TagGroup,
			Qualifier: "1005",
			Perms:     4,
		},
		aclLib.Entry{
			Tag:   aclLib.TagMask,
			Perms: 7,
		},
	}

	acl, err := aclLib.Get(testDir)
	if err != nil {
		t.Fatalf("failed to get ACL on %s: %s", testDir, err)
	}

	acl = append(acl, aclUserEntry, aclGroupEntry, aclMaskEntry)

	if err := aclLib.Set(testDir, acl); err != nil {
		t.Fatalf("failed to set ACL %v on %s: %s", acl, testDir, err)
	}

	if err := aclLib.SetDefault(testDir, aclDef); err != nil {
		t.Fatalf("failed to set default ACL %v on %s: %s", aclDef, testDir, err)
	}

	// ShiftAcls by subtracting offset

	uidOffset := int32(-1000)
	gidOffset := int32(-1000)

	if err := shiftAclIds(testDir, true, uidOffset, gidOffset); err != nil {
		t.Fatalf("shiftAclIds() failed: %s", err)
	}

	// Verify the ACL for the dir were modified as expected
	newAcl := aclLib.ACL{}
	newDefAcl := aclLib.ACL{}

	newAcl, err = aclLib.Get(testDir)
	if err != nil {
		t.Fatalf("failed to get ACL on %s: %s", testDir, err)
	}

	newDefAcl, err = aclLib.GetDefault(testDir)
	if err != nil {
		t.Fatalf("failed to get default ACL on %s: %s", testDir, err)
	}

	wantAclUserEntry := aclLib.Entry{
		Tag:       aclLib.TagUser,
		Qualifier: "1", // 1001 - 1000
		Perms:     7,
	}

	wantAclGroupEntry := aclLib.Entry{
		Tag:       aclLib.TagGroup,
		Qualifier: "5", // 1005 - 1000
		Perms:     4,
	}

	wantAclDefUserEntry := aclLib.Entry{
		Tag:       aclLib.TagUser,
		Qualifier: "2", // 1002 - 1000
		Perms:     5,
	}

	wantAclDefGroupEntry := aclLib.Entry{
		Tag:       aclLib.TagGroup,
		Qualifier: "5", // 1005 - 1000
		Perms:     4,
	}

	for _, e := range newAcl {
		if e.Tag == aclLib.TagUser {
			if e != wantAclUserEntry {
				t.Logf("acl mismatch: want %v, got %v", wantAclUserEntry, e)
			}
		}
		if e.Tag == aclLib.TagGroup {
			if e != wantAclGroupEntry {
				t.Logf("acl mismatch: want %v, got %v", wantAclGroupEntry, e)
			}
		}
	}

	for _, e := range newDefAcl {
		if e.Tag == aclLib.TagUser {
			if e != wantAclDefUserEntry {
				t.Logf("acl mismatch: want %v, got %v", wantAclDefUserEntry, e)
			}
		}
		if e.Tag == aclLib.TagGroup {
			if e != wantAclDefGroupEntry {
				t.Logf("acl mismatch: want %v, got %v", wantAclDefGroupEntry, e)
			}
		}
	}

	// ShiftAcls by adding offset (revert back to original value)

	uidOffset = int32(1000)
	gidOffset = int32(1000)

	if err := shiftAclIds(testDir, true, uidOffset, gidOffset); err != nil {
		t.Fatalf("shiftAclIds() failed: %s", err)
	}

	newAcl, err = aclLib.Get(testDir)
	if err != nil {
		t.Fatalf("failed to get ACL on %s: %s", testDir, err)
	}

	newDefAcl, err = aclLib.GetDefault(testDir)
	if err != nil {
		t.Fatalf("failed to get default ACL on %s: %s", testDir, err)
	}

	wantAclUserEntry = aclUserEntry
	wantAclGroupEntry = aclGroupEntry

	wantAclDefUserEntry = aclLib.Entry{
		Tag:       aclLib.TagUser,
		Qualifier: "1002",
		Perms:     5,
	}

	wantAclDefGroupEntry = aclLib.Entry{
		Tag:       aclLib.TagGroup,
		Qualifier: "1005",
		Perms:     4,
	}

	for _, e := range newAcl {
		if e.Tag == aclLib.TagUser {
			if e != wantAclUserEntry {
				t.Logf("acl mismatch: want %v, got %v", wantAclUserEntry, e)
			}
		}
		if e.Tag == aclLib.TagGroup {
			if e != wantAclGroupEntry {
				t.Logf("acl mismatch: want %v, got %v", wantAclGroupEntry, e)
			}
		}
	}

	for _, e := range newDefAcl {
		if e.Tag == aclLib.TagUser {
			if e != wantAclDefUserEntry {
				t.Logf("acl mismatch: want %v, got %v", wantAclDefUserEntry, e)
			}
		}
		if e.Tag == aclLib.TagGroup {
			if e != wantAclDefGroupEntry {
				t.Logf("acl mismatch: want %v, got %v", wantAclDefGroupEntry, e)
			}
		}
	}

}
