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

// sysbox-mgr: sub user-id and sub group-id allocator
//
// The subidAlloc class allocates portions of the subuid and subgid ranges associated
// with a given user. It implements the intf.SubidAlloc interface.
//
// An subid object is created with New(), allocations are performed with Alloc(), and
// freeing is performed with Free().

package subidAlloc

import (
	"fmt"
	"io"
	"sort"
	"sync"

	mapset "github.com/deckarep/golang-set"
	"github.com/nestybox/sysbox-libs/formatter"
	intf "github.com/nestybox/sysbox-mgr/intf"
	"github.com/nestybox/sysbox-runc/libcontainer/user"
	"github.com/sirupsen/logrus"
)

const (
	allocBlkSize uint32 = 65536 // min uid(gid) allocation range
)

// subidAlloc class (implements the UidAllocator interface)
type subidAlloc struct {
	mu          sync.Mutex
	idRange     user.SubID
	allocations map[string]uint32 // container ID -> block index
	freeBlocks  []uint32          // recycled block indices
	nextBlock   uint32            // next unallocated block index
	maxBlocks   uint32            // total blocks available in range
}

// New creates an subidAlloc object
//
// userName is the Linux user whose subid/gid ranges will be used
// subuidSrc and subgidSrc contain the subid/gid ranges for the system
func New(userName string, subuidSrc, subgidSrc io.Reader) (intf.SubidAlloc, error) {

	filter := func(entry user.SubID) bool {
		return entry.Name == userName
	}

	// read subuid range(s) for userName
	uidRanges, err := user.ParseSubIDFilter(subuidSrc, filter)
	if err != nil {
		return nil, err
	}

	if len(uidRanges) == 0 {
		return nil, fmt.Errorf("could not find subuid info for user %s", userName)
	}

	// read subgid range(s) for userName
	gidRanges, err := user.ParseSubIDFilter(subgidSrc, filter)
	if err != nil {
		return nil, err
	}

	if len(gidRanges) == 0 {
		return nil, fmt.Errorf("could not find subgid info for user %s", userName)
	}

	// we need at least one common subuid and subgid range
	commonRanges := getCommonRanges(uidRanges, gidRanges)
	if len(commonRanges) == 0 {
		return nil, fmt.Errorf("could not find matching subuid and subgids range for user %s", userName)
	}

	sub := &subidAlloc{
		allocations: make(map[string]uint32),
	}

	// find a common range that is large enough for the allocation size
	foundRange := false
	for _, subid := range commonRanges {
		if subid.Count >= int64(allocBlkSize) {
			foundRange = true
			sub.idRange = subid
			break
		}
	}

	if !foundRange {
		return nil, fmt.Errorf("did not find a large enough subuid range for user %s (need %v)", userName, allocBlkSize)
	}

	sub.maxBlocks = uint32(sub.idRange.Count / int64(allocBlkSize))

	return sub, nil
}

func getCommonRanges(uidRanges, gidRanges []user.SubID) []user.SubID {

	uidRangeSet := mapset.NewSet()
	for _, uidRange := range uidRanges {
		uidRangeSet.Add(uidRange)
	}

	gidRangeSet := mapset.NewSet()
	for _, gidRange := range gidRanges {
		gidRangeSet.Add(gidRange)
	}

	commonSet := uidRangeSet.Intersect(gidRangeSet)

	common := []user.SubID{}
	for elem := range commonSet.Iter() {
		subid := elem.(user.SubID)
		common = append(common, subid)
	}

	// this ordering makes multi-range allocations more predictable, which helps in
	// testing.
	sort.Slice(common, func(i, j int) bool {
		return common[i].SubID < common[j].SubID
	})

	return common
}

// Implements intf.SubidAlloc.Alloc
//
// Each call with a new container ID allocates an exclusive 65536-uid/gid block
// from the subordinate range. Repeated calls with the same ID return the same block.
func (sub *subidAlloc) Alloc(id string, size uint64) (uint32, uint32, error) {
	sub.mu.Lock()
	defer sub.mu.Unlock()

	// Return existing allocation for this container
	if blockIdx, ok := sub.allocations[id]; ok {
		uid := uint32(sub.idRange.SubID) + blockIdx*allocBlkSize
		logrus.Debugf("Alloc(%s, %v) = %v (existing block %d)",
			formatter.ContainerID{id}, size, uid, blockIdx)
		return uid, uid, nil
	}

	// Allocate a new block: prefer recycled, then fresh
	var blockIdx uint32
	if n := len(sub.freeBlocks); n > 0 {
		blockIdx = sub.freeBlocks[n-1]
		sub.freeBlocks = sub.freeBlocks[:n-1]
	} else if sub.nextBlock < sub.maxBlocks {
		blockIdx = sub.nextBlock
		sub.nextBlock++
	} else {
		return 0, 0, fmt.Errorf("exhausted: no more subid blocks available (max %d containers)", sub.maxBlocks)
	}

	sub.allocations[id] = blockIdx
	uid := uint32(sub.idRange.SubID) + blockIdx*allocBlkSize

	logrus.Debugf("Alloc(%s, %v) = %v (block %d)",
		formatter.ContainerID{id}, size, uid, blockIdx)
	return uid, uid, nil
}

// Implements intf.SubidAlloc.Free
//
// Releases the block allocated for the given container, making it available for reuse.
func (sub *subidAlloc) Free(id string) error {
	sub.mu.Lock()
	defer sub.mu.Unlock()

	blockIdx, ok := sub.allocations[id]
	if !ok {
		return fmt.Errorf("not-found: container %s has no allocation", id)
	}

	delete(sub.allocations, id)
	sub.freeBlocks = append(sub.freeBlocks, blockIdx)

	logrus.Debugf("Free(%v) released block %d", formatter.ContainerID{id}, blockIdx)
	return nil
}
