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

	mapset "github.com/deckarep/golang-set"
	intf "github.com/nestybox/sysbox-mgr/intf"
	"github.com/nestybox/sysbox-runc/libcontainer/user"
	"github.com/sirupsen/logrus"
)

const (
	allocBlkSize uint32 = 65536 // min uid(gid) allocation range
)

// subidAlloc class (implements the UidAllocator interface)
type subidAlloc struct {
	idRange user.SubID
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

	sub := &subidAlloc{}

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
func (sub *subidAlloc) Alloc(id string, size uint64) (uint32, uint32, error) {
	subid := sub.idRange
	logrus.Debugf("Alloc(%s, %v) = %v, %v", id, size, subid, subid)
	return uint32(subid.SubID), uint32(subid.SubID), nil
}

// Implements intf.SubidAlloc.Free
func (sub *subidAlloc) Free(id string) error {
	logrus.Debugf("Free(%v)", id)
	return nil
}
