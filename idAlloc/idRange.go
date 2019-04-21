package idAlloc

import (
	"sort"
)

// idRange represents a uid range
type idRange struct{ start, size uint32 }

func (r *idRange) contains(val uint32) bool {
	return r.start <= val && val < (r.start+r.size)
}

// idRangesByStart is a slice of idRanges which supports sorting by range start
type idRangesByStart []idRange

func (s idRangesByStart) Len() int {
	return len(s)
}

func (s idRangesByStart) Less(i, j int) bool {
	return s[i].start < s[j].start
}

func (s idRangesByStart) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

// sortIDRanges sorts the given idRange slice from smallest to largest range, by range 'start'
func sortIDRanges(ranges []idRange) []idRange {
	sort.Sort(idRangesByStart(ranges))
	return ranges
}

// compIDRanges compares the given id range slices
func compIDRanges(a, b []idRange) bool {
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

// getRangesWithin takes a sorted slice of idRanges and returns a subset slice whose
// id ranges are between (rstart, rstart+rsize] (including ranges that overlap with
// the boundaries)
func getRangesWithin(rstart, rsize uint32, idRanges []idRange) []idRange {
	var foundStart bool

	if len(idRanges) == 0 {
		return []idRange{}
	}

	startIdx := 0
	endIdx := 0

	rend := rstart + rsize

	for i, idRange := range idRanges {
		if idRange.contains(rstart) || (idRange.start >= rstart && idRange.start < rend) {
			startIdx = i
			foundStart = true
			break
		}
	}

	if foundStart {
		for i, idRange := range idRanges[startIdx:] {
			idRangeEnd := idRange.start + idRange.size
			if idRange.contains(rend-1) || idRangeEnd <= rend {
				endIdx = i + 1
			}
			if idRange.start >= rend {
				break
			}
		}
	}

	endIdx += startIdx
	return idRanges[startIdx:endIdx]
}

// findUnusedRange finds the first unused range of size >= 'size', between 'rstart' and
// 'rstart+rsize'. Slice 'used' contains ranges that are currently in-use; it's
// assumed to be sorted by range start. If a suitable range is not found, an empty
// idRange ({0,0}) is returned.
func findUnusedRange(rstart, rsize, size uint32, used []idRange) idRange {

	if size > rsize {
		return idRange{0, 0}
	}

	if len(used) == 0 {
		return idRange{rstart, rsize}
	}

	usedInRange := getRangesWithin(rstart, rsize, used)
	if len(usedInRange) == 0 {
		return idRange{rstart, rsize}
	}

	start := rstart
	for _, u := range usedInRange {
		if start < u.start {
			gap := idRange{start, u.start - start}
			if gap.size >= size {
				return gap
			}
		}
		start = u.start + u.size
	}

	// There may be a gap between the last used range and rstart+rsize
	end := rstart + rsize
	if start < end {
		gap := idRange{start, end - start}
		if gap.size >= size {
			return gap
		}
	}

	return idRange{0, 0}
}
