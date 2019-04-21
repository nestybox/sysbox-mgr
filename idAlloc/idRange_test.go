package idAlloc

import (
	"testing"
)

func TestSortIDRanges(t *testing.T) {
	ranges := []idRange{{10, 5}, {20, 15}, {0, 10}, {90, 10}, {50, 5}}
	sorted := sortIDRanges(ranges)

	var prevStart uint32
	for _, r := range sorted {
		if r.start < prevStart {
			t.Errorf("sortAllocMapRanges failed: %v", sorted)
		}
		prevStart = r.start
	}
}

func TestCompIDRanges(t *testing.T) {
	a := []idRange{{10, 5}, {20, 15}, {0, 10}, {90, 10}, {50, 5}}
	b := []idRange{{10, 5}, {20, 15}, {0, 10}, {90, 10}, {50, 5}}

	if !compIDRanges(a, b) {
		t.Errorf("compIDRanges failed on id range slice: %v", a)
	}
}

func TestGetRangesWithin(t *testing.T) {
	ranges := []idRange{{0, 10}, {10, 5}, {20, 15}, {50, 5}, {90, 10}}

	var tests = []struct {
		start, size uint32
		want        []idRange
	}{
		{0, 10, []idRange{{0, 10}}},
		{10, 10, []idRange{{10, 5}}},
		{16, 4, []idRange{}},
		{55, 35, []idRange{}},
		{0, 20, []idRange{{0, 10}, {10, 5}}},
		{1, 20, []idRange{{0, 10}, {10, 5}, {20, 15}}},
		{0, 35, []idRange{{0, 10}, {10, 5}, {20, 15}}},
		{10, 0, []idRange{}},
		{8, 4, []idRange{{0, 10}, {10, 5}}},
	}

	for _, test := range tests {
		got := getRangesWithin(test.start, test.size, ranges)
		if !compIDRanges(got, test.want) {
			t.Errorf("getRangesWithin failed; got = %v; want %v", got, test.want)
		}
	}
}

func TestFindUnusedRange(t *testing.T) {
	ranges := []idRange{{0, 10}, {10, 5}, {20, 15}, {50, 5}, {90, 10}}

	var tests = []struct {
		rstart, rsize uint32
		size          uint32
		want          idRange
	}{
		{0, 100, 5, idRange{15, 5}},
		{0, 100, 10, idRange{35, 15}},
		{0, 100, 35, idRange{55, 35}},
		{0, 100, 1, idRange{15, 5}},
		{0, 100, 0, idRange{15, 5}},
		{0, 100, 36, idRange{0, 0}},
		{0, 15, 1, idRange{0, 0}},
		{0, 100, 101, idRange{0, 0}},
	}

	for _, test := range tests {
		got := findUnusedRange(test.rstart, test.rsize, test.size, ranges)
		if got != test.want {
			t.Errorf("findUnusedRange failed; got = %v; want %v", got, test.want)
		}
	}
}

func TestFindUnusedRangeEmpty(t *testing.T) {
	ranges := []idRange{}

	var tests = []struct {
		rstart, rsize uint32
		size          uint32
		want          idRange
	}{
		{0, 100, 101, idRange{0, 0}},
	}

	for _, test := range tests {
		got := findUnusedRange(test.rstart, test.rsize, test.size, ranges)
		if got != test.want {
			t.Errorf("findUnusedRange failed; got = %v; want %v", got, test.want)
		}
	}
}
