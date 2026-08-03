package internal

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	db "github.com/anchore/grype/grype/db/v6"
)

// rhelMinorHandle builds an affected-package handle that is identical to its siblings in
// name, ecosystem, and version constraint, differing ONLY by the OS minor version -- exactly
// the shape the RHEL per-minor stream-affinity expansion emits.
func rhelMinorHandle(pkgName, constraint, minor string) db.AffectedPackageHandle {
	return db.AffectedPackageHandle{
		OperatingSystem: &db.OperatingSystem{
			Name:         "redhat",
			ReleaseID:    "rhel",
			MajorVersion: "9",
			MinorVersion: minor,
		},
		Package: &db.Package{Name: pkgName, Ecosystem: "rpm"},
		BlobValue: &db.PackageBlob{
			Ranges: []db.Range{{Version: db.Version{Type: "rpm", Constraint: constraint}}},
		},
	}
}

// TestByAffectedPackage_DeterministicOSMinorTiebreaker guards the tie-breaker that makes the
// built database reproducible. The RHEL per-minor expansion produces many rows sharing an
// identical name/ecosystem/constraint that differ only by OS minor. Without the OS tie-breaker
// in comparePackageHandles those rows compare equal, so the unstable sort.Sort emits them in a
// run-to-run-varying order and the DB is non-deterministic. With it, the ordering is a strict
// total order and every input permutation sorts to the same sequence.
func TestByAffectedPackage_DeterministicOSMinorTiebreaker(t *testing.T) {
	const (
		pkgName    = "kernel"
		constraint = "< 0:5.14.0-362.8.1.el9_3"
	)
	// major-only ("") plus minors 0..11 -- the full expanded set for one package+constraint.
	minors := []string{"", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11"}

	build := func(order []int) []db.AffectedPackageHandle {
		out := make([]db.AffectedPackageHandle, 0, len(order))
		for _, idx := range order {
			out = append(out, rhelMinorHandle(pkgName, constraint, minors[idx]))
		}
		return out
	}

	identity := make([]int, len(minors))
	for i := range identity {
		identity[i] = i
	}
	reversed := make([]int, len(identity))
	for i := range identity {
		reversed[i] = identity[len(identity)-1-i]
	}
	rotated := func(shift int) []int {
		out := make([]int, len(identity))
		for i := range identity {
			out[i] = identity[(i+shift)%len(identity)]
		}
		return out
	}

	permutations := [][]int{
		append([]int(nil), identity...),
		reversed,
		rotated(1),
		rotated(4),
		rotated(9),
		{5, 0, 12, 3, 9, 1, 7, 11, 2, 8, 4, 10, 6}, // fixed pseudo-shuffle (all 13 indices, once each)
	}

	var want []string
	for pi, perm := range permutations {
		h := build(perm)
		sort.Sort(ByAffectedPackage(h))

		got := make([]string, len(h))
		for i := range h {
			got[i] = h[i].OperatingSystem.MinorVersion
		}

		if pi == 0 {
			want = got
			// the comparator must be a STRICT total order over these rows: after sorting, each
			// adjacent pair is ordered in exactly one direction (never equal-both-ways, which is
			// what a missing tie-breaker would produce).
			s := ByAffectedPackage(h)
			for i := 0; i+1 < len(h); i++ {
				assert.Truef(t, s.Less(i, i+1) != s.Less(i+1, i),
					"rows %d (%q) and %d (%q) are not strictly ordered -- tie-breaker missing",
					i, got[i], i+1, got[i+1])
			}
			continue
		}
		assert.Equalf(t, want, got, "permutation %d sorted to a different order -- sort is non-deterministic", pi)
	}
	require.Len(t, want, len(minors))
}

// TestByAffectedPackage_TiebreakerFieldsCovered asserts the tie-breaker distinguishes rows that
// differ in each OS identity field, not just the minor -- so channel-scoped (EUS) and same-minor
// rows also order deterministically.
func TestByAffectedPackage_TiebreakerFieldsCovered(t *testing.T) {
	base := &db.OperatingSystem{Name: "redhat", ReleaseID: "rhel", MajorVersion: "9", MinorVersion: "4"}

	variants := map[string]func(os *db.OperatingSystem){
		"minor":   func(os *db.OperatingSystem) { os.MinorVersion = "5" },
		"channel": func(os *db.OperatingSystem) { os.Channel = "eus" },
		"label":   func(os *db.OperatingSystem) { os.LabelVersion = "unstable" },
		"major":   func(os *db.OperatingSystem) { os.MajorVersion = "10" },
	}

	for name, mutate := range variants {
		t.Run(name, func(t *testing.T) {
			other := *base
			mutate(&other)
			k1 := operatingSystemSortKey(base)
			k2 := operatingSystemSortKey(&other)
			assert.NotEqualf(t, k1, k2, "sort key must differ when %s differs", name)
		})
	}

	// nil OS is handled without panic and sorts before any populated OS.
	assert.Equal(t, "", operatingSystemSortKey(nil))
}
