package match

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/cpe"
)

func TestMatch_Merge(t *testing.T) {
	tests := []struct {
		name        string
		m1          Match
		m2          Match
		expectedErr error
		expected    Match
	}{
		{
			name: "error on fingerprint mismatch",
			m1: Match{
				Vulnerability: vulnerability.Vulnerability{
					Reference: vulnerability.Reference{
						ID:        "CVE-2023-0001",
						Namespace: "namespace1",
					},
				},
				Package: pkg.Package{
					ID: "pkg1",
				},
			},
			m2: Match{
				Vulnerability: vulnerability.Vulnerability{
					Reference: vulnerability.Reference{
						ID:        "CVE-2023-0002",
						Namespace: "namespace2",
					},
				},
				Package: pkg.Package{
					ID: "pkg2",
				},
			},
			expectedErr: ErrCannotMerge,
		},
		{
			name: "merge with unique values",
			m1: Match{
				Vulnerability: vulnerability.Vulnerability{
					Reference: vulnerability.Reference{
						ID:        "CVE-2023-0001",
						Namespace: "namespace",
					},
					RelatedVulnerabilities: []vulnerability.Reference{
						{
							Namespace: "ns1",
							ID:        "ID1",
						},
					},
					CPEs: []cpe.CPE{
						cpe.Must("cpe:2.3:a:example:example:1.0:*:*:*:*:*:*:*", cpe.DeclaredSource),
					},
				},
				Package: pkg.Package{
					ID: "pkg1",
				},
				Details: Details{
					{
						Type:       ExactDirectMatch,
						SearchedBy: "attr1",
						Found:      "value1",
						Matcher:    "matcher1",
					},
				},
			},
			m2: Match{
				Vulnerability: vulnerability.Vulnerability{
					Reference: vulnerability.Reference{
						ID:        "CVE-2023-0001",
						Namespace: "namespace",
					},
					RelatedVulnerabilities: []vulnerability.Reference{
						{
							Namespace: "ns2",
							ID:        "ID2",
						},
					},
					CPEs: []cpe.CPE{
						cpe.Must("cpe:2.3:a:example:example:1.1:*:*:*:*:*:*:*", cpe.DeclaredSource),
					},
				},
				Package: pkg.Package{
					ID: "pkg1",
				},
				Details: Details{
					{
						Type:       ExactIndirectMatch,
						SearchedBy: "attr2",
						Found:      "value2",
						Matcher:    "matcher2",
					},
				},
			},
			expectedErr: nil,
			expected: Match{
				Vulnerability: vulnerability.Vulnerability{
					Reference: vulnerability.Reference{
						ID:        "CVE-2023-0001",
						Namespace: "namespace",
					},
					RelatedVulnerabilities: []vulnerability.Reference{
						{
							Namespace: "ns1",
							ID:        "ID1",
						},
						{
							Namespace: "ns2",
							ID:        "ID2",
						},
					},
					CPEs: []cpe.CPE{
						cpe.Must("cpe:2.3:a:example:example:1.0:*:*:*:*:*:*:*", cpe.DeclaredSource),
						cpe.Must("cpe:2.3:a:example:example:1.1:*:*:*:*:*:*:*", cpe.DeclaredSource),
					},
				},
				Package: pkg.Package{
					ID: "pkg1",
				},
				Details: Details{
					{
						Type:       ExactDirectMatch,
						SearchedBy: "attr1",
						Found:      "value1",
						Matcher:    "matcher1",
					},
					{
						Type:       ExactIndirectMatch,
						SearchedBy: "attr2",
						Found:      "value2",
						Matcher:    "matcher2",
					},
				},
			},
		},
		{
			name: "merges with duplicate values",
			m1: Match{
				Vulnerability: vulnerability.Vulnerability{
					Reference: vulnerability.Reference{
						ID:        "CVE-2023-0001",
						Namespace: "namespace",
					},
					RelatedVulnerabilities: []vulnerability.Reference{
						{
							Namespace: "ns1",
							ID:        "ID1",
						},
					},
					CPEs: []cpe.CPE{
						cpe.Must("cpe:2.3:a:example:example:1.0:*:*:*:*:*:*:*", cpe.DeclaredSource),
					},
				},
				Package: pkg.Package{
					ID: "pkg1",
				},
				Details: Details{
					{
						Type:       ExactDirectMatch,
						SearchedBy: "attr1",
						Found:      "value1",
						Matcher:    "matcher1",
					},
				},
			},
			m2: Match{
				Vulnerability: vulnerability.Vulnerability{
					Reference: vulnerability.Reference{
						ID:        "CVE-2023-0001",
						Namespace: "namespace",
					},
					RelatedVulnerabilities: []vulnerability.Reference{
						{
							Namespace: "ns1",
							ID:        "ID1",
						},
					},
					CPEs: []cpe.CPE{
						cpe.Must("cpe:2.3:a:example:example:1.0:*:*:*:*:*:*:*", cpe.DeclaredSource),
					},
				},
				Package: pkg.Package{
					ID: "pkg1",
				},
				Details: Details{
					{
						Type:       ExactDirectMatch,
						SearchedBy: "attr1",
						Found:      "value1",
						Matcher:    "matcher1",
					},
				},
			},
			expectedErr: nil,
			expected: Match{
				Vulnerability: vulnerability.Vulnerability{
					Reference: vulnerability.Reference{
						ID:        "CVE-2023-0001",
						Namespace: "namespace",
					},
					RelatedVulnerabilities: []vulnerability.Reference{
						{
							Namespace: "ns1",
							ID:        "ID1",
						},
					},
					CPEs: []cpe.CPE{
						cpe.Must("cpe:2.3:a:example:example:1.0:*:*:*:*:*:*:*", cpe.DeclaredSource),
					},
				},
				Package: pkg.Package{
					ID: "pkg1",
				},
				Details: Details{
					{
						Type:       ExactDirectMatch,
						SearchedBy: "attr1",
						Found:      "value1",
						Matcher:    "matcher1",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.m1.Merge(tt.m2)
			if tt.expectedErr != nil {
				require.ErrorIs(t, err, tt.expectedErr)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.expected.Vulnerability.RelatedVulnerabilities, tt.m1.Vulnerability.RelatedVulnerabilities)
				require.Equal(t, tt.expected.Details, tt.m1.Details)
				require.Equal(t, tt.expected.Vulnerability.CPEs, tt.m1.Vulnerability.CPEs)
			}
		})
	}
}

// TestMergeReferences_UncomparableInternal guards the reason mergeReferences projects onto
// referenceKey rather than keying on vulnerability.Reference itself: Reference.Internal is an `any`,
// and providers do put uncomparable values in it. Using Reference as a map key would compile fine
// and panic at runtime ("hash of unhashable type") the first time one showed up.
func TestMergeReferences_UncomparableInternal(t *testing.T) {
	withSlice := vulnerability.Reference{
		ID:        "CVE-2023-0001",
		Namespace: "nvd:cpe",
		Internal:  []string{"uncomparable"},
	}
	withMap := vulnerability.Reference{
		ID:        "CVE-2023-0002",
		Namespace: "nvd:cpe",
		Internal:  map[string]string{"also": "uncomparable"},
	}

	require.NotPanics(t, func() {
		got := mergeReferences([]vulnerability.Reference{withSlice}, []vulnerability.Reference{withMap, withSlice})

		// deduped on (id, namespace), ignoring Internal, and sorted
		require.Len(t, got, 2)
		assert.Equal(t, "CVE-2023-0001", got[0].ID)
		assert.Equal(t, "CVE-2023-0002", got[1].ID)
	})
}

// TestMergeAdvisories covers dedup and ordering for the set keyed directly on the (comparable)
// vulnerability.Advisory value.
func TestMergeAdvisories(t *testing.T) {
	a := vulnerability.Advisory{ID: "RHSA-2024:9371", Link: "https://example.com/a"}
	b := vulnerability.Advisory{ID: "RHSA-2024:6163", Link: "https://example.com/b"}
	// same ID, different link -- a distinct advisory, so both are kept
	aPrime := vulnerability.Advisory{ID: "RHSA-2024:9371", Link: "https://example.com/other"}

	got := mergeAdvisories([]vulnerability.Advisory{a, b}, []vulnerability.Advisory{a, aPrime})

	// sorted by ID, then Link
	assert.Equal(t, []vulnerability.Advisory{b, a, aPrime}, got)
}

// TestMergeFix_AvailableDedup covers the set keyed directly on the (comparable)
// vulnerability.FixAvailable value, including its time.Time field.
func TestMergeFix_AvailableDedup(t *testing.T) {
	when := time.Date(2024, 5, 1, 0, 0, 0, 0, time.UTC)
	later := time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)

	base := vulnerability.Fix{
		Versions:  []string{"2.0.0", "1.0.0"},
		State:     vulnerability.FixStateFixed,
		Available: []vulnerability.FixAvailable{{Version: "1.0.0", Kind: "rpm", Date: when}},
	}
	other := vulnerability.Fix{
		Versions: []string{"1.0.0", "3.0.0"},
		Available: []vulnerability.FixAvailable{
			{Version: "1.0.0", Kind: "rpm", Date: when},  // exact duplicate, dropped
			{Version: "1.0.0", Kind: "rpm", Date: later}, // same version+kind, different date: kept
		},
	}

	got := mergeFix(base, other)

	assert.Equal(t, []string{"1.0.0", "2.0.0", "3.0.0"}, got.Versions, "versions should be sorted and deduped")
	assert.Equal(t, vulnerability.FixStateFixed, got.State)
	assert.Equal(t, []vulnerability.FixAvailable{
		{Version: "1.0.0", Kind: "rpm", Date: when},
		{Version: "1.0.0", Kind: "rpm", Date: later},
	}, got.Available)
}

// TestMergeFix_StateResolution pins the whole fix-state table of mergeFix.
func TestMergeFix_StateResolution(t *testing.T) {
	var (
		none     vulnerability.FixState // a record that states nothing at all
		unknown  = vulnerability.FixStateUnknown
		notFixed = vulnerability.FixStateNotFixed
		wontFix  = vulnerability.FixStateWontFix
		fixed    = vulnerability.FixStateFixed
	)

	// rows are the base record's state, cells the merged state for each of the other record's states
	others := []vulnerability.FixState{none, unknown, notFixed, wontFix, fixed}
	expected := map[vulnerability.FixState][]vulnerability.FixState{
		//         other:  none      unknown   not-fixed  wont-fix  fixed
		none:     {none, unknown, notFixed, wontFix, fixed},
		unknown:  {unknown, unknown, notFixed, wontFix, fixed},
		notFixed: {notFixed, notFixed, notFixed, notFixed, fixed},
		wontFix:  {wontFix, wontFix, notFixed, wontFix, fixed},
		fixed:    {fixed, fixed, fixed, fixed, fixed},
	}

	for _, base := range []vulnerability.FixState{none, unknown, notFixed, wontFix, fixed} {
		for i, other := range others {
			name := fmt.Sprintf("base=%q other=%q", base, other)
			t.Run(name, func(t *testing.T) {
				got := mergeFix(vulnerability.Fix{State: base}, vulnerability.Fix{State: other})
				assert.Equal(t, expected[base][i], got.State)
			})
		}
	}

	// the table must be symmetric: compareRecordAuthority can leave either record as the base when
	// they are equally authoritative, and for three or more records a direction-sensitive cell would
	// make the merged state depend on arrival order
	t.Run("is commutative", func(t *testing.T) {
		for _, a := range others {
			for _, b := range others {
				forward := mergeFix(vulnerability.Fix{State: a}, vulnerability.Fix{State: b}).State
				reverse := mergeFix(vulnerability.Fix{State: b}, vulnerability.Fix{State: a}).State
				assert.Equal(t, forward, reverse, "mergeFix(%q, %q) must not depend on direction", a, b)
			}
		}
	})

	// the pair the policy exists for, stated on its own so a change to it cannot pass unnoticed
	t.Run("wont-fix merged with fixed reports fixed, either direction", func(t *testing.T) {
		wontFixRecord := vulnerability.Fix{State: wontFix}
		fixedRecord := vulnerability.Fix{State: fixed, Versions: []string{"2.0.0"}}

		forward := mergeFix(wontFixRecord, fixedRecord)
		assert.Equal(t, fixed, forward.State)
		assert.Equal(t, []string{"2.0.0"}, forward.Versions)

		reverse := mergeFix(fixedRecord, wontFixRecord)
		assert.Equal(t, fixed, reverse.State)
		assert.Equal(t, []string{"2.0.0"}, reverse.Versions)
	})
}

// TestMatch_Merge_isOrderIndependent pins that two records for one finding reconcile to the same match
// whichever one was stored first.
func TestMatch_Merge_isOrderIndependent(t *testing.T) {
	p := pkg.Package{ID: "pkg-1", Name: "openssl", Version: "1.0"}
	record := func(packageName string, state vulnerability.FixState, constraint, searchedCPE string) Match {
		return Match{
			Package: p,
			Vulnerability: vulnerability.Vulnerability{
				Reference:   vulnerability.Reference{ID: "CVE-1", Namespace: "nvd:cpe"},
				PackageName: packageName,
				Fix:         vulnerability.Fix{State: state},
			},
			Details: Details{{
				Type: CPEMatch, Matcher: JavaMatcher, Confidence: 0.9,
				SearchedBy: CPEParameters{Namespace: "nvd:cpe", CPEs: []string{searchedCPE}, Package: PackageParameter{Name: "openssl", Version: "1.0"}},
				Found:      CPEResult{VulnerabilityID: "CVE-1", VersionConstraint: constraint, CPEs: []string{"cpe:2.3:a:o:openssl:*:*:*:*:*:*:*:*"}},
			}},
		}
	}

	// two NVD records for one CVE: same rank, disagreeing about the fix state
	a := record("openssl-a", vulnerability.FixStateWontFix, "< 2.0", "cpe:2.3:a:o:openssl:1.0:*:*:*:*:*:*:*")
	b := record("openssl-b", vulnerability.FixStateNotFixed, "< 3.0", "cpe:2.3:a:p:openssl:1.0:*:*:*:*:*:*:*")

	forward := a
	require.NoError(t, forward.Merge(b))

	reverse := b
	require.NoError(t, reverse.Merge(a))

	assert.Equal(t, forward.Vulnerability.PackageName, reverse.Vulnerability.PackageName, "the surviving record must not depend on merge direction")
	assert.Equal(t, forward.Vulnerability.Fix.State, reverse.Vulnerability.Fix.State, "the surviving fix state must not depend on merge direction")
	assert.Equal(t, forward.Details, reverse.Details, "the merged details must not depend on merge direction")

	// and the same through Matches.Add, which is how this is reached in practice
	first := NewMatches(a, b)
	second := NewMatches(b, a)
	assert.Equal(t, first.Sorted(), second.Sorted(), "Matches.Add must not depend on the order matches arrive in")
}

// TestMatch_Merge_isOrderIndependentForThreeRecords extends the two-record case above
// to three, which is where compareRecordAuthority stops holding its promise.
//
// compareDetailSets is slices.CompareFunc, so a shorter set that is a prefix of a longer
// one sorts first: a record carrying only the shared detail outranks a record carrying
// the shared detail plus one of its own. Merging then replaces the winner's details with
// the union of both, so the third comparison runs against a set that never existed as an
// input, and the relation is not associative.
//
// The surviving record supplies Metadata (severity/CVSS), PackageName, Status and the
// mergeFix base state, so which one wins is user-visible. Reached in practice whenever
// one fingerprint collects three or more records, e.g. two package CPEs against two NVD
// records on the apk upstream path.
func TestMatch_Merge_isOrderIndependentForThreeRecords(t *testing.T) {
	p := pkg.Package{ID: "pkg-1", Name: "openssl", Version: "1.0"}
	detail := func(searchedCPE string) Detail {
		return Detail{
			Type: CPEMatch, Matcher: JavaMatcher, Confidence: 0.9,
			SearchedBy: CPEParameters{Namespace: "nvd:cpe", CPEs: []string{searchedCPE}, Package: PackageParameter{Name: "openssl", Version: "1.0"}},
			Found:      CPEResult{VulnerabilityID: "CVE-1", VersionConstraint: "< 1.0.0"},
		}
	}
	record := func(packageName string, state vulnerability.FixState, details ...Detail) Match {
		return Match{
			Package: p,
			Vulnerability: vulnerability.Vulnerability{
				Reference:   vulnerability.Reference{ID: "CVE-1", Namespace: "nvd:cpe"},
				PackageName: packageName,
				Fix:         vulnerability.Fix{State: state},
			},
			Details: details,
		}
	}

	// every record was found through the same shared CPE; b and c were each also found
	// through a second one, so their detail sets are supersets of a's
	shared := detail("cpe:2.3:a:o:openssl:*:*:*:*:*:*:*:*")
	a := record("openssl-a", vulnerability.FixStateNotFixed, shared)
	b := record("openssl-b", vulnerability.FixStateWontFix, shared, detail("cpe:2.3:a:o:openssl:1:*:*:*:*:*:*:*"))
	c := record("openssl-c", vulnerability.FixStateNotFixed, shared, detail("cpe:2.3:a:o:openssl:2:*:*:*:*:*:*:*"))

	permutations := [][]Match{
		{a, b, c}, {a, c, b}, {b, a, c},
		{b, c, a}, {c, a, b}, {c, b, a},
	}

	var want Match
	for i, order := range permutations {
		collection := NewMatches(order...)
		got := collection.Sorted()
		require.Len(t, got, 1, "all three records share a fingerprint, so they must collapse to one match")

		if i == 0 {
			want = got[0]
			continue
		}
		assert.Equal(t, want.Vulnerability.PackageName, got[0].Vulnerability.PackageName, "the surviving record must not depend on the order matches arrive in")
		assert.Equal(t, want.Vulnerability.Fix.State, got[0].Vulnerability.Fix.State, "the surviving fix state must not depend on the order matches arrive in")
	}
}
