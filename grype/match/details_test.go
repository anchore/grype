package match

import (
	"fmt"
	"math"
	"slices"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDetails_Sorting(t *testing.T) {

	detailExactDirectHigh := Detail{
		Type:       ExactDirectMatch,
		Confidence: 0.9,
		SearchedBy: "attribute1",
		Found:      "value1",
		Matcher:    "matcher1",
	}
	detailExactDirectLow := Detail{
		Type:       ExactDirectMatch,
		Confidence: 0.5,
		SearchedBy: "attribute1",
		Found:      "value1",
		Matcher:    "matcher1",
	}
	detailExactIndirect := Detail{
		Type:       ExactIndirectMatch,
		Confidence: 0.7,
		SearchedBy: "attribute2",
		Found:      "value2",
		Matcher:    "matcher2",
	}
	detailCPEMatch := Detail{
		Type:       CPEMatch,
		Confidence: 0.8,
		SearchedBy: "attribute3",
		Found:      "value3",
		Matcher:    "matcher3",
	}

	tests := []struct {
		name     string
		details  Details
		expected Details
	}{
		{
			name: "sorts by type first, then by confidence",
			details: Details{
				detailCPEMatch,
				detailExactDirectHigh,
				detailExactIndirect,
				detailExactDirectLow,
			},
			expected: Details{
				detailExactDirectHigh,
				detailExactDirectLow,
				detailExactIndirect,
				detailCPEMatch,
			},
		},
		{
			name: "sorts by confidence within the same type",
			details: Details{
				detailExactDirectLow,
				detailExactDirectHigh,
			},
			expected: Details{
				detailExactDirectHigh,
				detailExactDirectLow,
			},
		},
		{
			name: "sorts by ID when type and confidence are the same",
			details: Details{
				// clone of detailExactDirectLow with slight difference to enforce ID sorting
				{
					Type:       ExactDirectMatch,
					Confidence: 0.5,
					SearchedBy: "attribute2",
					Found:      "value2",
					Matcher:    "matcher2",
				},
				detailExactDirectLow,
			},
			expected: Details{
				detailExactDirectLow,
				{
					Type:       ExactDirectMatch,
					Confidence: 0.5,
					SearchedBy: "attribute2",
					Found:      "value2",
					Matcher:    "matcher2",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sort.Sort(tt.details)
			require.Equal(t, tt.expected, tt.details)
		})
	}
}

// TestDetails_rank covers the ranking Match.Merge uses to decide which of two records for the
// same finding describes it -- the successor to the direct-supersedes-indirect rules that used to
// live in Matches.Add.
func TestDetails_rank(t *testing.T) {
	tests := []struct {
		name     string
		details  Details
		expected int
	}{
		{
			name:     "direct is the strongest",
			details:  Details{{Type: ExactDirectMatch}},
			expected: 1,
		},
		{
			name:     "indirect ranks below direct",
			details:  Details{{Type: ExactIndirectMatch}},
			expected: 2,
		},
		{
			name:     "CPE ranks below indirect",
			details:  Details{{Type: CPEMatch}},
			expected: 3,
		},
		{
			name:     "the strongest detail in the set wins",
			details:  Details{{Type: CPEMatch}, {Type: ExactDirectMatch}, {Type: ExactIndirectMatch}},
			expected: 1,
		},
		{
			name:     "unrecognized types do not contribute",
			details:  Details{{Type: "made-up"}, {Type: CPEMatch}},
			expected: 3,
		},
		{
			name:     "no recognized type ranks last",
			details:  Details{{Type: "made-up"}},
			expected: math.MaxInt,
		},
		{
			name:     "no details rank last",
			details:  Details{},
			expected: math.MaxInt,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.details.rank())
		})
	}
}

// TestMergeDetails covers the guarantee that a match never carries the same detail twice: exact
// duplicates are dropped both across the sets being merged and within each one.
func TestMergeDetails(t *testing.T) {
	direct := Detail{Type: ExactDirectMatch, SearchedBy: "attr1", Found: "value1", Matcher: "matcher1"}
	cpe := Detail{Type: CPEMatch, SearchedBy: "attr2", Found: "value2", Matcher: "matcher2"}
	otherCPE := Detail{Type: CPEMatch, SearchedBy: "attr3", Found: "value2", Matcher: "matcher2"}

	tests := []struct {
		name     string
		sets     []Details
		expected Details
	}{
		{
			name:     "duplicates within a single set",
			sets:     []Details{{cpe, cpe}},
			expected: Details{cpe},
		},
		{
			name:     "duplicates across sets",
			sets:     []Details{{cpe}, {cpe}},
			expected: Details{cpe},
		},
		{
			name:     "duplicates on both sides",
			sets:     []Details{{cpe, cpe}, {cpe, cpe}},
			expected: Details{cpe},
		},
		{
			name: "details that differ are all kept, sorted strongest first",
			sets: []Details{{cpe, otherCPE}, {direct, cpe}},
			// direct sorts ahead of the CPE details
			expected: Details{direct, cpe, otherCPE},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mergeDetails(tt.sets...)
			assert.Equal(t, tt.expected[0], got[0], "strongest detail should sort first")
			assert.ElementsMatch(t, tt.expected, got)
		})
	}
}

// TestMergeDetails_foldsCPEDetailsByRecord covers folding the details of several of a package's CPEs
// that found one database record into a single detail listing every CPE that found it.
func TestMergeDetails_foldsCPEDetailsByRecord(t *testing.T) {
	pkgParam := PackageParameter{Name: "widget", Version: "1.5.0"}

	searchedByFirst := CPEParameters{
		Namespace: "nvd:cpe",
		CPEs:      []string{"cpe:2.3:a:acme:widget:1.5.0:*:*:*:*:*:*:*"},
		Package:   pkgParam,
	}
	searchedBySecond := CPEParameters{
		Namespace: "nvd:cpe",
		CPEs:      []string{"cpe:2.3:a:acme:widget:1.5.0:*:*:*:*:rails:*:*"},
		Package:   pkgParam,
	}
	searchedByBoth := CPEParameters{
		Namespace: "nvd:cpe",
		CPEs: []string{
			// sorted, as CPEParameters.Merge leaves them
			"cpe:2.3:a:acme:widget:1.5.0:*:*:*:*:*:*:*",
			"cpe:2.3:a:acme:widget:1.5.0:*:*:*:*:rails:*:*",
		},
		Package: pkgParam,
	}

	record := CPEResult{
		VulnerabilityID:   "CVE-2026-1",
		VersionConstraint: ">= 1.0.0, < 2.0.0 (unknown)",
		CPEs:              []string{"cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*"},
	}
	// the same CVE as a second DB record, with its own constraint
	otherRecord := CPEResult{
		VulnerabilityID:   "CVE-2026-1",
		VersionConstraint: "<= 1.5.0 (unknown)",
		CPEs:              []string{"cpe:2.3:a:acme:widget:*:*:*:*:*:embedded-mod:*:*"},
	}

	detail := func(searchedBy CPEParameters, found CPEResult) Detail {
		return Detail{
			Type:       CPEMatch,
			Matcher:    "java-matcher",
			Confidence: 0.9,
			SearchedBy: searchedBy,
			Found:      found,
		}
	}

	tests := []struct {
		name     string
		sets     []Details
		expected Details
	}{
		{
			name:     "same record via two package CPEs folds into one detail",
			sets:     []Details{{detail(searchedByFirst, record)}, {detail(searchedBySecond, record)}},
			expected: Details{detail(searchedByBoth, record)},
		},
		{
			name:     "folding does not depend on merge order",
			sets:     []Details{{detail(searchedBySecond, record)}, {detail(searchedByFirst, record)}},
			expected: Details{detail(searchedByBoth, record)},
		},
		{
			name:     "two CPEs of one package finding it in a single set fold too",
			sets:     []Details{{detail(searchedByFirst, record), detail(searchedBySecond, record)}},
			expected: Details{detail(searchedByBoth, record)},
		},
		{
			name: "details that found different records are kept apart",
			sets: []Details{{detail(searchedByFirst, record)}, {detail(searchedBySecond, otherRecord)}},
			expected: Details{
				detail(searchedByFirst, record),
				detail(searchedBySecond, otherRecord),
			},
		},
		{
			name: "a namespace mismatch is kept apart",
			sets: func() []Details {
				otherNamespace := searchedBySecond
				otherNamespace.Namespace = "other:cpe"
				return []Details{{detail(searchedByFirst, record)}, {detail(otherNamespace, record)}}
			}(),
			expected: Details{
				detail(searchedByFirst, record),
				detail(func() CPEParameters { c := searchedBySecond; c.Namespace = "other:cpe"; return c }(), record),
			},
		},
		{
			name: "the same record searched for a different package is kept apart",
			sets: func() []Details {
				upstream := searchedBySecond
				upstream.Package = PackageParameter{Name: "widget-upstream", Version: "1.5.0"}
				return []Details{{detail(searchedByFirst, record)}, {detail(upstream, record)}}
			}(),
			expected: Details{
				detail(searchedByFirst, record),
				detail(func() CPEParameters {
					c := searchedBySecond
					c.Package = PackageParameter{Name: "widget-upstream", Version: "1.5.0"}
					return c
				}(), record),
			},
		},
		{
			name: "details from different matchers are kept apart",
			sets: func() []Details {
				d := detail(searchedBySecond, record)
				d.Matcher = "stock-matcher"
				return []Details{{detail(searchedByFirst, record)}, {d}}
			}(),
			expected: Details{
				detail(searchedByFirst, record),
				func() Detail { d := detail(searchedBySecond, record); d.Matcher = "stock-matcher"; return d }(),
			},
		},
		{
			name: "details that are not CPE details are kept, never dropped",
			sets: []Details{
				{detail(searchedByFirst, record)},
				{{Type: ExactDirectMatch, Matcher: "java-matcher", SearchedBy: "attr", Found: "value"}},
			},
			expected: Details{
				{Type: ExactDirectMatch, Matcher: "java-matcher", SearchedBy: "attr", Found: "value"},
				detail(searchedByFirst, record),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mergeDetails(tt.sets...)
			assert.Len(t, got, len(tt.expected))
			assert.ElementsMatch(t, tt.expected, got)
		})
	}
}

// TestMergeDetails_keepsDetailsThatCannotBeHashed pins that identity is the field-by-field comparison
// and not a hash, so details that cannot be hashed are not all treated as the same detail.
func TestMergeDetails_keepsDetailsThatCannotBeHashed(t *testing.T) {
	// a func field is enough to make hashstructure fail
	unhashable := Detail{Type: CPEMatch, Matcher: "java-matcher", SearchedBy: "first", Found: func() {}}
	otherUnhashable := Detail{Type: CPEMatch, Matcher: "java-matcher", SearchedBy: "second", Found: func() {}}
	require.Empty(t, unhashable.ID(), "expected this detail to be unhashable")
	require.Empty(t, otherUnhashable.ID(), "expected this detail to be unhashable")

	got := mergeDetails(Details{unhashable}, Details{otherUnhashable})
	assert.Len(t, got, 2, "details that cannot be hashed must not collapse into one")

	// the same detail merged twice is still one piece of evidence, hashable or not
	got = mergeDetails(Details{unhashable}, Details{unhashable})
	assert.Len(t, got, 1, "the same detail merged twice is one detail")

	// a hashable detail dedups as always
	plain := Detail{Type: CPEMatch, Matcher: "java-matcher", SearchedBy: "attr", Found: "value"}
	assert.Len(t, mergeDetails(Details{plain}, Details{plain}), 1)
}

// TestMergeDetails_orderMatchesDetailsLess guards mergeDetails and Details.Less against ordering
// details differently.
func TestMergeDetails_orderMatchesDetailsLess(t *testing.T) {
	details := Details{
		{Type: CPEMatch, Matcher: "java-matcher", SearchedBy: "a", Found: "1", Confidence: 0.9},
		{Type: ExactDirectMatch, Matcher: "java-matcher", SearchedBy: "b", Found: "2", Confidence: 1},
		{Type: CPEMatch, Matcher: "stock-matcher", SearchedBy: "c", Found: "3", Confidence: 0.9},
		{Type: ExactIndirectMatch, Matcher: "dpkg-matcher", SearchedBy: "d", Found: "4", Confidence: 1},
		{Type: CPEMatch, Matcher: "java-matcher", SearchedBy: "e", Found: "5", Confidence: 0.5},
	}

	viaLess := append(Details(nil), details...)
	sort.Sort(viaLess)

	assert.Equal(t, viaLess, mergeDetails(details))

	// and independent of the order they arrive in
	reversed := append(Details(nil), details...)
	slices.Reverse(reversed)
	assert.Equal(t, viaLess, mergeDetails(reversed))
}

// TestCompareDetails_isATotalOrder pins that the comparison is antisymmetric and separates any two
// details that are not the same evidence.
func TestCompareDetails_isATotalOrder(t *testing.T) {
	details := Details{
		{Type: ExactDirectMatch, Matcher: ApkMatcher, Confidence: 1,
			SearchedBy: DistroParameters{Namespace: "alpine:distro:alpine:3.20", Distro: DistroIdentification{Type: "alpine", Version: "3.20"}, Package: PackageParameter{Name: "openssl", Version: "1.0"}},
			Found:      DistroResult{VulnerabilityID: "CVE-1", VersionConstraint: "< 1.2.3"}},
		// same as above but a different distro version -- must not collapse into it
		{Type: ExactDirectMatch, Matcher: ApkMatcher, Confidence: 1,
			SearchedBy: DistroParameters{Namespace: "alpine:distro:alpine:3.20", Distro: DistroIdentification{Type: "alpine", Version: "3.21"}, Package: PackageParameter{Name: "openssl", Version: "1.0"}},
			Found:      DistroResult{VulnerabilityID: "CVE-1", VersionConstraint: "< 1.2.3"}},
		{Type: ExactIndirectMatch, Matcher: ApkMatcher, Confidence: 1,
			SearchedBy: DistroParameters{Namespace: "alpine:distro:alpine:3.20", Distro: DistroIdentification{Type: "alpine", Version: "3.20"}, Package: PackageParameter{Name: "openssl", Version: "1.0"}},
			Found:      DistroResult{VulnerabilityID: "CVE-1", VersionConstraint: "< 1.2.3"}},
		{Type: CPEMatch, Matcher: JavaMatcher, Confidence: 0.9,
			SearchedBy: CPEParameters{Namespace: "nvd:cpe", CPEs: []string{"cpe:2.3:a:o:openssl:1.0:*:*:*:*:*:*:*"}, Package: PackageParameter{Name: "openssl", Version: "1.0"}},
			Found:      CPEResult{VulnerabilityID: "CVE-1", VersionConstraint: "< 2.0", CPEs: []string{"cpe:2.3:a:o:openssl:*:*:*:*:*:*:*:*"}}},
		// differs from the CPE detail above only in the constraint of the record found
		{Type: CPEMatch, Matcher: JavaMatcher, Confidence: 0.9,
			SearchedBy: CPEParameters{Namespace: "nvd:cpe", CPEs: []string{"cpe:2.3:a:o:openssl:1.0:*:*:*:*:*:*:*"}, Package: PackageParameter{Name: "openssl", Version: "1.0"}},
			Found:      CPEResult{VulnerabilityID: "CVE-1", VersionConstraint: "< 3.0", CPEs: []string{"cpe:2.3:a:o:openssl:*:*:*:*:*:*:*:*"}}},
		// differs from the first distro detail only in the vulnerability found
		{Type: ExactDirectMatch, Matcher: ApkMatcher, Confidence: 1,
			SearchedBy: DistroParameters{Namespace: "alpine:distro:alpine:3.20", Distro: DistroIdentification{Type: "alpine", Version: "3.20"}, Package: PackageParameter{Name: "openssl", Version: "1.0"}},
			Found:      DistroResult{VulnerabilityID: "CVE-2", VersionConstraint: "< 1.2.3"}},
		{Type: ExactDirectMatch, Matcher: GoModuleMatcher, Confidence: 1,
			SearchedBy: EcosystemParameters{Language: "go", Namespace: "github:language:go", Package: PackageParameter{Name: "golang.org/x/net", Version: "0.1.0"}},
			Found:      EcosystemResult{VulnerabilityID: "GHSA-1", VersionConstraint: "< 0.2.0", MatchedSymbols: []string{"html.Parse"}}},
		// differs from the ecosystem detail above only in the symbols matched
		{Type: ExactDirectMatch, Matcher: GoModuleMatcher, Confidence: 1,
			SearchedBy: EcosystemParameters{Language: "go", Namespace: "github:language:go", Package: PackageParameter{Name: "golang.org/x/net", Version: "0.1.0"}},
			Found:      EcosystemResult{VulnerabilityID: "GHSA-1", VersionConstraint: "< 0.2.0", MatchedSymbols: []string{"html.Render"}}},
		// an unrecognized match type and a payload type this package knows nothing about
		{Type: "some-future-type", Matcher: "some-future-matcher", SearchedBy: "a", Found: 1},
		{Type: "some-future-type", Matcher: "some-future-matcher", SearchedBy: "b", Found: 1},
	}

	for i := range details {
		for j := range details {
			a, b := details[i], details[j]
			forward, reverse := compareDetails(a, b), compareDetails(b, a)

			require.Equal(t, -reverse, forward, "comparison is not antisymmetric for details %d and %d", i, j)

			if i == j {
				require.Zero(t, forward, "a detail must compare equal to itself (index %d)", i)
				continue
			}
			require.NotZero(t, forward, "distinct details %d and %d compare equal, so one would be dropped as a duplicate", i, j)
		}
	}

	// nothing in the set duplicates or folds into anything else, so merging keeps all of it
	assert.Len(t, mergeDetails(details), len(details))
}

// benchmarkCPEDetail builds a distinct CPE detail per index: one package CPE found one database
// record, with a constraint of its own so that nothing folds and the merged set keeps every detail.
func benchmarkCPEDetail(i int) Detail {
	return Detail{
		Type:       CPEMatch,
		Matcher:    JavaMatcher,
		Confidence: 0.9,
		SearchedBy: CPEParameters{
			Namespace: "nvd:cpe",
			CPEs:      []string{fmt.Sprintf("cpe:2.3:a:acme:widget%d:1.5.0:*:*:*:*:*:*:*", i)},
			Package:   PackageParameter{Name: "widget", Version: "1.5.0"},
		},
		Found: CPEResult{
			VulnerabilityID:   "CVE-2026-1",
			VersionConstraint: fmt.Sprintf(">= 1.0.0, < %d.0.0 (unknown)", i+2),
			CPEs: []string{
				"cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*",
				"cpe:2.3:a:acme:widget-core:*:*:*:*:*:*:*:*",
			},
		},
	}
}

// BenchmarkMergeDetails tracks the cost of normalizing a finding's details, which Matches.Add pays
// once per record contributing to the finding.
func BenchmarkMergeDetails(b *testing.B) {
	for _, n := range []int{2, 10, 50} {
		set := make(Details, 0, n)
		for i := 0; i < n; i++ {
			set = append(set, benchmarkCPEDetail(i))
		}
		b.Run(fmt.Sprintf("details=%d", n), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_ = mergeDetails(set)
			}
		})
	}
}
