package result

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/search"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/file"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

func TestSet_Remove(t *testing.T) {
	tests := []struct {
		name     string
		receiver Set
		incoming Set
		want     Set
	}{
		{
			name: "remove existing entries",
			receiver: Set{
				"vuln-1": []Result{
					{
						ID:              "vuln-1",
						Vulnerabilities: []vulnerability.Vulnerability{{Reference: vulnerability.Reference{ID: "CVE-2021-1"}}},
						Details:         match.Details{{Type: match.ExactDirectMatch}},
					},
				},
				"vuln-2": []Result{
					{
						ID:              "vuln-2",
						Vulnerabilities: []vulnerability.Vulnerability{{Reference: vulnerability.Reference{ID: "CVE-2021-2"}}},
						Details:         match.Details{{Type: match.ExactDirectMatch}},
					},
				},
			},
			incoming: Set{
				"vuln-1": []Result{
					{ID: "vuln-1"},
				},
			},
			want: Set{
				"vuln-2": []Result{
					{
						ID:              "vuln-2",
						Vulnerabilities: []vulnerability.Vulnerability{{Reference: vulnerability.Reference{ID: "CVE-2021-2"}}},
						Details:         match.Details{{Type: match.ExactDirectMatch}},
					},
				},
			},
		},
		{
			name: "remove non-existing entry has no effect",
			receiver: Set{
				"vuln-1": []Result{
					{
						ID:              "vuln-1",
						Vulnerabilities: []vulnerability.Vulnerability{{Reference: vulnerability.Reference{ID: "CVE-2021-1"}}},
						Details:         match.Details{{Type: match.ExactDirectMatch}},
					},
				},
			},
			incoming: Set{
				"vuln-2": []Result{
					{ID: "vuln-2"},
				},
			},
			want: Set{
				"vuln-1": []Result{
					{
						ID:              "vuln-1",
						Vulnerabilities: []vulnerability.Vulnerability{{Reference: vulnerability.Reference{ID: "CVE-2021-1"}}},
						Details:         match.Details{{Type: match.ExactDirectMatch}},
					},
				},
			},
		},
		{
			name:     "remove from empty set",
			receiver: Set{},
			incoming: Set{
				"vuln-1": []Result{
					{ID: "vuln-1"},
				},
			},
			want: Set{},
		},
		{
			name: "remove with empty incoming set",
			receiver: Set{
				"vuln-1": []Result{
					{
						ID:              "vuln-1",
						Vulnerabilities: []vulnerability.Vulnerability{{Reference: vulnerability.Reference{ID: "CVE-2021-1"}}},
						Details:         match.Details{{Type: match.ExactDirectMatch}},
					},
				},
			},
			incoming: Set{},
			want: Set{
				"vuln-1": []Result{
					{
						ID:              "vuln-1",
						Vulnerabilities: []vulnerability.Vulnerability{{Reference: vulnerability.Reference{ID: "CVE-2021-1"}}},
						Details:         match.Details{{Type: match.ExactDirectMatch}},
					},
				},
			},
		},
		{
			name: "remove entry with shared alias (comment example)",
			receiver: Set{
				"GHSA-g4mx-q9vg-27p4": []Result{
					{
						ID: "GHSA-g4mx-q9vg-27p4",
						Vulnerabilities: []vulnerability.Vulnerability{
							{
								Reference: vulnerability.Reference{ID: "GHSA-g4mx-q9vg-27p4"},
								RelatedVulnerabilities: []vulnerability.Reference{
									{ID: "CVE-2023-45803"},
								},
							},
						},
						Details: match.Details{{Type: match.ExactDirectMatch}},
					},
				},
			},
			incoming: Set{
				"CGA-7qjw-ggh3-pp9f": []Result{
					{
						ID: "CGA-7qjw-ggh3-pp9f",
						Vulnerabilities: []vulnerability.Vulnerability{
							{
								Reference: vulnerability.Reference{ID: "CGA-7qjw-ggh3-pp9f"},
								RelatedVulnerabilities: []vulnerability.Reference{
									{ID: "CVE-2023-45803"},
								},
							},
						},
						Details: match.Details{{Type: match.ExactDirectMatch}},
					},
				},
			},
			want: Set{}, // GHSA-g4mx-q9vg-27p4 should be removed due to shared CVE-2023-45803 alias
		},
		{
			name: "remove entry where receiver ID appears as alias in incoming",
			receiver: Set{
				"CVE-2023-45803": []Result{
					{
						ID: "CVE-2023-45803",
						Vulnerabilities: []vulnerability.Vulnerability{
							{Reference: vulnerability.Reference{ID: "CVE-2023-45803"}},
						},
						Details: match.Details{{Type: match.ExactDirectMatch}},
					},
				},
			},
			incoming: Set{
				"GHSA-main-id": []Result{
					{
						ID: "GHSA-main-id",
						Vulnerabilities: []vulnerability.Vulnerability{
							{
								Reference: vulnerability.Reference{ID: "GHSA-main-id"},
								RelatedVulnerabilities: []vulnerability.Reference{
									{ID: "CVE-2023-45803"},
								},
							},
						},
						Details: match.Details{{Type: match.ExactDirectMatch}},
					},
				},
			},
			want: Set{}, // CVE-2023-45803 should be removed because it appears as alias in incoming
		},
		{
			name: "multiple aliases with partial overlap",
			receiver: Set{
				"vuln-1": []Result{
					{
						ID: "vuln-1",
						Vulnerabilities: []vulnerability.Vulnerability{
							{
								Reference: vulnerability.Reference{ID: "vuln-1"},
								RelatedVulnerabilities: []vulnerability.Reference{
									{ID: "CVE-2021-1"},
									{ID: "CVE-2021-2"},
								},
							},
						},
						Details: match.Details{{Type: match.ExactDirectMatch}},
					},
				},
				"vuln-2": []Result{
					{
						ID: "vuln-2",
						Vulnerabilities: []vulnerability.Vulnerability{
							{
								Reference: vulnerability.Reference{ID: "vuln-2"},
								RelatedVulnerabilities: []vulnerability.Reference{
									{ID: "CVE-2021-3"},
								},
							},
						},
						Details: match.Details{{Type: match.ExactDirectMatch}},
					},
				},
			},
			incoming: Set{
				"incoming-vuln": []Result{
					{
						ID: "incoming-vuln",
						Vulnerabilities: []vulnerability.Vulnerability{
							{
								Reference: vulnerability.Reference{ID: "incoming-vuln"},
								RelatedVulnerabilities: []vulnerability.Reference{
									{ID: "CVE-2021-1"}, // overlaps with vuln-1
								},
							},
						},
						Details: match.Details{{Type: match.ExactDirectMatch}},
					},
				},
			},
			want: Set{
				"vuln-2": []Result{ // vuln-1 removed, vuln-2 preserved
					{
						ID: "vuln-2",
						Vulnerabilities: []vulnerability.Vulnerability{
							{
								Reference: vulnerability.Reference{ID: "vuln-2"},
								RelatedVulnerabilities: []vulnerability.Reference{
									{ID: "CVE-2021-3"},
								},
							},
						},
						Details: match.Details{{Type: match.ExactDirectMatch}},
					},
				},
			},
		},
		{
			name: "no aliases in vulnerabilities",
			receiver: Set{
				"vuln-1": []Result{
					{
						ID: "vuln-1",
						Vulnerabilities: []vulnerability.Vulnerability{
							{Reference: vulnerability.Reference{ID: "vuln-1"}},
						},
						Details: match.Details{{Type: match.ExactDirectMatch}},
					},
				},
			},
			incoming: Set{
				"vuln-2": []Result{
					{
						ID: "vuln-2",
						Vulnerabilities: []vulnerability.Vulnerability{
							{Reference: vulnerability.Reference{ID: "vuln-2"}},
						},
						Details: match.Details{{Type: match.ExactDirectMatch}},
					},
				},
			},
			want: Set{
				"vuln-1": []Result{
					{
						ID: "vuln-1",
						Vulnerabilities: []vulnerability.Vulnerability{
							{Reference: vulnerability.Reference{ID: "vuln-1"}},
						},
						Details: match.Details{{Type: match.ExactDirectMatch}},
					},
				},
			},
		},
		{
			name: "complex transitive relationship chain",
			receiver: Set{
				"A": []Result{
					{
						ID: "A",
						Vulnerabilities: []vulnerability.Vulnerability{
							{
								Reference: vulnerability.Reference{ID: "A"},
								RelatedVulnerabilities: []vulnerability.Reference{
									{ID: "CVE-1"},
								},
							},
						},
						Details: match.Details{{Type: match.ExactDirectMatch}},
					},
				},
				"B": []Result{
					{
						ID: "B",
						Vulnerabilities: []vulnerability.Vulnerability{
							{
								Reference: vulnerability.Reference{ID: "B"},
								RelatedVulnerabilities: []vulnerability.Reference{
									{ID: "CVE-2"},
								},
							},
						},
						Details: match.Details{{Type: match.ExactDirectMatch}},
					},
				},
			},
			incoming: Set{
				"C": []Result{
					{
						ID: "C",
						Vulnerabilities: []vulnerability.Vulnerability{
							{
								Reference: vulnerability.Reference{ID: "C"},
								RelatedVulnerabilities: []vulnerability.Reference{
									{ID: "CVE-1"}, // matches A's alias
									{ID: "CVE-3"},
								},
							},
						},
						Details: match.Details{{Type: match.ExactDirectMatch}},
					},
				},
			},
			want: Set{
				"B": []Result{ // A should be removed, B should remain
					{
						ID: "B",
						Vulnerabilities: []vulnerability.Vulnerability{
							{
								Reference: vulnerability.Reference{ID: "B"},
								RelatedVulnerabilities: []vulnerability.Reference{
									{ID: "CVE-2"},
								},
							},
						},
						Details: match.Details{{Type: match.ExactDirectMatch}},
					},
				},
			},
		},
		{
			name: "empty related vulnerabilities field",
			receiver: Set{
				"vuln-1": []Result{
					{
						ID: "vuln-1",
						Vulnerabilities: []vulnerability.Vulnerability{
							{
								Reference:              vulnerability.Reference{ID: "vuln-1"},
								RelatedVulnerabilities: []vulnerability.Reference{}, // empty
							},
						},
						Details: match.Details{{Type: match.ExactDirectMatch}},
					},
				},
			},
			incoming: Set{
				"vuln-2": []Result{
					{
						ID: "vuln-2",
						Vulnerabilities: []vulnerability.Vulnerability{
							{
								Reference: vulnerability.Reference{ID: "vuln-2"},
								RelatedVulnerabilities: []vulnerability.Reference{
									{ID: "some-cve"},
								},
							},
						},
						Details: match.Details{{Type: match.ExactDirectMatch}},
					},
				},
			},
			want: Set{
				"vuln-1": []Result{
					{
						ID: "vuln-1",
						Vulnerabilities: []vulnerability.Vulnerability{
							{
								Reference:              vulnerability.Reference{ID: "vuln-1"},
								RelatedVulnerabilities: []vulnerability.Reference{},
							},
						},
						Details: match.Details{{Type: match.ExactDirectMatch}},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.receiver.Remove(tt.incoming)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("Set.Remove() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestSet_Merge(t *testing.T) {
	tests := []struct {
		name       string
		receiver   Set
		incoming   Set
		mergeFuncs []func(existing, incoming []Result) []Result
		want       Set
	}{
		{
			name: "merge with default merge function",
			receiver: Set{
				"vuln-1": []Result{
					{
						ID:              "vuln-1",
						Vulnerabilities: []vulnerability.Vulnerability{{Reference: vulnerability.Reference{ID: "CVE-2021-1"}}},
						Details:         match.Details{{Type: match.ExactDirectMatch}},
					},
				},
			},
			incoming: Set{
				"vuln-1": []Result{
					{
						ID:              "vuln-1",
						Vulnerabilities: []vulnerability.Vulnerability{{Reference: vulnerability.Reference{ID: "CVE-2021-1-updated"}}},
						Details:         match.Details{{Type: match.ExactIndirectMatch}},
					},
				},
			},
			want: Set{
				"vuln-1": []Result{
					{
						ID:              "vuln-1",
						Vulnerabilities: []vulnerability.Vulnerability{{Reference: vulnerability.Reference{ID: "CVE-2021-1"}}},
						Details:         match.Details{{Type: match.ExactDirectMatch}},
					},
					{
						ID:              "vuln-1",
						Vulnerabilities: []vulnerability.Vulnerability{{Reference: vulnerability.Reference{ID: "CVE-2021-1-updated"}}},
						Details:         match.Details{{Type: match.ExactIndirectMatch}},
					},
				},
			},
		},
		{
			name: "merge new entry from incoming",
			receiver: Set{
				"vuln-1": []Result{
					{
						ID:              "vuln-1",
						Vulnerabilities: []vulnerability.Vulnerability{{Reference: vulnerability.Reference{ID: "CVE-2021-1"}}},
						Details:         match.Details{{Type: match.ExactDirectMatch}},
					},
				},
			},
			incoming: Set{
				"vuln-2": []Result{
					{
						ID:              "vuln-2",
						Vulnerabilities: []vulnerability.Vulnerability{{Reference: vulnerability.Reference{ID: "CVE-2021-2"}}},
						Details:         match.Details{{Type: match.ExactDirectMatch}},
					},
				},
			},
			want: Set{
				"vuln-1": []Result{
					{
						ID:              "vuln-1",
						Vulnerabilities: []vulnerability.Vulnerability{{Reference: vulnerability.Reference{ID: "CVE-2021-1"}}},
						Details:         match.Details{{Type: match.ExactDirectMatch}},
					},
				},
				"vuln-2": []Result{
					{
						ID:              "vuln-2",
						Vulnerabilities: []vulnerability.Vulnerability{{Reference: vulnerability.Reference{ID: "CVE-2021-2"}}},
						Details:         match.Details{{Type: match.ExactDirectMatch}},
					},
				},
			},
		},
		{
			name: "merge with custom merge function that filters out results",
			receiver: Set{
				"vuln-1": []Result{
					{
						ID:              "vuln-1",
						Vulnerabilities: []vulnerability.Vulnerability{{Reference: vulnerability.Reference{ID: "CVE-2021-1"}}},
						Details:         match.Details{{Type: match.ExactDirectMatch}},
					},
				},
			},
			incoming: Set{
				"vuln-1": []Result{
					{
						ID:              "vuln-1",
						Vulnerabilities: []vulnerability.Vulnerability{{Reference: vulnerability.Reference{ID: "CVE-2021-1-updated"}}},
						Details:         match.Details{{Type: match.ExactIndirectMatch}},
					},
				},
			},
			mergeFuncs: []func(existing, incoming []Result) []Result{
				func(existing, incoming []Result) []Result {
					// custom merge function that returns empty result to filter out
					return []Result{}
				},
			},
			want: Set{},
		},
		{
			name:     "merge empty sets",
			receiver: Set{},
			incoming: Set{},
			want:     Set{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.receiver.Merge(tt.incoming, tt.mergeFuncs...)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("Set.Merge() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestSet_ToMatches(t *testing.T) {
	testPkg := pkg.Package{
		Name:    "test-Package",
		Version: "1.0.0",
		Type:    syftPkg.DebPkg,
	}

	tests := []struct {
		name     string
		receiver Set
		want     []match.Match
	}{
		{
			name: "convert results to matches",
			receiver: Set{
				"vuln-1": []Result{
					{
						ID: "vuln-1",
						Vulnerabilities: []vulnerability.Vulnerability{
							{Reference: vulnerability.Reference{ID: "CVE-2021-1"}},
							{Reference: vulnerability.Reference{ID: "CVE-2021-2"}},
						},
						Details: match.Details{{Type: match.ExactDirectMatch}},
						Package: &testPkg,
					},
				},
			},
			want: []match.Match{
				{
					Vulnerability: vulnerability.Vulnerability{Reference: vulnerability.Reference{ID: "CVE-2021-1"}},
					Package:       testPkg,
					Details:       match.Details{{Type: match.ExactDirectMatch}},
				},
				{
					Vulnerability: vulnerability.Vulnerability{Reference: vulnerability.Reference{ID: "CVE-2021-2"}},
					Package:       testPkg,
					Details:       match.Details{{Type: match.ExactDirectMatch}},
				},
			},
		},
		{
			name: "skip results with no vulnerabilities",
			receiver: Set{
				"vuln-1": []Result{
					{
						ID:              "vuln-1",
						Vulnerabilities: []vulnerability.Vulnerability{},
						Details:         match.Details{{Type: match.ExactDirectMatch}},
						Package:         &testPkg,
					},
				},
				"vuln-2": []Result{
					{
						ID: "vuln-2",
						Vulnerabilities: []vulnerability.Vulnerability{
							{Reference: vulnerability.Reference{ID: "CVE-2021-2"}},
						},
						Details: match.Details{{Type: match.ExactDirectMatch}},
						Package: &testPkg,
					},
				},
			},
			want: []match.Match{
				{
					Vulnerability: vulnerability.Vulnerability{Reference: vulnerability.Reference{ID: "CVE-2021-2"}},
					Package:       testPkg,
					Details:       match.Details{{Type: match.ExactDirectMatch}},
				},
			},
		},
		{
			name:     "empty set returns no matches",
			receiver: Set{},
			want:     []match.Match{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.receiver.ToMatches()
			opts := cmp.Options{
				cmpopts.IgnoreUnexported(file.LocationSet{}),
				cmpopts.EquateEmpty(),
			}
			if diff := cmp.Diff(tt.want, got, opts...); diff != "" {
				t.Errorf("Set.ToMatches() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestSet_Filter(t *testing.T) {
	tests := []struct {
		name     string
		receiver Set
		criteria []vulnerability.Criteria
		want     Set
		wantErr  require.ErrorAssertionFunc
	}{
		{
			name: "filter vulnerabilities with matching criteria",
			receiver: Set{
				"vuln-1": []Result{
					{
						ID: "vuln-1",
						Vulnerabilities: []vulnerability.Vulnerability{
							{
								Reference:   vulnerability.Reference{ID: "CVE-2021-1"},
								PackageName: "test-Package",
								Constraint:  version.MustGetConstraint("< 2.0.0", version.SemanticFormat),
							},
							{
								Reference:   vulnerability.Reference{ID: "CVE-2021-2"},
								PackageName: "other-Package",
								Constraint:  version.MustGetConstraint("< 1.0.0", version.SemanticFormat),
							},
						},
						Details: match.Details{{Type: match.ExactDirectMatch}},
					},
				},
			},
			criteria: []vulnerability.Criteria{
				search.ByPackageName("test-Package"),
			},
			want: Set{
				"vuln-1": []Result{
					{
						ID: "vuln-1",
						Vulnerabilities: []vulnerability.Vulnerability{
							{
								Reference:   vulnerability.Reference{ID: "CVE-2021-1"},
								PackageName: "test-Package",
								Constraint:  version.MustGetConstraint("< 2.0.0", version.SemanticFormat),
							},
						},
						Details: match.Details{{Type: match.ExactDirectMatch}},
					},
				},
			},
		},
		{
			name: "filter out all vulnerabilities removes result",
			receiver: Set{
				"vuln-1": []Result{
					{
						ID: "vuln-1",
						Vulnerabilities: []vulnerability.Vulnerability{
							{
								Reference:   vulnerability.Reference{ID: "CVE-2021-1"},
								PackageName: "other-Package",
								Constraint:  version.MustGetConstraint("< 2.0.0", version.SemanticFormat),
							},
						},
						Details: match.Details{{Type: match.ExactDirectMatch}},
					},
				},
			},
			criteria: []vulnerability.Criteria{
				search.ByPackageName("test-Package"),
			},
			want: Set{},
		},
		{
			name:     "filter empty set",
			receiver: Set{},
			criteria: []vulnerability.Criteria{
				search.ByPackageName("test-Package"),
			},
			want: Set{},
		},
		{
			name: "filter with no criteria returns original set",
			receiver: Set{
				"vuln-1": []Result{
					{
						ID: "vuln-1",
						Vulnerabilities: []vulnerability.Vulnerability{
							{
								Reference:   vulnerability.Reference{ID: "CVE-2021-1"},
								PackageName: "test-Package",
								Constraint:  version.MustGetConstraint("< 2.0.0", version.SemanticFormat),
							},
						},
						Details: match.Details{{Type: match.ExactDirectMatch}},
					},
				},
			},
			criteria: []vulnerability.Criteria{},
			want: Set{
				"vuln-1": []Result{
					{
						ID: "vuln-1",
						Vulnerabilities: []vulnerability.Vulnerability{
							{
								Reference:   vulnerability.Reference{ID: "CVE-2021-1"},
								PackageName: "test-Package",
								Constraint:  version.MustGetConstraint("< 2.0.0", version.SemanticFormat),
							},
						},
						Details: match.Details{{Type: match.ExactDirectMatch}},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr == nil {
				tt.wantErr = require.NoError
			}

			got := tt.receiver.Filter(tt.criteria...)

			opts := cmp.Options{
				cmpopts.IgnoreUnexported(file.LocationSet{}),
				cmpopts.IgnoreFields(vulnerability.Vulnerability{}, "Constraint"),
				cmpopts.EquateEmpty(),
			}
			if diff := cmp.Diff(tt.want, got, opts...); diff != "" {
				t.Errorf("Set.Filter() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestSet_Contains(t *testing.T) {
	tests := []struct {
		name     string
		receiver Set
		id       string
		want     bool
	}{
		{
			name: "contains existing ID",
			receiver: Set{
				"vuln-1": []Result{
					{
						ID:              "vuln-1",
						Vulnerabilities: []vulnerability.Vulnerability{{Reference: vulnerability.Reference{ID: "CVE-2021-1"}}},
					},
				},
				"vuln-2": []Result{
					{
						ID:              "vuln-2",
						Vulnerabilities: []vulnerability.Vulnerability{{Reference: vulnerability.Reference{ID: "CVE-2021-2"}}},
					},
				},
			},
			id:   "vuln-1",
			want: true,
		},
		{
			name: "does not contain non-existing ID",
			receiver: Set{
				"vuln-1": []Result{
					{
						ID:              "vuln-1",
						Vulnerabilities: []vulnerability.Vulnerability{{Reference: vulnerability.Reference{ID: "CVE-2021-1"}}},
					},
				},
			},
			id:   "vuln-2",
			want: false,
		},
		{
			name:     "empty set does not contain any ID",
			receiver: Set{},
			id:       "vuln-1",
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.receiver.Contains(tt.id)
			require.Equal(t, tt.want, got)
		})
	}
}
