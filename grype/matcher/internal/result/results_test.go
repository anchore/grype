package result

import (
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/syft/syft/file"
	"github.com/google/go-cmp/cmp/cmpopts"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/search"
	"github.com/anchore/grype/grype/vulnerability"
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
				"vuln-1": Result{
					ID:              "vuln-1",
					Vulnerabilities: []vulnerability.Vulnerability{{Reference: vulnerability.Reference{ID: "CVE-2021-1"}}},
					Details:         match.Details{{Type: match.ExactDirectMatch}},
				},
				"vuln-2": Result{
					ID:              "vuln-2",
					Vulnerabilities: []vulnerability.Vulnerability{{Reference: vulnerability.Reference{ID: "CVE-2021-2"}}},
					Details:         match.Details{{Type: match.ExactDirectMatch}},
				},
			},
			incoming: Set{
				"vuln-1": Result{ID: "vuln-1"},
			},
			want: Set{
				"vuln-2": Result{
					ID:              "vuln-2",
					Vulnerabilities: []vulnerability.Vulnerability{{Reference: vulnerability.Reference{ID: "CVE-2021-2"}}},
					Details:         match.Details{{Type: match.ExactDirectMatch}},
				},
			},
		},
		{
			name: "remove non-existing entry has no effect",
			receiver: Set{
				"vuln-1": Result{
					ID:              "vuln-1",
					Vulnerabilities: []vulnerability.Vulnerability{{Reference: vulnerability.Reference{ID: "CVE-2021-1"}}},
					Details:         match.Details{{Type: match.ExactDirectMatch}},
				},
			},
			incoming: Set{
				"vuln-2": Result{ID: "vuln-2"},
			},
			want: Set{
				"vuln-1": Result{
					ID:              "vuln-1",
					Vulnerabilities: []vulnerability.Vulnerability{{Reference: vulnerability.Reference{ID: "CVE-2021-1"}}},
					Details:         match.Details{{Type: match.ExactDirectMatch}},
				},
			},
		},
		{
			name:     "remove from empty set",
			receiver: Set{},
			incoming: Set{
				"vuln-1": Result{ID: "vuln-1"},
			},
			want: Set{},
		},
		{
			name: "remove with empty incoming set",
			receiver: Set{
				"vuln-1": Result{
					ID:              "vuln-1",
					Vulnerabilities: []vulnerability.Vulnerability{{Reference: vulnerability.Reference{ID: "CVE-2021-1"}}},
					Details:         match.Details{{Type: match.ExactDirectMatch}},
				},
			},
			incoming: Set{},
			want: Set{
				"vuln-1": Result{
					ID:              "vuln-1",
					Vulnerabilities: []vulnerability.Vulnerability{{Reference: vulnerability.Reference{ID: "CVE-2021-1"}}},
					Details:         match.Details{{Type: match.ExactDirectMatch}},
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
		mergeFuncs []func(existing, incoming Result) Result
		want       Set
	}{
		{
			name: "merge with default merge function",
			receiver: Set{
				"vuln-1": Result{
					ID:              "vuln-1",
					Vulnerabilities: []vulnerability.Vulnerability{{Reference: vulnerability.Reference{ID: "CVE-2021-1"}}},
					Details:         match.Details{{Type: match.ExactDirectMatch}},
				},
			},
			incoming: Set{
				"vuln-1": Result{
					ID:              "vuln-1",
					Vulnerabilities: []vulnerability.Vulnerability{{Reference: vulnerability.Reference{ID: "CVE-2021-1-updated"}}},
					Details:         match.Details{{Type: match.ExactIndirectMatch}},
				},
			},
			want: Set{
				"vuln-1": Result{
					ID: "vuln-1",
					Vulnerabilities: []vulnerability.Vulnerability{
						{Reference: vulnerability.Reference{ID: "CVE-2021-1"}},
						{Reference: vulnerability.Reference{ID: "CVE-2021-1-updated"}},
					},
					Details: match.Details{
						{Type: match.ExactDirectMatch},
						{Type: match.ExactIndirectMatch},
					},
				},
			},
		},
		{
			name: "merge new entry from incoming",
			receiver: Set{
				"vuln-1": Result{
					ID:              "vuln-1",
					Vulnerabilities: []vulnerability.Vulnerability{{Reference: vulnerability.Reference{ID: "CVE-2021-1"}}},
					Details:         match.Details{{Type: match.ExactDirectMatch}},
				},
			},
			incoming: Set{
				"vuln-2": Result{
					ID:              "vuln-2",
					Vulnerabilities: []vulnerability.Vulnerability{{Reference: vulnerability.Reference{ID: "CVE-2021-2"}}},
					Details:         match.Details{{Type: match.ExactDirectMatch}},
				},
			},
			want: Set{
				"vuln-1": Result{
					ID:              "vuln-1",
					Vulnerabilities: []vulnerability.Vulnerability{{Reference: vulnerability.Reference{ID: "CVE-2021-1"}}},
					Details:         match.Details{{Type: match.ExactDirectMatch}},
				},
				"vuln-2": Result{
					ID:              "vuln-2",
					Vulnerabilities: []vulnerability.Vulnerability{{Reference: vulnerability.Reference{ID: "CVE-2021-2"}}},
					Details:         match.Details{{Type: match.ExactDirectMatch}},
				},
			},
		},
		{
			name: "merge with custom merge function that filters out results",
			receiver: Set{
				"vuln-1": Result{
					ID:              "vuln-1",
					Vulnerabilities: []vulnerability.Vulnerability{{Reference: vulnerability.Reference{ID: "CVE-2021-1"}}},
					Details:         match.Details{{Type: match.ExactDirectMatch}},
				},
			},
			incoming: Set{
				"vuln-1": Result{
					ID:              "vuln-1",
					Vulnerabilities: []vulnerability.Vulnerability{{Reference: vulnerability.Reference{ID: "CVE-2021-1-updated"}}},
					Details:         match.Details{{Type: match.ExactIndirectMatch}},
				},
			},
			mergeFuncs: []func(existing, incoming Result) Result{
				func(existing, incoming Result) Result {
					// custom merge function that returns empty result to filter out
					return Result{}
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
		Name:    "test-pkg",
		Version: "1.0.0",
		Type:    syftPkg.DebPkg,
	}

	tests := []struct {
		name       string
		receiver   Set
		pkg        pkg.Package
		mergeFuncs []func(vulns []vulnerability.Vulnerability) []vulnerability.Vulnerability
		want       []match.Match
	}{
		{
			name: "convert results to matches",
			receiver: Set{
				"vuln-1": Result{
					ID: "vuln-1",
					Vulnerabilities: []vulnerability.Vulnerability{
						{Reference: vulnerability.Reference{ID: "CVE-2021-1"}},
						{Reference: vulnerability.Reference{ID: "CVE-2021-2"}},
					},
					Details: match.Details{{Type: match.ExactDirectMatch}},
				},
			},
			pkg: testPkg,
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
				"vuln-1": Result{
					ID:              "vuln-1",
					Vulnerabilities: []vulnerability.Vulnerability{},
					Details:         match.Details{{Type: match.ExactDirectMatch}},
				},
				"vuln-2": Result{
					ID: "vuln-2",
					Vulnerabilities: []vulnerability.Vulnerability{
						{Reference: vulnerability.Reference{ID: "CVE-2021-2"}},
					},
					Details: match.Details{{Type: match.ExactDirectMatch}},
				},
			},
			pkg: testPkg,
			want: []match.Match{
				{
					Vulnerability: vulnerability.Vulnerability{Reference: vulnerability.Reference{ID: "CVE-2021-2"}},
					Package:       testPkg,
					Details:       match.Details{{Type: match.ExactDirectMatch}},
				},
			},
		},
		{
			name: "apply merge functions to vulnerabilities",
			receiver: Set{
				"vuln-1": Result{
					ID: "vuln-1",
					Vulnerabilities: []vulnerability.Vulnerability{
						{Reference: vulnerability.Reference{ID: "CVE-2021-1"}},
						{Reference: vulnerability.Reference{ID: "CVE-2021-2"}},
					},
					Details: match.Details{{Type: match.ExactDirectMatch}},
				},
			},
			pkg: testPkg,
			mergeFuncs: []func(vulns []vulnerability.Vulnerability) []vulnerability.Vulnerability{
				func(vulns []vulnerability.Vulnerability) []vulnerability.Vulnerability {
					// filter out the first vulnerability
					if len(vulns) > 1 {
						return vulns[1:]
					}
					return vulns
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
			pkg:      testPkg,
			want:     []match.Match{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.receiver.ToMatches(tt.pkg, tt.mergeFuncs...)
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
				"vuln-1": Result{
					ID: "vuln-1",
					Vulnerabilities: []vulnerability.Vulnerability{
						{
							Reference:   vulnerability.Reference{ID: "CVE-2021-1"},
							PackageName: "test-pkg",
							Constraint:  version.MustGetConstraint("< 2.0.0", version.SemanticFormat),
						},
						{
							Reference:   vulnerability.Reference{ID: "CVE-2021-2"},
							PackageName: "other-pkg",
							Constraint:  version.MustGetConstraint("< 1.0.0", version.SemanticFormat),
						},
					},
					Details: match.Details{{Type: match.ExactDirectMatch}},
				},
			},
			criteria: []vulnerability.Criteria{
				search.ByPackageName("test-pkg"),
			},
			want: Set{
				"vuln-1": Result{
					ID: "vuln-1",
					Vulnerabilities: []vulnerability.Vulnerability{
						{
							Reference:   vulnerability.Reference{ID: "CVE-2021-1"},
							PackageName: "test-pkg",
							Constraint:  version.MustGetConstraint("< 2.0.0", version.SemanticFormat),
						},
					},
					Details: match.Details{{Type: match.ExactDirectMatch}},
				},
			},
		},
		{
			name: "filter out all vulnerabilities removes result",
			receiver: Set{
				"vuln-1": Result{
					ID: "vuln-1",
					Vulnerabilities: []vulnerability.Vulnerability{
						{
							Reference:   vulnerability.Reference{ID: "CVE-2021-1"},
							PackageName: "other-pkg",
							Constraint:  version.MustGetConstraint("< 2.0.0", version.SemanticFormat),
						},
					},
					Details: match.Details{{Type: match.ExactDirectMatch}},
				},
			},
			criteria: []vulnerability.Criteria{
				search.ByPackageName("test-pkg"),
			},
			want: Set{},
		},
		{
			name:     "filter empty set",
			receiver: Set{},
			criteria: []vulnerability.Criteria{
				search.ByPackageName("test-pkg"),
			},
			want: Set{},
		},
		{
			name: "filter with no criteria returns original set",
			receiver: Set{
				"vuln-1": Result{
					ID: "vuln-1",
					Vulnerabilities: []vulnerability.Vulnerability{
						{
							Reference:   vulnerability.Reference{ID: "CVE-2021-1"},
							PackageName: "test-pkg",
							Constraint:  version.MustGetConstraint("< 2.0.0", version.SemanticFormat),
						},
					},
					Details: match.Details{{Type: match.ExactDirectMatch}},
				},
			},
			criteria: []vulnerability.Criteria{},
			want: Set{
				"vuln-1": Result{
					ID: "vuln-1",
					Vulnerabilities: []vulnerability.Vulnerability{
						{
							Reference:   vulnerability.Reference{ID: "CVE-2021-1"},
							PackageName: "test-pkg",
							Constraint:  version.MustGetConstraint("< 2.0.0", version.SemanticFormat),
						},
					},
					Details: match.Details{{Type: match.ExactDirectMatch}},
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
		id       ID
		want     bool
	}{
		{
			name: "contains existing ID",
			receiver: Set{
				"vuln-1": Result{
					ID:              "vuln-1",
					Vulnerabilities: []vulnerability.Vulnerability{{Reference: vulnerability.Reference{ID: "CVE-2021-1"}}},
				},
				"vuln-2": Result{
					ID:              "vuln-2",
					Vulnerabilities: []vulnerability.Vulnerability{{Reference: vulnerability.Reference{ID: "CVE-2021-2"}}},
				},
			},
			id:   "vuln-1",
			want: true,
		},
		{
			name: "does not contain non-existing ID",
			receiver: Set{
				"vuln-1": Result{
					ID:              "vuln-1",
					Vulnerabilities: []vulnerability.Vulnerability{{Reference: vulnerability.Reference{ID: "CVE-2021-1"}}},
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
