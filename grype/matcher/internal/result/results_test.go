package result

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/distro"
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
					{Vulnerability: vulnerability.Vulnerability{Reference: vulnerability.Reference{ID: "CVE-2021-1"}}},
				},
				"vuln-2": []Result{
					{Vulnerability: vulnerability.Vulnerability{Reference: vulnerability.Reference{ID: "CVE-2021-2"}}},
				},
			},
			incoming: Set{
				"vuln-1": []Result{
					// need non-empty vulnerabilities; these will never be added to the set using its own utility functions
					{Vulnerability: vulnerability.Vulnerability{Reference: vulnerability.Reference{ID: "CVE-2021-2"}}},
				},
			},
			want: Set{
				"vuln-2": []Result{
					{Vulnerability: vulnerability.Vulnerability{Reference: vulnerability.Reference{ID: "CVE-2021-2"}}},
				},
			},
		},
		{
			name: "remove non-existing entry has no effect",
			receiver: Set{
				"vuln-1": []Result{
					{Vulnerability: vulnerability.Vulnerability{Reference: vulnerability.Reference{ID: "CVE-2021-1"}}},
				},
			},
			incoming: Set{
				"vuln-2": []Result{
					{Vulnerability: vulnerability.Vulnerability{Reference: vulnerability.Reference{ID: "vuln-2"}}},
				},
			},
			want: Set{
				"vuln-1": []Result{
					{Vulnerability: vulnerability.Vulnerability{Reference: vulnerability.Reference{ID: "CVE-2021-1"}}},
				},
			},
		},
		{
			name:     "remove from empty set",
			receiver: Set{},
			incoming: Set{
				"vuln-1": []Result{},
			},
			want: Set{},
		},
		{
			name: "remove with empty incoming set",
			receiver: Set{
				"vuln-1": []Result{
					{Vulnerability: vulnerability.Vulnerability{Reference: vulnerability.Reference{ID: "CVE-2021-1"}}},
				},
			},
			incoming: Set{},
			want: Set{
				"vuln-1": []Result{
					{Vulnerability: vulnerability.Vulnerability{Reference: vulnerability.Reference{ID: "CVE-2021-1"}}},
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
						Vulnerability: vulnerability.Vulnerability{Reference: vulnerability.Reference{ID: "vuln-1", Namespace: "1"}},
					},
				},
			},
			incoming: Set{
				"vuln-1": []Result{
					{Vulnerability: vulnerability.Vulnerability{Reference: vulnerability.Reference{ID: "vuln-1", Namespace: "2"}}},
				},
			},
			want: Set{
				"vuln-1": []Result{
					{Vulnerability: vulnerability.Vulnerability{Reference: vulnerability.Reference{ID: "vuln-1", Namespace: "1"}}},
					{Vulnerability: vulnerability.Vulnerability{Reference: vulnerability.Reference{ID: "vuln-1", Namespace: "2"}}},
				},
			},
		},
		{
			name: "merge new entry from incoming",
			receiver: Set{
				"vuln-1": []Result{
					{Vulnerability: vulnerability.Vulnerability{Reference: vulnerability.Reference{ID: "vuln-1"}}},
				},
			},
			incoming: Set{
				"vuln-2": []Result{
					{Vulnerability: vulnerability.Vulnerability{Reference: vulnerability.Reference{ID: "vuln-2"}}},
				},
			},
			want: Set{
				"vuln-1": []Result{
					{Vulnerability: vulnerability.Vulnerability{Reference: vulnerability.Reference{ID: "vuln-1"}}},
				},
				"vuln-2": []Result{
					{Vulnerability: vulnerability.Vulnerability{Reference: vulnerability.Reference{ID: "vuln-2"}}},
				},
			},
		},
		{
			name: "merge with custom merge function that filters out results",
			receiver: Set{
				"vuln-1": []Result{
					{Vulnerability: vulnerability.Vulnerability{Reference: vulnerability.Reference{ID: "CVE-2021-1"}}},
				},
			},
			incoming: Set{
				"vuln-1": []Result{
					{Vulnerability: vulnerability.Vulnerability{Reference: vulnerability.Reference{ID: "CVE-2021-1-updated"}}},
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

func Test_ToMatches(t *testing.T) {
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
					{Vulnerability: vulnerability.Vulnerability{Reference: vulnerability.Reference{ID: "vuln-1", Namespace: "1"}},
						Criteria: []vulnerability.Criteria{
							search.ByPackageName("test-Package"),
							search.ByDistro(distro.Distro{Type: "rhel", Version: "8"}),
						},
					},
					{Vulnerability: vulnerability.Vulnerability{Reference: vulnerability.Reference{ID: "vuln-1", Namespace: "2"}},
						Criteria: []vulnerability.Criteria{
							search.ByPackageName("pkg"),
							search.ByDistro(distro.Distro{Type: "rhel", Version: "8"}),
						},
					},
				},
			},
			want: []match.Match{
				{
					Vulnerability: vulnerability.Vulnerability{Reference: vulnerability.Reference{ID: "vuln-1", Namespace: "1"}},
					Package:       testPkg,
					Details: match.Details{{
						Type:       match.ExactDirectMatch,
						Matcher:    match.RpmMatcher,
						Confidence: 1,
						SearchedBy: match.DistroParameters{
							Distro: match.DistroIdentification{
								Type:    "rhel",
								Version: "8",
							},
							Package: match.PackageParameter{
								Name: "test-Package",
							},
							Namespace: "1",
						},
						Found: match.DistroResult{
							VulnerabilityID: "vuln-1",
						},
					}},
				},
				{
					Vulnerability: vulnerability.Vulnerability{Reference: vulnerability.Reference{ID: "vuln-1", Namespace: "2"}},
					Package:       testPkg,
					Details: match.Details{{
						Type:       match.ExactIndirectMatch,
						Matcher:    match.RpmMatcher,
						Confidence: 1,
						SearchedBy: match.DistroParameters{
							Distro: match.DistroIdentification{
								Type:    "rhel",
								Version: "8",
							},
							Package: match.PackageParameter{
								Name: "pkg",
							},
							Namespace: "2",
						},
						Found: match.DistroResult{
							VulnerabilityID: "vuln-1",
						},
					}},
				},
			},
		},
		{
			name: "skip results with no vulnerabilities",
			receiver: Set{
				"vuln-1": []Result{},
				"vuln-2": []Result{
					{Vulnerability: vulnerability.Vulnerability{Reference: vulnerability.Reference{ID: "vuln-2"}},
						Criteria: []vulnerability.Criteria{
							search.ByPackageName("test-Package"),
							search.ByDistro(distro.Distro{Type: "rhel", Version: "8"}),
						},
					},
				},
			},
			want: []match.Match{
				{
					Vulnerability: vulnerability.Vulnerability{Reference: vulnerability.Reference{ID: "vuln-2"}},
					Package:       testPkg,
					Details: match.Details{{
						Type:       match.ExactDirectMatch,
						Matcher:    match.RpmMatcher,
						Confidence: 1,
						SearchedBy: match.DistroParameters{
							Distro: match.DistroIdentification{
								Type:    "rhel",
								Version: "8",
							},
							Package: match.PackageParameter{
								Name: "test-Package",
							},
						},
						Found: match.DistroResult{
							VulnerabilityID: "vuln-2",
						},
					}},
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
			got := ToMatches(tt.receiver, match.RpmMatcher, testPkg)
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
					{Vulnerability: vulnerability.Vulnerability{
						Reference:   vulnerability.Reference{ID: "vuln-1"},
						PackageName: "test-Package",
						Constraint:  version.MustGetConstraint("< 2.0.0", version.SemanticFormat),
					}},
					{Vulnerability: vulnerability.Vulnerability{
						Reference:   vulnerability.Reference{ID: "vuln-1"},
						PackageName: "other-Package",
						Constraint:  version.MustGetConstraint("< 1.0.0", version.SemanticFormat),
					}},
				},
			},
			criteria: []vulnerability.Criteria{
				search.ByPackageName("test-Package"),
			},
			want: Set{
				"vuln-1": []Result{
					{Vulnerability: vulnerability.Vulnerability{
						Reference:   vulnerability.Reference{ID: "vuln-1"},
						PackageName: "test-Package",
						Constraint:  version.MustGetConstraint("< 2.0.0", version.SemanticFormat),
					}},
				},
			},
		},
		{
			name: "filter out all vulnerabilities removes result",
			receiver: Set{
				"vuln-1": []Result{
					{Vulnerability: vulnerability.Vulnerability{
						Reference:   vulnerability.Reference{ID: "vuln-1"},
						PackageName: "other-Package",
						Constraint:  version.MustGetConstraint("< 2.0.0", version.SemanticFormat),
					}},
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
					{Vulnerability: vulnerability.Vulnerability{
						Reference:   vulnerability.Reference{ID: "vuln-1"},
						PackageName: "test-Package",
						Constraint:  version.MustGetConstraint("< 2.0.0", version.SemanticFormat),
					}},
				},
			},
			criteria: []vulnerability.Criteria{},
			want: Set{
				"vuln-1": []Result{
					{Vulnerability: vulnerability.Vulnerability{
						Reference:   vulnerability.Reference{ID: "vuln-1"},
						PackageName: "test-Package",
						Constraint:  version.MustGetConstraint("< 2.0.0", version.SemanticFormat),
					}},
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
				cmpopts.IgnoreFields(Result{}, "Criteria"),
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
					{Vulnerability: vulnerability.Vulnerability{Reference: vulnerability.Reference{ID: "CVE-2021-1"}}},
				},
				"vuln-2": []Result{
					{Vulnerability: vulnerability.Vulnerability{Reference: vulnerability.Reference{ID: "CVE-2021-2"}}},
				},
			},
			id:   "vuln-1",
			want: true,
		},
		{
			name: "does not contain non-existing ID",
			receiver: Set{
				"vuln-1": []Result{
					{Vulnerability: vulnerability.Vulnerability{Reference: vulnerability.Reference{ID: "CVE-2021-1"}}},
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
