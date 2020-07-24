package common

import (
	"github.com/anchore/grype/grype/cpe"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal"
	"github.com/anchore/syft/syft/pkg"
	"testing"
)

func must(c cpe.CPE, e error) cpe.CPE {
	if e != nil {
		panic(e)
	}
	return c
}

type mockCPEProvider struct {
	data map[string]map[string][]*vulnerability.Vulnerability
}

func newMockProviderByCPE() *mockCPEProvider {
	pr := mockCPEProvider{
		data: make(map[string]map[string][]*vulnerability.Vulnerability),
	}
	pr.stub()
	return &pr
}

func (pr *mockCPEProvider) stub() {
	pr.data["nvd"] = map[string][]*vulnerability.Vulnerability{
		"activerecord": {
			{
				Constraint: version.MustGetConstraint("< 3.7.6", version.SemanticFormat),
				ID:         "CVE-2017-fake-1",
				CPEs: []cpe.CPE{
					must(cpe.New("cpe:2.3:*:activerecord:activerecord:*:*:*:*:*:rails:*:*")),
				},
			},
			{
				Constraint: version.MustGetConstraint("< 3.7.4", version.SemanticFormat),
				ID:         "CVE-2017-fake-2",
				CPEs: []cpe.CPE{
					must(cpe.New("cpe:2.3:*:activerecord:activerecord:*:*:*:*:*:ruby:*:*")),
				},
			},
			{
				Constraint: version.MustGetConstraint("= 4.0.1", version.SemanticFormat),
				ID:         "CVE-2017-fake-3",
				CPEs: []cpe.CPE{
					must(cpe.New("cpe:2.3:*:couldntgetthisrightcouldyou:activerecord:4.0.1:*:*:*:*:*:*:*")),
				},
			},
		},
		"awesome": {
			{
				Constraint: version.MustGetConstraint("< 98SP3", version.UnknownFormat),
				ID:         "CVE-2017-fake-4",
				CPEs: []cpe.CPE{
					must(cpe.New("cpe:2.3:*:awesome:awesome:*:*:*:*:*:*:*:*")),
				},
			},
		},
	}
}

func (pr *mockCPEProvider) GetByCPE(c cpe.CPE) ([]*vulnerability.Vulnerability, error) {
	return pr.data["nvd"][c.Product], nil
}

func TestFindMatchesByPackageCPE(t *testing.T) {
	tests := []struct {
		name     string
		p        pkg.Package
		expected []string
	}{
		{
			name: "match from range",
			p: pkg.Package{
				Name:     "activerecord",
				Version:  "3.7.5",
				Language: pkg.Ruby,
				Type:     pkg.BundlerPkg,
			},
			expected: []string{
				"CVE-2017-fake-1",
			},
		},
		{
			name: "multiple matches",
			p: pkg.Package{
				Name:     "activerecord",
				Version:  "3.7.3",
				Language: pkg.Ruby,
				Type:     pkg.BundlerPkg,
			},
			expected: []string{
				"CVE-2017-fake-1",
				"CVE-2017-fake-2",
			},
		},
		{
			name: "exact match",
			p: pkg.Package{
				Name:     "activerecord",
				Version:  "4.0.1",
				Language: pkg.Ruby,
				Type:     pkg.BundlerPkg,
			},
			expected: []string{
				"CVE-2017-fake-3",
			},
		},
		{
			name: "no match",
			p: pkg.Package{
				Name:     "couldntgetthisrightcouldyou",
				Version:  "4.0.1",
				Language: pkg.Ruby,
				Type:     pkg.BundlerPkg,
			},
			expected: []string{},
		},
		{
			name: "fuzzy version match",
			p: pkg.Package{
				Name:    "awesome",
				Version: "98SE1",
			},
			expected: []string{
				"CVE-2017-fake-4",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			store := newMockProviderByCPE()
			actual, err := FindMatchesByPackageCPE(store, &test.p, match.PythonMatcher)
			if err != nil {
				t.Fatalf("error while finding matches: %+v", err)
			}

			if len(actual) != len(test.expected) {
				for _, a := range actual {
					t.Errorf("   entry: %+v", a)
				}
				t.Fatalf("unexpected matches count: %d", len(actual))
			}

			foundCVEs := internal.NewStringSet()

			for _, a := range actual {
				foundCVEs.Add(a.Vulnerability.ID)

				if a.Type != match.FuzzyMatch {
					t.Error("fuzzy match not indicated")
				}

				if a.Package.Name != test.p.Name {
					t.Errorf("failed to capture correct original package: %s", a.Package.Name)
				}

				if a.Matcher != match.PythonMatcher {
					t.Errorf("failed to capture matcher name: %s", a.Matcher)
				}

				if a.IndirectPackage != nil {
					t.Fatalf("should not have captured indirect package")
				}

				if a.Confidence != 0.9 {
					t.Fatalf("unexpected confidence: %f", a.Confidence)
				}
			}

			for _, id := range test.expected {
				if !foundCVEs.Contains(id) {
					t.Errorf("missing CVE: %s", id)
				}
			}
		})
	}
}
