package common

import (
	"testing"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

func must(c syftPkg.CPE, e error) syftPkg.CPE {
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
				CPEs: []syftPkg.CPE{
					must(syftPkg.NewCPE("cpe:2.3:*:activerecord:activerecord:*:*:*:*:*:rails:*:*")),
				},
			},
			{
				Constraint: version.MustGetConstraint("< 3.7.4", version.SemanticFormat),
				ID:         "CVE-2017-fake-2",
				CPEs: []syftPkg.CPE{
					must(syftPkg.NewCPE("cpe:2.3:*:activerecord:activerecord:*:*:*:*:*:ruby:*:*")),
				},
			},
			{
				Constraint: version.MustGetConstraint("= 4.0.1", version.SemanticFormat),
				ID:         "CVE-2017-fake-3",
				CPEs: []syftPkg.CPE{
					must(syftPkg.NewCPE("cpe:2.3:*:couldntgetthisrightcouldyou:activerecord:4.0.1:*:*:*:*:*:*:*")),
				},
			},
			{
				Constraint: version.MustGetConstraint("= 4.0.1", version.SemanticFormat),
				ID:         "CVE-2017-fake-3",
				CPEs: []syftPkg.CPE{
					must(syftPkg.NewCPE("cpe:2.3:*:couldntgetthisrightcouldyou:activerecord:4.0.1:*:*:*:*:*:*:*")),
				},
			},
		},
		"awesome": {
			{
				Constraint: version.MustGetConstraint("< 98SP3", version.UnknownFormat),
				ID:         "CVE-2017-fake-4",
				CPEs: []syftPkg.CPE{
					must(syftPkg.NewCPE("cpe:2.3:*:awesome:awesome:*:*:*:*:*:*:*:*")),
				},
			},
		},
	}
}

func (pr *mockCPEProvider) GetByCPE(c syftPkg.CPE) ([]*vulnerability.Vulnerability, error) {
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
				CPEs: []syftPkg.CPE{
					must(syftPkg.NewCPE("cpe:2.3:*:activerecord:activerecord:3.7.5:rando1:*:rando2:*:ruby:*:*")),
					must(syftPkg.NewCPE("cpe:2.3:*:activerecord:activerecord:3.7.5:rando4:*:rando3:*:rails:*:*")),
				},
				Name:     "activerecord",
				Version:  "3.7.5",
				Language: syftPkg.Ruby,
				Type:     syftPkg.GemPkg,
			},
			expected: []string{
				"CVE-2017-fake-1",
			},
		},
		{
			name: "multiple matches",
			p: pkg.Package{
				CPEs: []syftPkg.CPE{
					must(syftPkg.NewCPE("cpe:2.3:*:activerecord:activerecord:3.7.3:rando1:*:rando2:*:ruby:*:*")),
					must(syftPkg.NewCPE("cpe:2.3:*:activerecord:activerecord:3.7.3:rando4:*:rando3:*:rails:*:*")),
				},
				Name:     "activerecord",
				Version:  "3.7.3",
				Language: syftPkg.Ruby,
				Type:     syftPkg.GemPkg,
			},
			expected: []string{
				"CVE-2017-fake-1",
				"CVE-2017-fake-2",
			},
		},
		{
			name: "exact match",
			p: pkg.Package{
				CPEs: []syftPkg.CPE{
					must(syftPkg.NewCPE("cpe:2.3:*:activerecord:activerecord:4.0.1:rando1:*:rando2:*:ruby:*:*")),
					must(syftPkg.NewCPE("cpe:2.3:*:activerecord:activerecord:4.0.1:rando4:*:rando3:*:rails:*:*")),
				},
				Name:     "activerecord",
				Version:  "4.0.1",
				Language: syftPkg.Ruby,
				Type:     syftPkg.GemPkg,
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
				Language: syftPkg.Ruby,
				Type:     syftPkg.GemPkg,
			},
			expected: []string{},
		},
		{
			name: "fuzzy version match",
			p: pkg.Package{
				CPEs: []syftPkg.CPE{
					must(syftPkg.NewCPE("cpe:2.3:*:awesome:awesome:98SE1:rando1:*:rando2:*:dunno:*:*")),
				},
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
			actual, err := FindMatchesByPackageCPE(store, test.p, match.PythonMatcher)
			if err != nil {
				t.Fatalf("error while finding matches: %+v", err)
			}

			if len(actual) != len(test.expected) {
				for _, a := range actual {
					t.Errorf("   entry: %+v", a)
				}
				t.Fatalf("unexpected matches count: %d != %d", len(actual), len(test.expected))
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
