package result

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/search"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/cpe"
)

func TestMatchedCPEsForSearch(t *testing.T) {
	tests := []struct {
		name              string
		version           string
		vulnerabilityCPEs []string
		expected          []string
	}{
		{
			name:    "filter out by simple version",
			version: "1.0",
			vulnerabilityCPEs: []string{
				"cpe:2.3:*:multiple:multiple:*:*:*:*:*:*:*:*",
				"cpe:2.3:*:multiple:multiple:1.0:*:*:*:*:*:*:*",
				"cpe:2.3:*:multiple:multiple:2.0:*:*:*:*:*:*:*",
			},
			expected: []string{
				"cpe:2.3:*:multiple:multiple:*:*:*:*:*:*:*:*",
				"cpe:2.3:*:multiple:multiple:1.0:*:*:*:*:*:*:*",
			},
		},
		{
			name:    "do not filter on empty version",
			version: "", // important!
			vulnerabilityCPEs: []string{
				"cpe:2.3:*:multiple:multiple:*:*:*:*:*:*:*:*",
				"cpe:2.3:*:multiple:multiple:1.0:*:*:*:*:*:*:*",
				"cpe:2.3:*:multiple:multiple:2.0:*:*:*:*:*:*:*",
			},
			expected: []string{
				"cpe:2.3:*:multiple:multiple:*:*:*:*:*:*:*:*",
				"cpe:2.3:*:multiple:multiple:1.0:*:*:*:*:*:*:*",
				"cpe:2.3:*:multiple:multiple:2.0:*:*:*:*:*:*:*",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// format strings to CPE objects...
			vulnerabilityCPEs := make([]cpe.CPE, len(test.vulnerabilityCPEs))
			for idx, c := range test.vulnerabilityCPEs {
				vulnerabilityCPEs[idx] = cpe.Must(c, "")
			}

			catalogedPkg := pkg.Package{Version: test.version}
			vuln := vulnerability.Vulnerability{CPEs: vulnerabilityCPEs}

			// run the test subject...
			actual := matchedCPEsForSearch(catalogedPkg, vuln)

			// format CPE objects to string...
			actualStrs := make([]string, len(actual))
			for idx, a := range actual {
				// use .String() for proper escaping
				actualStrs[idx] = a.Attributes.String()
			}

			assert.ElementsMatch(t, test.expected, actualStrs)
		})
	}
}

// TestDetailProvider_CPEDetail pins how a CPE match detail is rendered: the searched-by CPE is the
// one that was searched with, WFN-escaped, and the found CPEs are the record's own.
func TestDetailProvider_CPEDetail(t *testing.T) {
	tests := []struct {
		name               string
		pkgVersion         string
		searchedCPE        string
		vulnCPEs           []string
		expectedSearchedBy string
		expectedFound      []string
	}{
		{
			// the searched-by CPE must be WFN-escaped, i.e. rendered with cpe.Attributes.String()
			// rather than BindToFmtString(), which leaves the "+" unquoted. That is the form the rest
			// of grype emits, including the found CPEs on this very detail.
			name:               "searched-by CPE is escaped when the version has WFN punctuation",
			pkgVersion:         `1.5.0+build.7`,
			searchedCPE:        `cpe:2.3:a:acme:gadget:1.5.0\+build.7:*:*:*:*:*:*:*`,
			vulnCPEs:           []string{"cpe:2.3:a:acme:gadget:*:*:*:*:*:*:*:*"},
			expectedSearchedBy: `cpe:2.3:a:acme:gadget:1.5.0\+build.7:*:*:*:*:*:*:*`,
			expectedFound:      []string{"cpe:2.3:a:acme:gadget:*:*:*:*:*:*:*:*"},
		},
		{
			// v6 always stores a vulnerability's CPEs with version=ANY, so the version filtering in
			// matchedCPEsForSearch is a no-op on real records however specific the searched-by CPE is
			name:               "found CPEs are the record's CPEs, version-agnostic",
			pkgVersion:         "1.9.9",
			searchedCPE:        "cpe:2.3:a:acme:gadget:1.9.9:*:*:*:*:*:*:*",
			vulnCPEs:           []string{"cpe:2.3:a:acme:gadget:*:*:*:*:*:*:*:*"},
			expectedSearchedBy: "cpe:2.3:a:acme:gadget:1.9.9:*:*:*:*:*:*:*",
			expectedFound:      []string{"cpe:2.3:a:acme:gadget:*:*:*:*:*:*:*:*"},
		},
		{
			name:        "found CPEs are sorted",
			pkgVersion:  "1.5.0",
			searchedCPE: "cpe:2.3:a:acme:widget:1.5.0:*:*:*:*:*:*:*",
			vulnCPEs: []string{
				"cpe:2.3:a:acme:widget-core:*:*:*:*:*:*:*:*",
				"cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*",
			},
			expectedSearchedBy: "cpe:2.3:a:acme:widget:1.5.0:*:*:*:*:*:*:*",
			expectedFound: []string{
				"cpe:2.3:a:acme:widget-core:*:*:*:*:*:*:*:*",
				"cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vulnCPEs := make([]cpe.CPE, len(tt.vulnCPEs))
			for i, c := range tt.vulnCPEs {
				vulnCPEs[i] = cpe.Must(c, cpe.DeclaredSource)
			}

			catalogedPkg := pkg.Package{Name: "gadget", Version: tt.pkgVersion}
			vuln := vulnerability.Vulnerability{
				Reference: vulnerability.Reference{ID: "CVE-2026-40002"},
				CPEs:      vulnCPEs,
			}
			criteria := []vulnerability.Criteria{search.ByCPE(cpe.Must(tt.searchedCPE, cpe.DeclaredSource))}

			details := detailProvider(match.StockMatcher, catalogedPkg, criteria, vuln)

			require.Len(t, details, 1)
			assert.Equal(t, match.CPEMatch, details[0].Type)

			searchedBy, ok := details[0].SearchedBy.(match.CPEParameters)
			require.True(t, ok, "expected CPE search parameters, got %T", details[0].SearchedBy)
			assert.Equal(t, []string{tt.expectedSearchedBy}, searchedBy.CPEs)

			found, ok := details[0].Found.(match.CPEResult)
			require.True(t, ok, "expected a CPE result, got %T", details[0].Found)
			assert.Equal(t, tt.expectedFound, found.CPEs)
			assert.Equal(t, "CVE-2026-40002", found.VulnerabilityID)
		})
	}
}
