package internal

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/search"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/cpe"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

const (
	gnuTarName = "tar"
	gnuTarGHSA = "GHSA-3jfq-g458-7qm9"
	gnuTarCVE  = "CVE-2023-39804"
)

// nameOrCPEProvider returns language-ecosystem records when the search is by
// name/ecosystem, and NVD records when the search is by CPE. This is the
// split the stock matcher is supposed to keep when the cataloged package has
// no language of its own (the `cpes:` input path).
type nameOrCPEProvider struct {
	byName []vulnerability.Vulnerability
	byCPE  []vulnerability.Vulnerability
}

func (s nameOrCPEProvider) Close() error { return nil }

func (s nameOrCPEProvider) PackageSearchNames(p pkg.Package) []string {
	return []string{p.Name}
}

func (s nameOrCPEProvider) VulnerabilityMetadata(vulnerability.Reference) (*vulnerability.Metadata, error) {
	return nil, nil
}

func (s nameOrCPEProvider) FindVulnerabilities(criteria ...vulnerability.Criteria) ([]vulnerability.Vulnerability, error) {
	for _, row := range search.CriteriaIterator(criteria) {
		for _, c := range row {
			if _, ok := c.(*search.CPECriteria); ok {
				return s.byCPE, nil
			}
			if _, ok := c.(*search.EcosystemCriteria); ok {
				return s.byName, nil
			}
		}
	}
	return nil, nil
}

func TestMatchPackageByEcosystemAndCPEs_CPEOnlySkipsLanguageNameLookup(t *testing.T) {
	gnuTarCPE := cpe.Must("cpe:2.3:a:gnu:tar:1.35:*:*:*:*:*:*:*", cpe.DeclaredSource)
	store := nameOrCPEProvider{
		byName: []vulnerability.Vulnerability{
			{
				Reference: vulnerability.Reference{
					ID:        gnuTarGHSA,
					Namespace: "github:language:javascript",
				},
				PackageName: gnuTarName,
				Constraint:  version.MustGetConstraint("< 7.5.3", version.SemanticFormat),
			},
		},
		byCPE: []vulnerability.Vulnerability{
			{
				Reference: vulnerability.Reference{
					ID:        gnuTarCVE,
					Namespace: "nvd:cpe",
				},
				PackageName: gnuTarName,
				Constraint:  version.MustGetConstraint("< 1.36", version.UnknownFormat),
				CPEs:        []cpe.CPE{gnuTarCPE},
			},
		},
	}

	p := pkg.Package{
		Name:     gnuTarName,
		Version:  "1.35",
		Language: "",
		Type:     "",
		CPEs:     []cpe.CPE{gnuTarCPE},
	}

	matches, _, err := MatchPackageByEcosystemAndCPEs(store, p, match.StockMatcher, true)
	require.NoError(t, err)

	var ids []string
	for _, m := range matches {
		ids = append(ids, m.Vulnerability.ID)
	}
	assert.NotContains(t, ids, gnuTarGHSA, "npm tar advisories must not be exact-direct matches for a GNU tar CPE")
	assert.Contains(t, ids, gnuTarCVE, "CPE matching against GNU tar records must still run")
}

func TestHasLanguageEcosystem(t *testing.T) {
	assert.False(t, hasLanguageEcosystem(pkg.Package{}))
	assert.False(t, hasLanguageEcosystem(pkg.Package{Language: syftPkg.UnknownLanguage}))
	assert.True(t, hasLanguageEcosystem(pkg.Package{Language: syftPkg.JavaScript}))
}
