package stock

import (
	"testing"

	"github.com/google/uuid"
	"github.com/scylladb/go-set/strset"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/cpe"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

func TestMatcher_JVMPackage(t *testing.T) {
	p := pkg.Package{
		ID:      pkg.ID(uuid.NewString()),
		Name:    "java_se",
		Version: "1.8.0_400",
		Type:    syftPkg.BinaryPkg,
		CPEs: []cpe.CPE{
			cpe.Must("cpe:2.3:a:oracle:java_se:1.8.0:update400:*:*:*:*:*:*", cpe.DeclaredSource),
		},
	}
	matcher := Matcher{
		cfg: MatcherConfig{
			UseCPEs: true,
		},
	}
	store := newMockProvider()
	actual, err := matcher.Match(store, nil, p)
	require.NoError(t, err)

	foundCVEs := strset.New()
	for _, v := range actual {
		foundCVEs.Add(v.Vulnerability.ID)

		require.NotEmpty(t, v.Details)
		for _, d := range v.Details {
			assert.Equal(t, match.CPEMatch, d.Type, "indirect match not indicated")
			assert.Equal(t, matcher.Type(), d.Matcher, "failed to capture matcher type")
		}
		assert.Equal(t, p.Name, v.Package.Name, "failed to capture original package name")
	}

	expected := strset.New(
		"CVE-2024-20919-real",
		"CVE-2024-20919-underscore",
		"CVE-2024-20919-bonkers-format",
		"CVE-2024-20919-post-jep223",
	)

	for _, id := range expected.List() {
		if !foundCVEs.Has(id) {
			t.Errorf("missing CVE: %s", id)
		}
	}

	extra := strset.Difference(foundCVEs, expected)

	for _, id := range extra.List() {
		t.Errorf("unexpected CVE: %s", id)
	}

	if t.Failed() {
		t.Logf("discovered CVES: %d", foundCVEs.Size())
		for _, id := range foundCVEs.List() {
			t.Logf(" - %s", id)
		}
	}
}

func newMockProvider() *mockProvider {
	mp := mockProvider{
		data: make(map[syftPkg.Language]map[string][]vulnerability.Vulnerability),
	}

	mp.populateData()

	return &mp
}

type mockProvider struct {
	data map[syftPkg.Language]map[string][]vulnerability.Vulnerability
}

func (mp *mockProvider) Get(_, _ string) ([]vulnerability.Vulnerability, error) {
	// TODO implement me
	panic("not implemented")
}

func (mp *mockProvider) populateData() {

	// derived from vuln data found on CVE-2024-20919
	hit := "< 1.8.0_401 || >= 1.9-ea, < 8.0.401 || >= 9-ea, < 11.0.22 || >= 12-ea, < 17.0.10 || >= 18-ea, < 21.0.2"

	mp.data["nvd:cpe"] = map[string][]vulnerability.Vulnerability{
		"java_se": {
			{
				// positive cases
				Constraint: version.MustGetConstraint(hit, version.JVMFormat),
				ID:         "CVE-2024-20919-real",
			},
			{
				// positive cases
				Constraint: version.MustGetConstraint("< 22.22.22", version.UnknownFormat),
				ID:         "CVE-2024-20919-bonkers-format",
			},
			{
				// negative case
				Constraint: version.MustGetConstraint("< 1.8.0_399 || >= 1.9-ea, < 8.0.399 || >= 9-ea", version.JVMFormat),
				ID:         "CVE-FAKE-bad-update",
			},
			{
				// positive case
				Constraint: version.MustGetConstraint("< 8.0.401", version.JVMFormat),
				ID:         "CVE-2024-20919-post-jep223",
			},
			{
				// negative case
				Constraint: version.MustGetConstraint("< 8.0.399", version.JVMFormat),
				ID:         "CVE-FAKE-bad-range-post-jep223",
			},
			{
				// negative case
				Constraint: version.MustGetConstraint("< 7.0.0", version.JVMFormat),
				ID:         "CVE-FAKE-bad-range-post-jep223",
			},
		},
	}
}

func (mp *mockProvider) GetByCPE(p cpe.CPE) ([]vulnerability.Vulnerability, error) {
	return mp.data["nvd:cpe"][p.Attributes.Product], nil
}

func (mp *mockProvider) GetByDistro(d *distro.Distro, p pkg.Package) ([]vulnerability.Vulnerability, error) {
	return []vulnerability.Vulnerability{}, nil
}

func (mp *mockProvider) GetByLanguage(l syftPkg.Language, p pkg.Package) ([]vulnerability.Vulnerability, error) {
	return mp.data[l][p.Name], nil
}
