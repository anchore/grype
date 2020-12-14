package common

import (
	"fmt"
	"testing"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

type mockLanguageProvider struct {
	data map[string]map[string][]*vulnerability.Vulnerability
}

func newMockProviderByLanguage() *mockLanguageProvider {
	pr := mockLanguageProvider{
		data: make(map[string]map[string][]*vulnerability.Vulnerability),
	}
	pr.stub()
	return &pr
}

func (pr *mockLanguageProvider) stub() {
	pr.data["github:gem"] = map[string][]*vulnerability.Vulnerability{
		// direct...
		"activerecord": {
			{
				Constraint: version.MustGetConstraint("< 3.7.6", version.SemanticFormat),
				ID:         "CVE-2017-fake-1",
			},
			{
				Constraint: version.MustGetConstraint("< 3.7.4", version.SemanticFormat),
				ID:         "CVE-2017-fake-2",
			},
		},
	}
}

func (pr *mockLanguageProvider) GetByLanguage(l syftPkg.Language, p pkg.Package) ([]*vulnerability.Vulnerability, error) {
	if l != syftPkg.Ruby {
		panic(fmt.Errorf("test mock only supports ruby"))
	}
	return pr.data["github:gem"][p.Name], nil
}

func TestFindMatchesByPackageLanguage(t *testing.T) {
	p := pkg.Package{
		Name:     "activerecord",
		Version:  "3.7.5",
		Language: syftPkg.Ruby,
		Type:     syftPkg.GemPkg,
	}

	store := newMockProviderByLanguage()
	actual, err := FindMatchesByPackageLanguage(store, p.Language, p, match.PythonMatcher)
	if err != nil {
		t.Fatalf("error while finding matches: %+v", err)
	}

	if len(actual) != 1 {
		t.Fatalf("unexpected direct matches count: %d", len(actual))
	}

	foundCVEs := internal.NewStringSet()

	for _, a := range actual {
		foundCVEs.Add(a.Vulnerability.ID)

		if a.Type != match.ExactDirectMatch {
			t.Error("direct match not indicated")
		}

		if a.Package.Name != p.Name {
			t.Errorf("failed to capture correct original package: %s", a.Package.Name)
		}

		if a.Matcher != match.PythonMatcher {
			t.Errorf("failed to capture matcher name: %s", a.Matcher)
		}

	}

	for _, id := range []string{"CVE-2017-fake-1"} {
		if !foundCVEs.Contains(id) {
			t.Errorf("missing discovered CVE: %s", id)
		}
	}

}
