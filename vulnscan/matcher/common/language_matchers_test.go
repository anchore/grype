package common

import (
	"fmt"
	"testing"

	"github.com/anchore/imgbom/imgbom/pkg"
	"github.com/anchore/vulnscan/internal"
	"github.com/anchore/vulnscan/vulnscan/match"
	"github.com/anchore/vulnscan/vulnscan/version"
	"github.com/anchore/vulnscan/vulnscan/vulnerability"
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

func (pr *mockLanguageProvider) GetByLanguage(l pkg.Language, p *pkg.Package) ([]*vulnerability.Vulnerability, error) {
	if l != pkg.Ruby {
		panic(fmt.Errorf("test mock only supports ruby"))
	}
	return pr.data["github:gem"][p.Name], nil
}

func TestFindMatchesByPackageLanguage(t *testing.T) {
	p := pkg.Package{
		Name:     "activerecord",
		Version:  "3.7.5",
		Language: pkg.Ruby,
		Type:     pkg.BundlerPkg,
	}

	store := newMockProviderByLanguage()
	actual, err := FindMatchesByPackageLanguage(store, p.Language, &p, "SOME_OTHER_MATCHER")
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

		if a.Matcher != "SOME_OTHER_MATCHER" {
			t.Errorf("failed to capture matcher name: %s", a.Matcher)
		}

		if a.IndirectPackage != nil {
			t.Fatalf("should not have captured indirect package")
		}
	}

	for _, id := range []string{"CVE-2017-fake-1"} {
		if !foundCVEs.Contains(id) {
			t.Errorf("missing discovered CVE: %s", id)
		}
	}

}
