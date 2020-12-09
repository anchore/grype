package integration

import (
	"testing"

	"github.com/anchore/grype/grype"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal"
	"github.com/anchore/stereoscope/pkg/imagetest"
	"github.com/anchore/syft/syft"
	syftPkg "github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
	"github.com/sergi/go-diff/diffmatchpatch"
)

func getPackagesByPath(t *testing.T, theSource source.Source, catalog *syftPkg.Catalog, thePath string) []*syftPkg.Package {
	t.Helper()
	refs, err := theSource.Resolver.FilesByGlob(thePath)
	if err != nil {
		t.Fatalf("could not get ref by path %q: %+v", thePath, err)
	}
	if len(refs) != 1 {
		t.Fatalf("unexpected paths for %q: %+v", thePath, refs)
	}
	return catalog.PackagesByFile(refs[0])
}

func addAlpineMatches(t *testing.T, theSource source.Source, catalog *syftPkg.Catalog, theStore *mockStore, theResult *match.Matches) {
	packages := getPackagesByPath(t, theSource, catalog, "/lib/apk/db/installed")
	if len(packages) != 1 {
		t.Logf("Alpine Packages: %+v", packages)
		t.Fatalf("problem with upstream syft cataloger (alpine)")
	}
	thePkg := pkg.New(packages[0])
	theVuln := theStore.backend["alpine:3.12"][thePkg.Name][0]
	vulnObj, err := vulnerability.NewVulnerability(theVuln)
	if err != nil {
		t.Fatalf("failed to create vuln obj: %+v", err)
	}
	theResult.Add(thePkg, match.Match{
		Type:          match.FuzzyMatch,
		Confidence:    1.0,
		Vulnerability: *vulnObj,
		Package:       thePkg,
		SearchKey: map[string]interface{}{
			"cpe": "cpe:2.3:*:*:libvncserver:0.9.9:*:*:*:*:*:*:*",
		},
		SearchMatches: map[string]interface{}{
			"cpes":       []string{"cpe:2.3:*:*:libvncserver:0.9.9:*:*:*:*:*:*:*"},
			"constraint": "< 0.9.10 (unknown)",
		},
		Matcher: match.ApkMatcher,
	})
}

func addJavascriptMatches(t *testing.T, theSource source.Source, catalog *syftPkg.Catalog, theStore *mockStore, theResult *match.Matches) {
	packages := getPackagesByPath(t, theSource, catalog, "/javascript/pkg-json/package.json")
	if len(packages) != 1 {
		t.Logf("Javascript Packages: %+v", packages)
		t.Fatalf("problem with upstream syft cataloger (javascript)")
	}
	thePkg := pkg.New(packages[0])
	theVuln := theStore.backend["github:npm"][thePkg.Name][0]
	vulnObj, err := vulnerability.NewVulnerability(theVuln)
	if err != nil {
		t.Fatalf("failed to create vuln obj: %+v", err)
	}
	theResult.Add(thePkg, match.Match{
		Type:          match.ExactDirectMatch,
		Confidence:    1.0,
		Vulnerability: *vulnObj,
		Package:       thePkg,
		SearchKey: map[string]interface{}{
			"language": "javascript",
		},
		SearchMatches: map[string]interface{}{
			"constraint": "< 3.2.1 (unknown)",
		},
		Matcher: match.JavascriptMatcher,
	})
}

func addPythonMatches(t *testing.T, theSource source.Source, catalog *syftPkg.Catalog, theStore *mockStore, theResult *match.Matches) {
	packages := getPackagesByPath(t, theSource, catalog, "/python/dist-info/METADATA")
	if len(packages) != 1 {
		t.Logf("Python Packages: %+v", packages)
		t.Fatalf("problem with upstream syft cataloger (python)")
	}
	thePkg := pkg.New(packages[0])
	theVuln := theStore.backend["github:python"][thePkg.Name][0]
	vulnObj, err := vulnerability.NewVulnerability(theVuln)
	if err != nil {
		t.Fatalf("failed to create vuln obj: %+v", err)
	}
	theResult.Add(thePkg, match.Match{
		Type:          match.ExactDirectMatch,
		Confidence:    1.0,
		Vulnerability: *vulnObj,
		Package:       thePkg,
		SearchKey: map[string]interface{}{
			"language": "python",
		},
		SearchMatches: map[string]interface{}{
			"constraint": "< 2.6.2 (python)",
		},
		Matcher: match.PythonMatcher,
	})
}

func addRubyMatches(t *testing.T, theSource source.Source, catalog *syftPkg.Catalog, theStore *mockStore, theResult *match.Matches) {
	packages := getPackagesByPath(t, theSource, catalog, "/ruby/specifications/bundler.gemspec")
	if len(packages) != 1 {
		t.Logf("Ruby Packages: %+v", packages)
		t.Fatalf("problem with upstream syft cataloger (ruby)")
	}
	thePkg := pkg.New(packages[0])
	theVuln := theStore.backend["github:gem"][thePkg.Name][0]
	vulnObj, err := vulnerability.NewVulnerability(theVuln)
	if err != nil {
		t.Fatalf("failed to create vuln obj: %+v", err)
	}
	theResult.Add(thePkg, match.Match{
		Type:          match.ExactDirectMatch,
		Confidence:    1.0,
		Vulnerability: *vulnObj,
		Package:       thePkg,
		SearchKey: map[string]interface{}{
			"language": "ruby",
		},
		SearchMatches: map[string]interface{}{
			"constraint": "> 4.0.0, <= 4.1.1 (semver)",
		},
		Matcher: match.RubyGemMatcher,
	})
}

func addJavaMatches(t *testing.T, theSource source.Source, catalog *syftPkg.Catalog, theStore *mockStore, theResult *match.Matches) {
	packages := make([]*syftPkg.Package, 0)
	for p := range catalog.Enumerate(syftPkg.JavaPkg) {
		packages = append(packages, p)
	}
	if len(packages) != 2 { // 2, because there's a nested JAR inside the test fixture JAR
		t.Logf("Java Packages: %+v", packages)
		t.Fatalf("problem with upstream syft cataloger (java)")
	}
	theSyftPkg := packages[0]

	groupId := theSyftPkg.Metadata.(syftPkg.JavaMetadata).PomProperties.GroupID
	lookup := groupId + ":" + theSyftPkg.Name

	thePkg := pkg.New(theSyftPkg)

	theVuln := theStore.backend["github:java"][lookup][0]
	vulnObj, err := vulnerability.NewVulnerability(theVuln)
	if err != nil {
		t.Fatalf("failed to create vuln obj: %+v", err)
	}
	theResult.Add(thePkg, match.Match{
		Type:          match.ExactDirectMatch,
		Confidence:    1.0,
		Vulnerability: *vulnObj,
		Package:       thePkg,
		SearchKey: map[string]interface{}{
			"language": "java",
		},
		SearchMatches: map[string]interface{}{
			"constraint": ">= 0.0.1, < 1.2.0 (unknown)",
		},
		Matcher: match.JavaMatcher,
	})
}

func addDpkgMatches(t *testing.T, theSource source.Source, catalog *syftPkg.Catalog, theStore *mockStore, theResult *match.Matches) {
	packages := getPackagesByPath(t, theSource, catalog, "/var/lib/dpkg/status")
	if len(packages) != 1 {
		t.Logf("Dpkg Packages: %+v", packages)
		t.Fatalf("problem with upstream syft cataloger (dpkg)")
	}
	thePkg := pkg.New(packages[0])
	// NOTE: this is an indirect match, in typical debian style
	theVuln := theStore.backend["debian:8"][thePkg.Name+"-dev"][0]
	vulnObj, err := vulnerability.NewVulnerability(theVuln)
	if err != nil {
		t.Fatalf("failed to create vuln obj: %+v", err)
	}
	theResult.Add(thePkg, match.Match{
		Type:          match.ExactIndirectMatch,
		Confidence:    1.0,
		Vulnerability: *vulnObj,
		Package:       thePkg,
		SearchKey: map[string]interface{}{
			"distro": map[string]string{
				"type":    "debian",
				"version": "8",
			},
		},
		SearchMatches: map[string]interface{}{
			"constraint": "<= 1.8.2 (deb)",
		},
		Matcher: match.DpkgMatcher,
	})
}

func addRhelMatches(t *testing.T, theSource source.Source, catalog *syftPkg.Catalog, theStore *mockStore, theResult *match.Matches) {
	packages := getPackagesByPath(t, theSource, catalog, "/var/lib/rpm/Packages")
	if len(packages) != 1 {
		t.Logf("RPMDB Packages: %+v", packages)
		t.Fatalf("problem with upstream syft cataloger (RPMDB)")
	}
	thePkg := pkg.New(packages[0])
	theVuln := theStore.backend["rhel:8"][thePkg.Name][0]
	vulnObj, err := vulnerability.NewVulnerability(theVuln)
	if err != nil {
		t.Fatalf("failed to create vuln obj: %+v", err)
	}
	theResult.Add(thePkg, match.Match{
		Type:          match.ExactDirectMatch,
		Confidence:    1.0,
		Vulnerability: *vulnObj,
		Package:       thePkg,
		SearchKey: map[string]interface{}{
			"distro": map[string]string{
				"type":    "centos",
				"version": "8",
			},
		},
		SearchMatches: map[string]interface{}{
			"constraint": "<= 1.0.42 (rpm)",
		},
		Matcher: match.RpmDBMatcher,
	})
}

func TestPkgCoverageImage(t *testing.T) {

	observedMatchers := internal.NewStringSet()
	definedMatchers := internal.NewStringSet()
	for _, l := range match.AllMatcherTypes {
		definedMatchers.Add(l.String())
	}

	tests := []struct {
		fixtureImage string
		expectedFn   func(source.Source, *syftPkg.Catalog, *mockStore) match.Matches
	}{
		{
			fixtureImage: "image-debian-match-coverage",
			expectedFn: func(theSource source.Source, catalog *syftPkg.Catalog, theStore *mockStore) match.Matches {
				expectedMatches := match.NewMatches()
				addPythonMatches(t, theSource, catalog, theStore, &expectedMatches)
				addRubyMatches(t, theSource, catalog, theStore, &expectedMatches)
				addJavaMatches(t, theSource, catalog, theStore, &expectedMatches)
				addDpkgMatches(t, theSource, catalog, theStore, &expectedMatches)
				addJavascriptMatches(t, theSource, catalog, theStore, &expectedMatches)
				return expectedMatches
			},
		},
		{
			fixtureImage: "image-centos-match-coverage",
			expectedFn: func(theSource source.Source, catalog *syftPkg.Catalog, theStore *mockStore) match.Matches {
				expectedMatches := match.NewMatches()
				addRhelMatches(t, theSource, catalog, theStore, &expectedMatches)
				return expectedMatches
			},
		},
		{
			fixtureImage: "image-alpine-match-coverage",
			expectedFn: func(theSource source.Source, catalog *syftPkg.Catalog, theStore *mockStore) match.Matches {
				expectedMatches := match.NewMatches()
				addAlpineMatches(t, theSource, catalog, theStore, &expectedMatches)
				return expectedMatches
			},
		},
	}

	for _, test := range tests {
		t.Run(test.fixtureImage, func(t *testing.T) {
			theStore := NewMockDbStore()

			_, cleanup := imagetest.GetFixtureImage(t, "docker-archive", test.fixtureImage)
			tarPath := imagetest.GetFixtureImageTarPath(t, test.fixtureImage)
			defer cleanup()

			userImage := "docker-archive:" + tarPath
			scopeOption := source.AllLayersScope

			// this is purely done to help setup mocks
			theSource, theCatalog, theDistro, err := syft.Catalog(userImage, scopeOption)
			if err != nil {
				t.Fatalf("could not get the source obj: %+v", err)
			}

			actualResults := grype.FindVulnerabilitiesForPackage(
				vulnerability.NewProviderFromStore(theStore),
				theDistro,
				pkg.FromCatalog(theCatalog)...,
			)

			// build expected matches from what's discovered from the catalog
			expectedMatches := test.expectedFn(theSource, theCatalog, theStore)

			// build expected match set...
			expectedMatchSet := map[string]string{}
			for eMatch := range expectedMatches.Enumerate() {
				// NOTE: this does not include all fields...
				expectedMatchSet[eMatch.Package.Name] = eMatch.String()
			}

			expectedCount := len(expectedMatchSet)

			// ensure that all matches are covered
			actualCount := 0
			for aMatch := range actualResults.Enumerate() {
				actualCount++
				observedMatchers.Add(aMatch.Matcher.String())
				value, ok := expectedMatchSet[aMatch.Package.Name]
				if !ok {
					t.Errorf("Package: %s was expected but not found", aMatch.Package.Name)
				}

				if value != aMatch.String() {
					dmp := diffmatchpatch.New()
					diffs := dmp.DiffMain(value, aMatch.String(), true)
					t.Errorf("mismatched output:\n%s", dmp.DiffPrettyText(diffs))
				}

			}

			if expectedCount != actualCount {
				t.Errorf("expected %d matches but got %d matches", expectedCount, actualCount)
			}

		})
	}

	// ensure that integration test cases stay in sync with the implemented matchers

	observedMatchers.Remove(match.UnknownMatcherType.String())
	definedMatchers.Remove(match.UnknownMatcherType.String())

	if len(observedMatchers) != len(definedMatchers) {
		t.Errorf("matcher coverage incomplete (matchers=%d, coverage=%d)", len(definedMatchers), len(observedMatchers))
		for _, m := range definedMatchers.ToSlice() {
			t.Logf("  defined: %+v\n", m)
		}
		for _, m := range observedMatchers.ToSlice() {
			t.Logf("  found: %+v\n", m)
		}
	}

}
