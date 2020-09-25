//+build integration

package integration

import (
	"testing"

	"github.com/anchore/grype/grype"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal"
	"github.com/anchore/stereoscope/pkg/imagetest"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/scope"
	"github.com/sergi/go-diff/diffmatchpatch"
)

func getPackagesByPath(t *testing.T, theScope scope.Scope, catalog *pkg.Catalog, thePath string) []*pkg.Package {
	t.Helper()
	refs, err := theScope.Resolver.FilesByGlob(thePath)
	if err != nil {
		t.Fatalf("could not get ref by path %q: %+v", thePath, err)
	}
	if len(refs) != 1 {
		t.Fatalf("unexpected paths for %q: %+v", thePath, refs)
	}
	return catalog.PackagesByFile(refs[0])
}

func addAlpineMatches(t *testing.T, theScope scope.Scope, catalog *pkg.Catalog, theStore *mockStore, theResult *match.Matches) {
	packages := getPackagesByPath(t, theScope, catalog, "/lib/apk/db/installed")
	if len(packages) != 1 {
		t.Logf("Alpine Packages: %+v", packages)
		t.Fatalf("problem with upstream syft cataloger (alpine)")
	}
	thePkg := packages[0]
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
		IndirectPackage: nil,
		Matcher:         match.ApkMatcher,
	})
}

func addJavascriptMatches(t *testing.T, theScope scope.Scope, catalog *pkg.Catalog, theStore *mockStore, theResult *match.Matches) {
	packages := getPackagesByPath(t, theScope, catalog, "/javascript/pkg-lock/package-lock.json")
	if len(packages) != 1 {
		t.Logf("Javascript Packages: %+v", packages)
		t.Fatalf("problem with upstream syft cataloger (javascript)")
	}
	thePkg := packages[0]
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
		IndirectPackage: nil,
		Matcher:         match.JavascriptMatcher,
	})
}

func addPythonMatches(t *testing.T, theScope scope.Scope, catalog *pkg.Catalog, theStore *mockStore, theResult *match.Matches) {
	packages := getPackagesByPath(t, theScope, catalog, "/python/dist-info/METADATA")
	if len(packages) != 1 {
		t.Logf("Python Packages: %+v", packages)
		t.Fatalf("problem with upstream syft cataloger (python)")
	}
	thePkg := packages[0]
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
		IndirectPackage: nil,
		Matcher:         match.PythonMatcher,
	})
}

func addRubyMatches(t *testing.T, theScope scope.Scope, catalog *pkg.Catalog, theStore *mockStore, theResult *match.Matches) {
	packages := getPackagesByPath(t, theScope, catalog, "/ruby/Gemfile.lock")
	if len(packages) != 1 {
		t.Logf("Ruby Packages: %+v", packages)
		t.Fatalf("problem with upstream syft cataloger (ruby)")
	}
	thePkg := packages[0]
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
		IndirectPackage: nil,
		Matcher:         match.RubyBundleMatcher,
	})
}

func addJavaMatches(t *testing.T, theScope scope.Scope, catalog *pkg.Catalog, theStore *mockStore, theResult *match.Matches) {
	packages := make([]*pkg.Package, 0)
	for p := range catalog.Enumerate(pkg.JavaPkg) {
		packages = append(packages, p)
	}
	if len(packages) != 2 { // 2, because there's a nested JAR inside the test fixture JAR
		t.Logf("Java Packages: %+v", packages)
		t.Fatalf("problem with upstream syft cataloger (java)")
	}
	thePkg := packages[0]

	groupId := thePkg.Metadata.(pkg.JavaMetadata).PomProperties.GroupID
	lookup := groupId + ":" + thePkg.Name

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
		IndirectPackage: nil,
		Matcher:         match.JavaMatcher,
	})
}

func addDpkgMatches(t *testing.T, theScope scope.Scope, catalog *pkg.Catalog, theStore *mockStore, theResult *match.Matches) {
	packages := getPackagesByPath(t, theScope, catalog, "/var/lib/dpkg/status")
	if len(packages) != 1 {
		t.Logf("Dpkg Packages: %+v", packages)
		t.Fatalf("problem with upstream syft cataloger (dpkg)")
	}
	thePkg := packages[0]
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
		IndirectPackage: nil,
		Matcher:         match.DpkgMatcher,
	})
}

func addRhelMatches(t *testing.T, theScope scope.Scope, catalog *pkg.Catalog, theStore *mockStore, theResult *match.Matches) {
	packages := getPackagesByPath(t, theScope, catalog, "/var/lib/rpm/Packages")
	if len(packages) != 1 {
		t.Logf("RPMDB Packages: %+v", packages)
		t.Fatalf("problem with upstream syft cataloger (RPMDB)")
	}
	thePkg := packages[0]
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
		IndirectPackage: nil,
		Matcher:         match.RpmDBMatcher,
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
		expectedFn   func(scope.Scope, *pkg.Catalog, *mockStore) match.Matches
	}{
		{
			fixtureImage: "image-debian-match-coverage",
			expectedFn: func(theScope scope.Scope, catalog *pkg.Catalog, theStore *mockStore) match.Matches {
				expectedMatches := match.NewMatches()
				addPythonMatches(t, theScope, catalog, theStore, &expectedMatches)
				addRubyMatches(t, theScope, catalog, theStore, &expectedMatches)
				addJavaMatches(t, theScope, catalog, theStore, &expectedMatches)
				addDpkgMatches(t, theScope, catalog, theStore, &expectedMatches)
				addJavascriptMatches(t, theScope, catalog, theStore, &expectedMatches)
				return expectedMatches
			},
		},
		{
			fixtureImage: "image-centos-match-coverage",
			expectedFn: func(theScope scope.Scope, catalog *pkg.Catalog, theStore *mockStore) match.Matches {
				expectedMatches := match.NewMatches()
				addRhelMatches(t, theScope, catalog, theStore, &expectedMatches)
				return expectedMatches
			},
		},
		{
			fixtureImage: "image-alpine-match-coverage",
			expectedFn: func(theScope scope.Scope, catalog *pkg.Catalog, theStore *mockStore) match.Matches {
				expectedMatches := match.NewMatches()
				addAlpineMatches(t, theScope, catalog, theStore, &expectedMatches)
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

			actualResults, catalog, theScope, err := grype.FindVulnerabilities(
				vulnerability.NewProviderFromStore(theStore),
				"docker-archive:"+tarPath,
				scope.AllLayersScope,
			)
			if err != nil {
				t.Fatalf("failed to find vulnerabilities: %+v", err)
			}

			// build expected matches from what's discovered from the catalog
			expectedMatches := test.expectedFn(*theScope, catalog, theStore)

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
	}

}
