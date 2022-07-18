package integration

import (
	"testing"

	"github.com/sergi/go-diff/diffmatchpatch"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype"
	"github.com/anchore/grype/grype/db"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/store"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal"
	"github.com/anchore/stereoscope/pkg/imagetest"
	"github.com/anchore/syft/syft"
	syftPkg "github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger"
	"github.com/anchore/syft/syft/source"
)

func addAlpineMatches(t *testing.T, theSource source.Source, catalog *syftPkg.Catalog, theStore *mockStore, theResult *match.Matches) {
	packages := catalog.PackagesByPath("/lib/apk/db/installed")
	if len(packages) != 1 {
		t.Logf("Alpine Packages: %+v", packages)
		t.Fatalf("problem with upstream syft cataloger (alpine)")
	}
	thePkg := pkg.New(packages[0])
	theVuln := theStore.backend["alpine:distro:alpine:3.12"][thePkg.Name][0]
	vulnObj, err := vulnerability.NewVulnerability(theVuln)
	if err != nil {
		t.Fatalf("failed to create vuln obj: %+v", err)
	}
	theResult.Add(match.Match{
		// note: we are matching on the secdb record, not NVD primarily

		Vulnerability: *vulnObj,
		Package:       thePkg,
		Details: []match.Detail{
			{
				Type:       match.ExactDirectMatch,
				Confidence: 1.0,
				SearchedBy: map[string]interface{}{
					"cpe": "cpe:2.3:*:*:libvncserver:0.9.9:*:*:*:*:*:*:*",
				},
				Found: map[string]interface{}{
					"cpes":       []string{"cpe:2.3:*:*:libvncserver:0.9.9:*:*:*:*:*:*:*"},
					"constraint": "< 0.9.10 (unknown)",
				},
				Matcher: match.ApkMatcher,
			},
		},
	})
}

func addJavascriptMatches(t *testing.T, theSource source.Source, catalog *syftPkg.Catalog, theStore *mockStore, theResult *match.Matches) {
	packages := catalog.PackagesByPath("/javascript/pkg-json/package.json")
	if len(packages) != 1 {
		t.Logf("Javascript Packages: %+v", packages)
		t.Fatalf("problem with upstream syft cataloger (javascript)")
	}
	thePkg := pkg.New(packages[0])
	theVuln := theStore.backend["github:language:javascript"][thePkg.Name][0]
	vulnObj, err := vulnerability.NewVulnerability(theVuln)
	if err != nil {
		t.Fatalf("failed to create vuln obj: %+v", err)
	}
	theResult.Add(match.Match{
		Vulnerability: *vulnObj,
		Package:       thePkg,
		Details: []match.Detail{
			{
				Type:       match.ExactDirectMatch,
				Confidence: 1.0,
				SearchedBy: map[string]interface{}{
					"language": "javascript",
				},
				Found: map[string]interface{}{
					"constraint": "< 3.2.1 (unknown)",
				},
				Matcher: match.JavascriptMatcher,
			},
		},
	})
}

func addPythonMatches(t *testing.T, theSource source.Source, catalog *syftPkg.Catalog, theStore *mockStore, theResult *match.Matches) {
	packages := catalog.PackagesByPath("/python/dist-info/METADATA")
	if len(packages) != 1 {
		for _, p := range packages {
			t.Logf("Python Package: %s %+v", p.ID(), p)
		}

		t.Fatalf("problem with upstream syft cataloger (python)")
	}
	thePkg := pkg.New(packages[0])
	normalizedName := theStore.normalizedPackageNames["github:language:python"][thePkg.Name]
	theVuln := theStore.backend["github:language:python"][normalizedName][0]
	vulnObj, err := vulnerability.NewVulnerability(theVuln)
	if err != nil {
		t.Fatalf("failed to create vuln obj: %+v", err)
	}
	theResult.Add(match.Match{

		Vulnerability: *vulnObj,
		Package:       thePkg,
		Details: []match.Detail{
			{
				Type:       match.ExactDirectMatch,
				Confidence: 1.0,
				SearchedBy: map[string]interface{}{
					"language": "python",
				},
				Found: map[string]interface{}{
					"constraint": "< 2.6.2 (python)",
				},
				Matcher: match.PythonMatcher,
			},
		},
	})
}

func addDotnetMatches(t *testing.T, theSource source.Source, catalog *syftPkg.Catalog, theStore *mockStore, theResult *match.Matches) {
	packages := catalog.PackagesByPath("/dotnet/TestLibrary.deps.json")
	if len(packages) != 1 {
		for _, p := range packages {
			t.Logf("Dotnet Package: %s %+v", p.ID(), p)
		}

		t.Fatalf("problem with upstream syft cataloger (dotnet)")
	}
	thePkg := pkg.New(packages[0])
	normalizedName := theStore.normalizedPackageNames["github:language:dotnet"][thePkg.Name]
	theVuln := theStore.backend["github:language:dotnet"][normalizedName][0]
	vulnObj, err := vulnerability.NewVulnerability(theVuln)
	if err != nil {
		t.Fatalf("failed to create vuln obj: %+v", err)
	}
	theResult.Add(match.Match{

		Vulnerability: *vulnObj,
		Package:       thePkg,
		Details: []match.Detail{
			{
				Type:       match.ExactDirectMatch,
				Confidence: 1.0,
				SearchedBy: map[string]interface{}{
					"language": "dotnet",
				},
				Found: map[string]interface{}{
					"constraint": ">= 3.7.0.0, < 3.7.12.0 (dotnet)",
				},
				Matcher: match.DotnetMatcher,
			},
		},
	})
}

func addRubyMatches(t *testing.T, theSource source.Source, catalog *syftPkg.Catalog, theStore *mockStore, theResult *match.Matches) {
	packages := catalog.PackagesByPath("/ruby/specifications/bundler.gemspec")
	if len(packages) != 1 {
		t.Logf("Ruby Packages: %+v", packages)
		t.Fatalf("problem with upstream syft cataloger (ruby)")
	}
	thePkg := pkg.New(packages[0])
	theVuln := theStore.backend["github:language:ruby"][thePkg.Name][0]
	vulnObj, err := vulnerability.NewVulnerability(theVuln)
	if err != nil {
		t.Fatalf("failed to create vuln obj: %+v", err)
	}
	theResult.Add(match.Match{

		Vulnerability: *vulnObj,
		Package:       thePkg,
		Details: []match.Detail{
			{
				Type:       match.ExactDirectMatch,
				Confidence: 1.0,
				SearchedBy: map[string]interface{}{
					"language": "ruby",
				},
				Found: map[string]interface{}{
					"constraint": "> 4.0.0, <= 4.1.1 (gemfile)",
				},
				Matcher: match.RubyGemMatcher,
			},
		},
	})
}

func addGolangMatches(t *testing.T, theSource source.Source, catalog *syftPkg.Catalog, theStore *mockStore, theResult *match.Matches) {
	packages := catalog.PackagesByPath("/go-app")
	if len(packages) != 2 {
		t.Logf("Golang Packages: %+v", packages)
		t.Fatalf("problem with upstream syft cataloger (golang)")
	}

	for _, p := range packages {
		thePkg := pkg.New(p)
		theVuln := theStore.backend["github:language:go"][p.Name][0]
		vulnObj, err := vulnerability.NewVulnerability(theVuln)
		if err != nil {
			t.Fatalf("failed to create vuln obj: %+v", err)
		}

		// no vuln match supported for main module
		if p.Name != "github.com/anchore/coverage" {
			theResult.Add(match.Match{
				Vulnerability: *vulnObj,
				Package:       thePkg,
				Details: []match.Detail{
					{
						Type:       match.ExactDirectMatch,
						Confidence: 1.0,
						SearchedBy: map[string]interface{}{
							"langauge": "go",
						},
						Found: map[string]interface{}{
							"constraint": " < 1.4.0 (golang)",
						},
						Matcher: match.GoModuleMatcher,
					},
				},
			})
		}
	}
}

func addJavaMatches(t *testing.T, theSource source.Source, catalog *syftPkg.Catalog, theStore *mockStore, theResult *match.Matches) {
	packages := make([]syftPkg.Package, 0)
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

	theVuln := theStore.backend["github:language:java"][lookup][0]
	vulnObj, err := vulnerability.NewVulnerability(theVuln)
	if err != nil {
		t.Fatalf("failed to create vuln obj: %+v", err)
	}
	theResult.Add(match.Match{
		Vulnerability: *vulnObj,
		Package:       thePkg,
		Details: []match.Detail{
			{
				Type:       match.ExactDirectMatch,
				Confidence: 1.0,
				SearchedBy: map[string]interface{}{
					"language": "java",
				},
				Found: map[string]interface{}{
					"constraint": ">= 0.0.1, < 1.2.0 (unknown)",
				},
				Matcher: match.JavaMatcher,
			},
		},
	})
}

func addDpkgMatches(t *testing.T, theSource source.Source, catalog *syftPkg.Catalog, theStore *mockStore, theResult *match.Matches) {
	packages := catalog.PackagesByPath("/var/lib/dpkg/status")
	if len(packages) != 1 {
		t.Logf("Dpkg Packages: %+v", packages)
		t.Fatalf("problem with upstream syft cataloger (dpkg)")
	}
	thePkg := pkg.New(packages[0])
	// NOTE: this is an indirect match, in typical debian style
	theVuln := theStore.backend["debian:distro:debian:8"][thePkg.Name+"-dev"][0]
	vulnObj, err := vulnerability.NewVulnerability(theVuln)
	if err != nil {
		t.Fatalf("failed to create vuln obj: %+v", err)
	}
	theResult.Add(match.Match{

		Vulnerability: *vulnObj,
		Package:       thePkg,
		Details: []match.Detail{
			{
				Type:       match.ExactIndirectMatch,
				Confidence: 1.0,
				SearchedBy: map[string]interface{}{
					"distro": map[string]string{
						"type":    "debian",
						"version": "8",
					},
				},
				Found: map[string]interface{}{
					"constraint": "<= 1.8.2 (deb)",
				},
				Matcher: match.DpkgMatcher,
			},
		},
	})
}

func addPortageMatches(t *testing.T, theSource source.Source, catalog *syftPkg.Catalog, theStore *mockStore, theResult *match.Matches) {
	packages := catalog.PackagesByPath("/var/db/pkg/app-containers/skopeo-1.5.1/CONTENTS")
	if len(packages) != 1 {
		t.Logf("Portage Packages: %+v", packages)
		t.Fatalf("problem with upstream syft cataloger (portage)")
	}
	thePkg := pkg.New(packages[0])
	theVuln := theStore.backend["gentoo:distro:gentoo:portage"][thePkg.Name][0]
	vulnObj, err := vulnerability.NewVulnerability(theVuln)
	if err != nil {
		t.Fatalf("failed to create vuln obj: %+v", err)
	}
	theResult.Add(match.Match{
		Vulnerability: *vulnObj,
		Package:       thePkg,
		Details: []match.Detail{
			{
				Type:       match.ExactDirectMatch,
				Confidence: 1.0,
				SearchedBy: map[string]interface{}{
					"distro": map[string]string{
						"type":    "gentoo",
						"version": "portage",
					},
				},
				Found: map[string]interface{}{
					"constraint": "<= 1.6.0 (gentoo)",
				},
				Matcher: match.PortageMatcher,
			},
		},
	})
}

func addRhelMatches(t *testing.T, theSource source.Source, catalog *syftPkg.Catalog, theStore *mockStore, theResult *match.Matches) {
	packages := catalog.PackagesByPath("/var/lib/rpm/Packages")
	if len(packages) != 1 {
		t.Logf("RPMDB Packages: %+v", packages)
		t.Fatalf("problem with upstream syft cataloger (RPMDB)")
	}
	thePkg := pkg.New(packages[0])
	theVuln := theStore.backend["redhat:distro:redhat:8"][thePkg.Name][0]
	vulnObj, err := vulnerability.NewVulnerability(theVuln)
	if err != nil {
		t.Fatalf("failed to create vuln obj: %+v", err)
	}
	theResult.Add(match.Match{

		Vulnerability: *vulnObj,
		Package:       thePkg,
		Details: []match.Detail{
			{
				Type:       match.ExactDirectMatch,
				Confidence: 1.0,
				SearchedBy: map[string]interface{}{
					"distro": map[string]string{
						"type":    "centos",
						"version": "8",
					},
				},
				Found: map[string]interface{}{
					"constraint": "<= 1.0.42 (rpm)",
				},
				Matcher: match.RpmDBMatcher,
			},
		},
	})
}

func addSlesMatches(t *testing.T, theSource source.Source, catalog *syftPkg.Catalog, theStore *mockStore, theResult *match.Matches) {
	packages := catalog.PackagesByPath("/var/lib/rpm/Packages")
	if len(packages) != 1 {
		t.Logf("Sles Packages: %+v", packages)
		t.Fatalf("problem with upstream syft cataloger (RPMDB)")
	}
	thePkg := pkg.New(packages[0])
	theVuln := theStore.backend["redhat:distro:redhat:8"][thePkg.Name][0]
	vulnObj, err := vulnerability.NewVulnerability(theVuln)
	if err != nil {
		t.Fatalf("failed to create vuln obj: %+v", err)
	}
	theResult.Add(match.Match{
		Vulnerability: *vulnObj,
		Package:       thePkg,
		Details: []match.Detail{
			{
				Type:       match.ExactDirectMatch,
				Confidence: 1.0,
				SearchedBy: map[string]interface{}{
					"distro": map[string]string{
						"type":    "sles",
						"version": "12.5",
					},
				},
				Found: map[string]interface{}{
					"constraint": "<= 1.0.42 (rpm)",
				},
				Matcher: match.RpmDBMatcher,
			},
		},
	})
}

func TestMatchByImage(t *testing.T) {
	observedMatchers := internal.NewStringSet()
	definedMatchers := internal.NewStringSet()
	for _, l := range match.AllMatcherTypes {
		definedMatchers.Add(string(l))
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
				addDotnetMatches(t, theSource, catalog, theStore, &expectedMatches)
				addGolangMatches(t, theSource, catalog, theStore, &expectedMatches)
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
		{
			fixtureImage: "image-sles-match-coverage",
			expectedFn: func(theSource source.Source, catalog *syftPkg.Catalog, theStore *mockStore) match.Matches {
				expectedMatches := match.NewMatches()
				addSlesMatches(t, theSource, catalog, theStore, &expectedMatches)
				return expectedMatches
			},
		},
		{
			fixtureImage: "image-portage-match-coverage",
			expectedFn: func(theSource source.Source, catalog *syftPkg.Catalog, theStore *mockStore) match.Matches {
				expectedMatches := match.NewMatches()
				addPortageMatches(t, theSource, catalog, theStore, &expectedMatches)
				return expectedMatches
			},
		},
	}

	for _, test := range tests {
		t.Run(test.fixtureImage, func(t *testing.T) {
			theStore := newMockDbStore()

			imagetest.GetFixtureImage(t, "docker-archive", test.fixtureImage)
			tarPath := imagetest.GetFixtureImageTarPath(t, test.fixtureImage)

			userImage := "docker-archive:" + tarPath

			sourceInput, err := source.ParseInput(userImage, "", true)
			if err != nil {
				t.Fatalf("unable to parse user input %+v", err)
			}

			// this is purely done to help setup mocks
			theSource, cleanup, err := source.New(*sourceInput, nil, nil)
			if err != nil {
				t.Fatalf("failed to determine image source: %+v", err)
			}
			defer cleanup()

			// TODO: relationships are not verified at this time
			config := cataloger.DefaultConfig()
			config.Search.Scope = source.SquashedScope

			theCatalog, _, theDistro, err := syft.CatalogPackages(theSource, config)
			if err != nil {
				t.Fatalf("could not get the source obj: %+v", err)
			}

			matchers := matcher.NewDefaultMatchers(matcher.Config{})

			vp, err := db.NewVulnerabilityProvider(theStore)
			require.NoError(t, err)
			ep := db.NewMatchExclusionProvider(theStore)
			store := store.Store{
				Provider:          vp,
				MetadataProvider:  nil,
				ExclusionProvider: ep,
			}

			actualResults := grype.FindVulnerabilitiesForPackage(store, theDistro, matchers, pkg.FromCatalog(theCatalog, pkg.ProviderConfig{}))

			// build expected matches from what's discovered from the catalog
			expectedMatches := test.expectedFn(*theSource, theCatalog, theStore)

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
				for _, details := range aMatch.Details {
					observedMatchers.Add(string(details.Matcher))
				}
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
	observedMatchers.Remove(string(match.UnknownMatcherType))
	definedMatchers.Remove(string(match.UnknownMatcherType))
	definedMatchers.Remove(string(match.MsrcMatcher))

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
