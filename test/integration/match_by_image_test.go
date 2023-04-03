package integration

import (
	"sort"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
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
	require.NoError(t, err)

	theResult.Add(match.Match{
		// note: we are matching on the secdb record, not NVD primarily

		Vulnerability: *vulnObj,
		Package:       thePkg,
		Details: []match.Detail{
			{
				// note: the input pURL has an upstream reference (redundant)
				Type: "exact-indirect-match",
				SearchedBy: map[string]any{
					"distro": map[string]string{
						"type":    "alpine",
						"version": "3.12.0",
					},
					"namespace": "alpine:distro:alpine:3.12",
					"package": map[string]string{
						"name":    "libvncserver",
						"version": "0.9.9",
					},
				},
				Found: map[string]any{
					"versionConstraint": "< 0.9.10 (unknown)",
					"vulnerabilityID":   "CVE-alpine-libvncserver",
				},
				Matcher:    "apk-matcher",
				Confidence: 1,
			},
			{
				Type:       match.ExactDirectMatch,
				Confidence: 1.0,
				SearchedBy: map[string]interface{}{
					"distro": map[string]string{
						"type":    "alpine",
						"version": "3.12.0",
					},
					"namespace": "alpine:distro:alpine:3.12",
					"package": map[string]string{
						"name":    "libvncserver",
						"version": "0.9.9",
					},
				},
				Found: map[string]interface{}{
					"versionConstraint": "< 0.9.10 (unknown)",
					"vulnerabilityID":   vulnObj.ID,
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
	require.NoError(t, err)

	theResult.Add(match.Match{
		Vulnerability: *vulnObj,
		Package:       thePkg,
		Details: []match.Detail{
			{
				Type:       match.ExactDirectMatch,
				Confidence: 1.0,
				SearchedBy: map[string]interface{}{
					"language":  "javascript",
					"namespace": "github:language:javascript",
				},
				Found: map[string]interface{}{
					"versionConstraint": "> 5, < 7.2.1 (unknown)",
					"vulnerabilityID":   vulnObj.ID,
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
	require.NoError(t, err)

	theResult.Add(match.Match{

		Vulnerability: *vulnObj,
		Package:       thePkg,
		Details: []match.Detail{
			{
				Type:       match.ExactDirectMatch,
				Confidence: 1.0,
				SearchedBy: map[string]interface{}{
					"language":  "python",
					"namespace": "github:language:python",
				},
				Found: map[string]interface{}{
					"versionConstraint": "< 2.6.2 (python)",
					"vulnerabilityID":   vulnObj.ID,
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
	require.NoError(t, err)

	theResult.Add(match.Match{

		Vulnerability: *vulnObj,
		Package:       thePkg,
		Details: []match.Detail{
			{
				Type:       match.ExactDirectMatch,
				Confidence: 1.0,
				SearchedBy: map[string]interface{}{
					"language":  "dotnet",
					"namespace": "github:language:dotnet",
				},
				Found: map[string]interface{}{
					"versionConstraint": ">= 3.7.0.0, < 3.7.12.0 (unknown)",
					"vulnerabilityID":   vulnObj.ID,
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
	require.NoError(t, err)

	theResult.Add(match.Match{

		Vulnerability: *vulnObj,
		Package:       thePkg,
		Details: []match.Detail{
			{
				Type:       match.ExactDirectMatch,
				Confidence: 1.0,
				SearchedBy: map[string]interface{}{
					"language":  "ruby",
					"namespace": "github:language:ruby",
				},
				Found: map[string]interface{}{
					"versionConstraint": "> 2.0.0, <= 2.1.4 (unknown)",
					"vulnerabilityID":   vulnObj.ID,
				},
				Matcher: match.RubyGemMatcher,
			},
		},
	})
}

func addGolangMatches(t *testing.T, theSource source.Source, catalog *syftPkg.Catalog, theStore *mockStore, theResult *match.Matches) {
	modPackages := catalog.PackagesByPath("/golang/go.mod")
	if len(modPackages) != 1 {
		t.Logf("Golang Mod Packages: %+v", modPackages)
		t.Fatalf("problem with upstream syft cataloger (golang)")
	}

	binPackages := catalog.PackagesByPath("/go-app")
	if len(binPackages) != 2 {
		t.Logf("Golang Bin Packages: %+v", binPackages)
		t.Fatalf("problem with upstream syft cataloger (golang)")
	}

	var packages []syftPkg.Package
	packages = append(packages, modPackages...)
	packages = append(packages, binPackages...)

	for _, p := range packages {
		// no vuln match supported for main module
		if p.Name == "github.com/anchore/coverage" {
			continue
		}

		thePkg := pkg.New(p)
		theVuln := theStore.backend["github:language:go"][thePkg.Name][0]
		vulnObj, err := vulnerability.NewVulnerability(theVuln)
		require.NoError(t, err)

		theResult.Add(match.Match{
			Vulnerability: *vulnObj,
			Package:       thePkg,
			Details: []match.Detail{
				{
					Type:       match.ExactDirectMatch,
					Confidence: 1.0,
					SearchedBy: map[string]interface{}{
						"language":  "go",
						"namespace": "github:language:go",
					},
					Found: map[string]interface{}{
						"versionConstraint": "< 1.4.0 (unknown)",
						"vulnerabilityID":   vulnObj.ID,
					},
					Matcher: match.GoModuleMatcher,
				},
			},
		})

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
	require.NoError(t, err)

	theResult.Add(match.Match{
		Vulnerability: *vulnObj,
		Package:       thePkg,
		Details: []match.Detail{
			{
				Type:       match.ExactDirectMatch,
				Confidence: 1.0,
				SearchedBy: map[string]interface{}{
					"language":  "java",
					"namespace": "github:language:java",
				},
				Found: map[string]interface{}{
					"versionConstraint": ">= 0.0.1, < 1.2.0 (unknown)",
					"vulnerabilityID":   vulnObj.ID,
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
	require.NoError(t, err)

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
					"namespace": "debian:distro:debian:8",
					"package": map[string]string{
						"name":    "apt-dev",
						"version": "1.8.2",
					},
				},
				Found: map[string]interface{}{
					"versionConstraint": "<= 1.8.2 (deb)",
					"vulnerabilityID":   vulnObj.ID,
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
	theVuln := theStore.backend["gentoo:distro:gentoo:2.8"][thePkg.Name][0]
	vulnObj, err := vulnerability.NewVulnerability(theVuln)
	require.NoError(t, err)

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
						"version": "2.8",
					},
					"namespace": "gentoo:distro:gentoo:2.8",
					"package": map[string]string{
						"name":    "app-containers/skopeo",
						"version": "1.5.1",
					},
				},
				Found: map[string]interface{}{
					"versionConstraint": "< 1.6.0 (unknown)",
					"vulnerabilityID":   vulnObj.ID,
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
	require.NoError(t, err)

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
					"namespace": "redhat:distro:redhat:8",
					"package": map[string]string{
						"name":    "dive",
						"version": "0:0.9.2-1",
					},
				},
				Found: map[string]interface{}{
					"versionConstraint": "<= 1.0.42 (rpm)",
					"vulnerabilityID":   vulnObj.ID,
				},
				Matcher: match.RpmMatcher,
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
	require.NoError(t, err)

	vulnObj.Namespace = "sles:distro:sles:12.5"
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
					"namespace": "sles:distro:sles:12.5",
					"package": map[string]string{
						"name":    "dive",
						"version": "0:0.9.2-1",
					},
				},
				Found: map[string]interface{}{
					"versionConstraint": "<= 1.0.42 (rpm)",
					"vulnerabilityID":   vulnObj.ID,
				},
				Matcher: match.RpmMatcher,
			},
		},
	})
}

func addHaskellMatches(t *testing.T, theSource source.Source, catalog *syftPkg.Catalog, theStore *mockStore, theResult *match.Matches) {
	packages := catalog.PackagesByPath("/haskell/stack.yaml")
	if len(packages) < 1 {
		t.Logf("Haskel Packages: %+v", packages)
		t.Fatalf("problem with upstream syft cataloger (haskell)")
	}
	thePkg := pkg.New(packages[0])
	theVuln := theStore.backend["github:language:haskell"][strings.ToLower(thePkg.Name)][0]
	vulnObj, err := vulnerability.NewVulnerability(theVuln)
	require.NoError(t, err)

	theResult.Add(match.Match{
		Vulnerability: *vulnObj,
		Package:       thePkg,
		Details: []match.Detail{
			{
				Type:       match.ExactDirectMatch,
				Confidence: 1.0,
				SearchedBy: map[string]any{
					"language":  "haskell",
					"namespace": "github:language:haskell",
				},
				Found: map[string]any{
					"versionConstraint": "< 0.9.0 (unknown)",
					"vulnerabilityID":   "CVE-haskell-sample",
				},
				Matcher: match.StockMatcher,
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
				addHaskellMatches(t, theSource, catalog, theStore, &expectedMatches)
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

			sourceInput, err := source.ParseInput(userImage, "")
			require.NoError(t, err)

			// this is purely done to help setup mocks
			theSource, cleanup, err := source.New(*sourceInput, nil, nil)
			require.NoError(t, err)
			defer cleanup()

			// TODO: relationships are not verified at this time
			config := cataloger.DefaultConfig()
			config.Search.Scope = source.SquashedScope

			// enable all catalogers to cover non default cases
			config.Catalogers = []string{"all"}

			theCatalog, _, theDistro, err := syft.CatalogPackages(theSource, config)
			require.NoError(t, err)

			matchers := matcher.NewDefaultMatchers(matcher.Config{})

			vp, err := db.NewVulnerabilityProvider(theStore)
			require.NoError(t, err)
			mp := db.NewVulnerabilityMetadataProvider(theStore)
			ep := db.NewMatchExclusionProvider(theStore)
			str := store.Store{
				Provider:          vp,
				MetadataProvider:  mp,
				ExclusionProvider: ep,
			}

			actualResults := grype.FindVulnerabilitiesForPackage(str, theDistro, matchers, pkg.FromCatalog(theCatalog, pkg.SynthesisConfig{}))

			for _, m := range actualResults.Sorted() {
				for _, d := range m.Details {
					observedMatchers.Add(string(d.Matcher))
				}
			}

			// build expected matches from what's discovered from the catalog
			expectedMatches := test.expectedFn(*theSource, theCatalog, theStore)

			assertMatches(t, expectedMatches.Sorted(), actualResults.Sorted())
		})
	}

	// ensure that integration test cases stay in sync with the implemented matchers
	observedMatchers.Remove(string(match.StockMatcher))
	definedMatchers.Remove(string(match.StockMatcher))
	definedMatchers.Remove(string(match.MsrcMatcher))

	if len(observedMatchers) != len(definedMatchers) {
		t.Errorf("matcher coverage incomplete (matchers=%d, coverage=%d)", len(definedMatchers), len(observedMatchers))
		defs := definedMatchers.ToSlice()
		sort.Strings(defs)
		obs := observedMatchers.ToSlice()
		sort.Strings(obs)

		t.Log(cmp.Diff(defs, obs))
	}

}

func assertMatches(t *testing.T, expected, actual []match.Match) {
	t.Helper()
	var opts = []cmp.Option{
		cmpopts.IgnoreFields(vulnerability.Vulnerability{}, "Constraint"),
		cmpopts.IgnoreFields(pkg.Package{}, "Locations"),
		cmpopts.SortSlices(func(a, b match.Match) bool {
			return a.Package.ID < b.Package.ID
		}),
	}

	if diff := cmp.Diff(expected, actual, opts...); diff != "" {
		t.Errorf("mismatch (-want +got):\n%s", diff)
	}
}
