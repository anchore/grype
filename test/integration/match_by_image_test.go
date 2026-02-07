package integration

import (
	"context"
	"sort"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype"
	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher"
	"github.com/anchore/grype/grype/matcher/dotnet"
	"github.com/anchore/grype/grype/matcher/golang"
	"github.com/anchore/grype/grype/matcher/java"
	"github.com/anchore/grype/grype/matcher/javascript"
	"github.com/anchore/grype/grype/matcher/python"
	"github.com/anchore/grype/grype/matcher/ruby"
	"github.com/anchore/grype/grype/matcher/rust"
	"github.com/anchore/grype/grype/matcher/stock"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/search"
	"github.com/anchore/grype/grype/vex"
	vexStatus "github.com/anchore/grype/grype/vex/status"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/stringutil"
	"github.com/anchore/stereoscope/pkg/imagetest"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/cataloging/pkgcataloging"
	"github.com/anchore/syft/syft/cpe"
	syftPkg "github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

func addAlpineMatches(t *testing.T, theSource source.Source, catalog *syftPkg.Collection, provider vulnerability.Provider, theResult *match.Matches) {
	packages := catalog.PackagesByPath("/lib/apk/db/installed")
	if len(packages) != 3 {
		t.Logf("Alpine Packages: %+v", packages)
		t.Fatalf("problem with upstream syft cataloger (alpine)")
	}
	thePkg := pkg.New(packages[0])
	vulns, err := provider.FindVulnerabilities(byNamespace("alpine:distro:alpine:3.12"), search.ByPackageName(thePkg.Name))
	require.NoError(t, err)
	require.NotEmpty(t, vulns)
	vulnObj := vulns[0]

	theResult.Add(match.Match{
		// note: we are matching on the secdb record, not NVD primarily

		Vulnerability: vulnObj,
		Package:       thePkg,
		Details: []match.Detail{
			{
				Type:       match.ExactDirectMatch,
				Confidence: 1.0,
				SearchedBy: match.DistroParameters{
					Distro: match.DistroIdentification{
						Type:    "alpine",
						Version: "3.12.0",
					},
					Namespace: "alpine:distro:alpine:3.12",
					Package: match.PackageParameter{
						Name:    "libvncserver",
						Version: "0.9.9",
					},
				},
				Found: match.DistroResult{
					VersionConstraint: "< 0.9.10 (unknown)",
					VulnerabilityID:   vulnObj.ID,
				},
				Matcher: match.ApkMatcher,
			},
			{
				// note: the input pURL has an upstream reference (redundant)
				Type: match.ExactIndirectMatch,
				SearchedBy: match.DistroParameters{
					Distro: match.DistroIdentification{
						Type:    "alpine",
						Version: "3.12.0",
					},
					Namespace: "alpine:distro:alpine:3.12",
					Package: match.PackageParameter{
						Name:    "libvncserver",
						Version: "0.9.9",
					},
				},
				Found: match.DistroResult{
					VersionConstraint: "< 0.9.10 (unknown)",
					VulnerabilityID:   "CVE-2024-0000",
				},
				Matcher:    match.ApkMatcher,
				Confidence: 1,
			},
		},
	})
}

func addJavascriptMatches(t *testing.T, theSource source.Source, catalog *syftPkg.Collection, provider vulnerability.Provider, theResult *match.Matches) {
	packages := catalog.PackagesByPath("/javascript/pkg-json/package.json")
	if len(packages) != 1 {
		t.Logf("Javascript Packages: %+v", packages)
		t.Fatalf("problem with upstream syft cataloger (javascript)")
	}
	thePkg := pkg.New(packages[0])
	vulns, err := provider.FindVulnerabilities(byNamespace("github:language:javascript"), search.ByPackageName(thePkg.Name))
	require.NoError(t, err)
	require.NotEmpty(t, vulns)
	vulnObj := vulns[0]

	theResult.Add(match.Match{
		Vulnerability: vulnObj,
		Package:       thePkg,
		Details: []match.Detail{
			{
				Type:       match.ExactDirectMatch,
				Confidence: 1.0,
				SearchedBy: match.EcosystemParameters{
					Language:  "javascript",
					Namespace: "github:language:javascript",
					Package: match.PackageParameter{
						Name:    thePkg.Name,
						Version: thePkg.Version,
					},
				},
				Found: match.EcosystemResult{
					VersionConstraint: "> 5, < 7.2.1 (unknown)",
					VulnerabilityID:   vulnObj.ID,
				},
				Matcher: match.JavascriptMatcher,
			},
		},
	})
}

func addPythonMatches(t *testing.T, theSource source.Source, catalog *syftPkg.Collection, provider vulnerability.Provider, theResult *match.Matches) {
	packages := catalog.PackagesByPath("/python/dist-info/METADATA")
	if len(packages) != 1 {
		for _, p := range packages {
			t.Logf("Python Package: %s %+v", p.ID(), p)
		}

		t.Fatalf("problem with upstream syft cataloger (python)")
	}
	thePkg := pkg.New(packages[0])
	vulns, err := provider.FindVulnerabilities(byNamespace("github:language:python"), search.ByPackageName(strings.ToLower(thePkg.Name)))
	require.NoError(t, err)
	require.NotEmpty(t, vulns)
	vulnObj := vulns[0]

	theResult.Add(match.Match{
		Vulnerability: vulnObj,
		Package:       thePkg,
		Details: []match.Detail{
			{
				Type:       match.ExactDirectMatch,
				Confidence: 1.0,
				SearchedBy: match.EcosystemParameters{
					Language:  "python",
					Namespace: "github:language:python",
					Package: match.PackageParameter{
						Name:    provider.PackageSearchNames(thePkg)[0], // there is normalization that should be accounted for
						Version: thePkg.Version,
					},
				},
				Found: match.EcosystemResult{
					VersionConstraint: "< 2.6.2 (python)",
					VulnerabilityID:   vulnObj.ID,
				},
				Matcher: match.PythonMatcher,
			},
		},
	})
}

func addDotnetMatches(t *testing.T, theSource source.Source, catalog *syftPkg.Collection, provider vulnerability.Provider, theResult *match.Matches) {
	packages := catalog.PackagesByPath("/dotnet/TestLibrary.deps.json")
	// 55caef8df7ac822e Pkg(name="TestLibrary" version="1.0.0" type="dotnet" id="55caef8df7ac822e")
	// 0012329cdebba0ea Pkg(name="AWSSDK.Core" version="3.7.10.6" type="dotnet" id="0012329cdebba0ea")
	// 07ec6fb2adb2cf8f Pkg(name="Microsoft.Extensions.DependencyInjection.Abstractions" version="6.0.0" type="dotnet" id="07ec6fb2adb2cf8f")
	// ff03e77b91acca32 Pkg(name="Microsoft.Extensions.DependencyInjection" version="6.0.0" type="dotnet" id="ff03e77b91acca32")
	// a1ea42c8f064083e Pkg(name="Microsoft.Extensions.Logging.Abstractions" version="6.0.0" type="dotnet" id="a1ea42c8f064083e")
	// aaef85a2649e5d15 Pkg(name="Microsoft.Extensions.Logging" version="6.0.0" type="dotnet" id="aaef85a2649e5d15")
	// 4af0fb6a81ba0423 Pkg(name="Microsoft.Extensions.Options" version="6.0.0" type="dotnet" id="4af0fb6a81ba0423")
	// cb41a8aefdf40c3a Pkg(name="Microsoft.Extensions.Primitives" version="6.0.0" type="dotnet" id="cb41a8aefdf40c3a")
	// 5ee80fba9caa3ab3 Pkg(name="Newtonsoft.Json" version="13.0.1" type="dotnet" id="5ee80fba9caa3ab3")
	// df4b5dc73acd1f36 Pkg(name="Serilog.Sinks.Console" version="4.0.1" type="dotnet" id="df4b5dc73acd1f36")
	// 023b9ba74c5c5ef5 Pkg(name="Serilog" version="2.10.0" type="dotnet" id="023b9ba74c5c5ef5")
	// 430e4d4304a3ff55 Pkg(name="System.Diagnostics.DiagnosticSource" version="6.0.0" type="dotnet" id="430e4d4304a3ff55")
	// 42021023d8f87661 Pkg(name="System.Runtime.CompilerServices.Unsafe" version="6.0.0" type="dotnet" id="42021023d8f87661")
	// 2bb01d8c22df1e95 Pkg(name="TestCommon" version="1.0.0" type="dotnet" id="2bb01d8c22df1e95")
	if len(packages) != 14 {
		for _, p := range packages {
			t.Logf("Dotnet Package: %s %+v", p.ID(), p)
		}

		t.Fatalf("problem with upstream syft cataloger (dotnet)")
	}
	thePkg := pkg.New(packages[1])
	vulns, err := provider.FindVulnerabilities(byNamespace("github:language:dotnet"), search.ByPackageName(strings.ToLower(thePkg.Name)))
	require.NoError(t, err)
	require.NotEmpty(t, vulns)
	vulnObj := vulns[0]

	theResult.Add(match.Match{
		Vulnerability: vulnObj,
		Package:       thePkg,
		Details: []match.Detail{
			{
				Type:       match.ExactDirectMatch,
				Confidence: 1.0,
				SearchedBy: match.EcosystemParameters{
					Language:  "dotnet",
					Namespace: "github:language:dotnet",
					Package: match.PackageParameter{
						Name:    thePkg.Name,
						Version: thePkg.Version,
					},
				},
				Found: match.EcosystemResult{
					VersionConstraint: ">= 3.7.0.0, < 3.7.12.0 (unknown)",
					VulnerabilityID:   vulnObj.ID,
				},
				Matcher: match.DotnetMatcher,
			},
		},
	})
}

func addRubyMatches(t *testing.T, theSource source.Source, catalog *syftPkg.Collection, provider vulnerability.Provider, theResult *match.Matches) {
	packages := catalog.PackagesByPath("/ruby/specifications/bundler.gemspec")
	if len(packages) != 1 {
		t.Logf("Ruby Packages: %+v", packages)
		t.Fatalf("problem with upstream syft cataloger (ruby)")
	}
	thePkg := pkg.New(packages[0])
	vulns, err := provider.FindVulnerabilities(byNamespace("github:language:ruby"), search.ByPackageName(thePkg.Name))
	require.NoError(t, err)
	require.NotEmpty(t, vulns)
	vulnObj := vulns[0]

	theResult.Add(match.Match{
		Vulnerability: vulnObj,
		Package:       thePkg,
		Details: []match.Detail{
			{
				Type:       match.ExactDirectMatch,
				Confidence: 1.0,
				SearchedBy: match.EcosystemParameters{
					Language:  "ruby",
					Namespace: "github:language:ruby",
					Package: match.PackageParameter{
						Name:    thePkg.Name,
						Version: thePkg.Version,
					},
				},
				Found: match.EcosystemResult{
					VersionConstraint: "> 2.0.0, <= 2.1.4 (unknown)",
					VulnerabilityID:   vulnObj.ID,
				},
				Matcher: match.RubyGemMatcher,
			},
		},
	})
}

func addGolangMatches(t *testing.T, theSource source.Source, catalog *syftPkg.Collection, provider vulnerability.Provider, theResult *match.Matches) {
	modPackages := catalog.PackagesByPath("/golang/go.mod")
	if len(modPackages) != 1 {
		t.Logf("Golang Mod Packages: %+v", modPackages)
		t.Fatalf("problem with upstream syft cataloger (golang)")
	}

	binPackages := catalog.PackagesByPath("/go-app")
	// contains 2 package + a single stdlib package
	if len(binPackages) != 3 {
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

		if p.Name == "stdlib" {
			continue
		}

		thePkg := pkg.New(p)
		vulns, err := provider.FindVulnerabilities(byNamespace("github:language:go"), search.ByPackageName(thePkg.Name))
		require.NoError(t, err)
		require.NotEmpty(t, vulns)
		vulnObj := vulns[0]

		theResult.Add(match.Match{
			Vulnerability: vulnObj,
			Package:       thePkg,
			Details: []match.Detail{
				{
					Type:       match.ExactDirectMatch,
					Confidence: 1.0,
					SearchedBy: match.EcosystemParameters{
						Language:  "go",
						Namespace: "github:language:go",
						Package: match.PackageParameter{
							Name:    thePkg.Name,
							Version: thePkg.Version,
						},
					},
					Found: match.EcosystemResult{
						VersionConstraint: "< 1.4.0 (unknown)",
						VulnerabilityID:   vulnObj.ID,
					},
					Matcher: match.GoModuleMatcher,
				},
			},
		})

	}
}

func addJavaMatches(t *testing.T, theSource source.Source, catalog *syftPkg.Collection, provider vulnerability.Provider, theResult *match.Matches) {
	packages := make([]syftPkg.Package, 0)
	for p := range catalog.Enumerate(syftPkg.JavaPkg) {
		packages = append(packages, p)
	}
	if len(packages) != 2 { // 2, because there's a nested JAR inside the test fixture JAR
		t.Logf("Java Packages: %+v", packages)
		t.Fatalf("problem with upstream syft cataloger (java)")
	}
	theSyftPkg := packages[0]

	groupId := theSyftPkg.Metadata.(syftPkg.JavaArchive).PomProperties.GroupID
	lookup := groupId + ":" + theSyftPkg.Name

	thePkg := pkg.New(theSyftPkg)
	vulns, err := provider.FindVulnerabilities(byNamespace("github:language:java"), search.ByPackageName(lookup))
	require.NoError(t, err)
	require.NotEmpty(t, vulns)
	vulnObj := vulns[0]

	theResult.Add(match.Match{
		Vulnerability: vulnObj,
		Package:       thePkg,
		Details: []match.Detail{
			{
				Type:       match.ExactDirectMatch,
				Confidence: 1.0,
				SearchedBy: match.EcosystemParameters{
					Language:  "java",
					Namespace: "github:language:java",
					Package: match.PackageParameter{
						Name:    provider.PackageSearchNames(thePkg)[0], // there is normalization that should be accounted for
						Version: thePkg.Version,
					},
				},
				Found: match.EcosystemResult{
					VersionConstraint: ">= 0.0.1, < 1.2.0 (unknown)",
					VulnerabilityID:   vulnObj.ID,
				},
				Matcher: match.JavaMatcher,
			},
		},
	})
}

func addDpkgMatches(t *testing.T, theSource source.Source, catalog *syftPkg.Collection, provider vulnerability.Provider, theResult *match.Matches) {
	packages := catalog.PackagesByPath("/var/lib/dpkg/status")
	if len(packages) != 1 {
		t.Logf("Dpkg Packages: %+v", packages)
		t.Fatalf("problem with upstream syft cataloger (dpkg)")
	}
	thePkg := pkg.New(packages[0])
	// NOTE: this is an indirect match, in typical debian style
	vulns, err := provider.FindVulnerabilities(byNamespace("debian:distro:debian:8"), search.ByPackageName(thePkg.Name+"-dev"))
	require.NoError(t, err)
	require.NotEmpty(t, vulns)
	vulnObj := vulns[0]

	theResult.Add(match.Match{
		Vulnerability: vulnObj,
		Package:       thePkg,
		Details: []match.Detail{
			{
				Type:       match.ExactIndirectMatch,
				Confidence: 1.0,
				SearchedBy: match.DistroParameters{
					Distro: match.DistroIdentification{
						Type:    "debian",
						Version: "8",
					},
					Namespace: "debian:distro:debian:8",
					Package: match.PackageParameter{
						Name:    "apt-dev",
						Version: "1.8.2",
					},
				},
				Found: match.DistroResult{
					VersionConstraint: "<= 1.8.2 (deb)",
					VulnerabilityID:   vulnObj.ID,
				},
				Matcher: match.DpkgMatcher,
			},
		},
	})
}

func addPortageMatches(t *testing.T, theSource source.Source, catalog *syftPkg.Collection, provider vulnerability.Provider, theResult *match.Matches) {
	packages := catalog.PackagesByPath("/var/db/pkg/app-containers/skopeo-1.5.1/CONTENTS")
	if len(packages) != 1 {
		t.Logf("Portage Packages: %+v", packages)
		t.Fatalf("problem with upstream syft cataloger (portage)")
	}
	thePkg := pkg.New(packages[0])
	vulns, err := provider.FindVulnerabilities(byNamespace("gentoo:distro:gentoo:2.8"), search.ByPackageName(thePkg.Name))
	require.NoError(t, err)
	require.NotEmpty(t, vulns)
	vulnObj := vulns[0]

	theResult.Add(match.Match{
		Vulnerability: vulnObj,
		Package:       thePkg,
		Details: []match.Detail{
			{
				Type:       match.ExactDirectMatch,
				Confidence: 1.0,
				SearchedBy: match.DistroParameters{
					Distro: match.DistroIdentification{
						Type:    "gentoo",
						Version: "2.8",
					},
					Namespace: "gentoo:distro:gentoo:2.8",
					Package: match.PackageParameter{
						Name:    "app-containers/skopeo",
						Version: "1.5.1",
					},
				},
				Found: match.DistroResult{
					VersionConstraint: "< 1.6.0 (unknown)",
					VulnerabilityID:   vulnObj.ID,
				},
				Matcher: match.PortageMatcher,
			},
		},
	})
}

func addRhelMatches(t *testing.T, theSource source.Source, catalog *syftPkg.Collection, provider vulnerability.Provider, theResult *match.Matches) {
	packages := catalog.PackagesByPath("/var/lib/rpm/Packages")
	if len(packages) != 1 {
		t.Logf("RPMDB Packages: %+v", packages)
		t.Fatalf("problem with upstream syft cataloger (RPMDB)")
	}
	thePkg := pkg.New(packages[0])
	vulns, err := provider.FindVulnerabilities(byNamespace("redhat:distro:redhat:8"), search.ByPackageName(thePkg.Name))
	require.NoError(t, err)
	require.NotEmpty(t, vulns)
	vulnObj := vulns[0]

	theResult.Add(match.Match{
		Vulnerability: vulnObj,
		Package:       thePkg,
		Details: []match.Detail{
			{
				Type:       match.ExactDirectMatch,
				Confidence: 1.0,
				SearchedBy: match.DistroParameters{
					Distro: match.DistroIdentification{
						Type:    "centos",
						Version: "8",
					},
					Namespace: "redhat:distro:redhat:8",
					Package: match.PackageParameter{
						Name:    "dive",
						Version: "0:0.9.2-1",
					},
				},
				Found: match.DistroResult{
					VersionConstraint: "<= 1.0.42 (rpm)",
					VulnerabilityID:   vulnObj.ID,
				},
				Matcher: match.RpmMatcher,
			},
		},
	})
}

func addSlesMatches(t *testing.T, theSource source.Source, catalog *syftPkg.Collection, provider vulnerability.Provider, theResult *match.Matches) {
	packages := catalog.PackagesByPath("/var/lib/rpm/Packages")
	if len(packages) != 1 {
		t.Logf("Sles Packages: %+v", packages)
		t.Fatalf("problem with upstream syft cataloger (RPMDB)")
	}
	thePkg := pkg.New(packages[0])

	vulns, err := provider.FindVulnerabilities(byNamespace("redhat:distro:redhat:8"), search.ByPackageName(thePkg.Name))
	require.NoError(t, err)
	require.NotEmpty(t, vulns)
	vulnObj := vulns[0]

	vulnObj.Namespace = "sles:distro:sles:12.5"
	theResult.Add(match.Match{
		Vulnerability: vulnObj,
		Package:       thePkg,
		Details: []match.Detail{
			{
				Type:       match.ExactDirectMatch,
				Confidence: 1.0,
				SearchedBy: match.DistroParameters{
					Distro: match.DistroIdentification{
						Type:    "sles",
						Version: "12.5",
					},
					Namespace: "sles:distro:sles:12.5",
					Package: match.PackageParameter{
						Name:    "dive",
						Version: "0:0.9.2-1",
					},
				},
				Found: match.DistroResult{
					VersionConstraint: "<= 1.0.42 (rpm)",
					VulnerabilityID:   vulnObj.ID,
				},
				Matcher: match.RpmMatcher,
			},
		},
	})
}

func addArchMatches(t *testing.T, theSource source.Source, catalog *syftPkg.Collection, provider vulnerability.Provider, theResult *match.Matches) {
	packages := catalog.PackagesByPath("/var/lib/pacman/local/xz-5.2.4-1/desc")
	if len(packages) != 1 {
		t.Logf("Arch Packages: %+v", packages)
		t.Fatalf("problem with upstream syft cataloger (pacman)")
	}
	thePkg := pkg.New(packages[0])
	vulns, err := provider.FindVulnerabilities(byNamespace("arch:distro:arch:rolling"), search.ByPackageName(thePkg.Name))
	require.NoError(t, err)
	require.NotEmpty(t, vulns)
	vulnObj := vulns[0]

	theResult.Add(match.Match{
		Vulnerability: vulnObj,
		Package:       thePkg,
		Details: []match.Detail{
			{
				Type:       match.ExactDirectMatch,
				Confidence: 1.0,
				SearchedBy: match.DistroParameters{
					Distro: match.DistroIdentification{
						Type:    "archlinux",
						Version: "",
					},
					Namespace: "arch:distro:arch:rolling",
					Package: match.PackageParameter{
						Name:    "xz",
						Version: "5.2.4-1",
					},
				},
				Found: match.DistroResult{
					VersionConstraint: "< 5.6.1-2 (pacman)",
					VulnerabilityID:   vulnObj.ID,
				},
				Matcher: match.PacmanMatcher,
			},
		},
	})
}

func addHaskellMatches(t *testing.T, theSource source.Source, catalog *syftPkg.Collection, provider vulnerability.Provider, theResult *match.Matches) {
	packages := catalog.PackagesByPath("/haskell/stack.yaml")
	if len(packages) < 1 {
		t.Logf("Haskell Packages: %+v", packages)
		t.Fatalf("problem with upstream syft cataloger (haskell)")
	}
	thePkg := pkg.New(packages[0])
	vulns, err := provider.FindVulnerabilities(byNamespace("github:language:haskell"), search.ByPackageName(strings.ToLower(thePkg.Name)))
	require.NoError(t, err)
	require.NotEmpty(t, vulns)
	vulnObj := vulns[0]

	theResult.Add(match.Match{
		Vulnerability: vulnObj,
		Package:       thePkg,
		Details: []match.Detail{
			{
				Type:       match.ExactDirectMatch,
				Confidence: 1.0,
				SearchedBy: match.EcosystemParameters{
					Language:  "haskell",
					Namespace: "github:language:haskell",
					Package: match.PackageParameter{
						Name:    thePkg.Name,
						Version: thePkg.Version,
					},
				},
				Found: match.EcosystemResult{
					VersionConstraint: "< 0.9.0 (unknown)",
					VulnerabilityID:   "CVE-haskell-sample",
				},
				Matcher: match.StockMatcher,
			},
		},
	})
}

func addHexMatches(t *testing.T, theSource source.Source, catalog *syftPkg.Collection, provider vulnerability.Provider, theResult *match.Matches) {
	packages := catalog.PackagesByPath("/hex/mix.lock")
	if len(packages) < 1 {
		t.Logf("Hex Packages: %+v", packages)
		t.Fatalf("problem with upstream syft cataloger (elixir-mix-lock)")
	}
	thePkg := pkg.New(packages[0])
	vulns, err := provider.FindVulnerabilities(byNamespace("github:language:elixir"), search.ByPackageName(thePkg.Name))
	require.NoError(t, err)
	require.NotEmpty(t, vulns)
	vulnObj := vulns[0]

	theResult.Add(match.Match{
		Vulnerability: vulnObj,
		Package:       thePkg,
		Details: []match.Detail{
			{
				Type:       match.ExactDirectMatch,
				Confidence: 1.0,
				SearchedBy: match.EcosystemParameters{
					Language:  "elixir",
					Namespace: "github:language:elixir",
					Package: match.PackageParameter{
						Name:    thePkg.Name,
						Version: thePkg.Version,
					},
				},
				Found: match.EcosystemResult{
					VersionConstraint: "< 1.12.0 (unknown)",
					VulnerabilityID:   "CVE-hex-plug",
				},
				Matcher: match.HexMatcher,
			},
		},
	})
}

func addJvmMatches(t *testing.T, theSource source.Source, catalog *syftPkg.Collection, provider vulnerability.Provider, theResult *match.Matches) {
	packages := catalog.PackagesByPath("/opt/java/openjdk/release")
	if len(packages) < 1 {
		t.Logf("JVM Packages: %+v", packages)
		t.Fatalf("problem with upstream syft cataloger (java-jvm-cataloger)")
	}

	for _, p := range packages {
		thePkg := pkg.New(p)
		vulns, err := provider.FindVulnerabilities(byNamespace("nvd:cpe"), search.ByPackageName(thePkg.Name))
		require.NoError(t, err)
		require.NotEmpty(t, vulns)
		vulnObj := vulns[0]

		// why is this being set?
		vulnObj.CPEs = []cpe.CPE{
			cpe.Must("cpe:2.3:a:oracle:jdk:*:*:*:*:*:*:*:*", ""),
		}

		theResult.Add(match.Match{
			Vulnerability: vulnObj,
			Package:       thePkg,
			Details: []match.Detail{
				{
					Type:       match.CPEMatch,
					Confidence: 0.9,
					SearchedBy: match.CPEParameters{
						Namespace: "nvd:cpe",
						CPEs: []string{
							"cpe:2.3:a:oracle:jdk:1.8.0:update400:*:*:*:*:*:*",
						},
						Package: match.PackageParameter{Name: "jdk", Version: "1.8.0_400-b07"},
					},
					Found: match.CPEResult{
						VulnerabilityID:   "CVE-jdk",
						VersionConstraint: "< 1.8.0_401 (jvm)",
						CPEs: []string{
							"cpe:2.3:a:oracle:jdk:*:*:*:*:*:*:*:*",
						},
					},
					Matcher: match.StockMatcher,
				},
			},
		})
	}
}

func addRustMatches(t *testing.T, theSource source.Source, catalog *syftPkg.Collection, provider vulnerability.Provider, theResult *match.Matches) {
	packages := catalog.PackagesByPath("/hello-auditable")
	if len(packages) < 1 {
		t.Logf("Rust Packages: %+v", packages)
		t.Fatalf("problem with upstream syft cataloger (cargo-auditable-binary-cataloger)")
	}

	for _, p := range packages {
		thePkg := pkg.New(p)
		vulns, err := provider.FindVulnerabilities(byNamespace("github:language:rust"), search.ByPackageName(thePkg.Name))
		require.NoError(t, err)
		require.NotEmpty(t, vulns)
		vulnObj := vulns[0]

		theResult.Add(match.Match{
			Vulnerability: vulnObj,
			Package:       thePkg,
			Details: []match.Detail{
				{
					Type:       match.ExactDirectMatch,
					Confidence: 1.0,
					SearchedBy: match.EcosystemParameters{
						Language:  "rust",
						Namespace: "github:language:rust",
						Package: match.PackageParameter{
							Name:    thePkg.Name,
							Version: thePkg.Version,
						},
					},
					Found: match.EcosystemResult{
						VersionConstraint: vulnObj.Constraint.String(),
						VulnerabilityID:   vulnObj.ID,
					},
					Matcher: match.RustMatcher,
				},
			},
		})
	}
}

func TestMatchByImage(t *testing.T) {
	observedMatchers := stringutil.NewStringSet()
	definedMatchers := stringutil.NewStringSet()
	for _, l := range match.AllMatcherTypes {
		definedMatchers.Add(string(l))
	}

	tests := []struct {
		name       string
		expectedFn func(source.Source, *syftPkg.Collection, vulnerability.Provider) match.Matches
	}{
		{
			name: "image-debian-match-coverage",
			expectedFn: func(theSource source.Source, catalog *syftPkg.Collection, provider vulnerability.Provider) match.Matches {
				expectedMatches := match.NewMatches()
				addPythonMatches(t, theSource, catalog, provider, &expectedMatches)
				addRubyMatches(t, theSource, catalog, provider, &expectedMatches)
				addJavaMatches(t, theSource, catalog, provider, &expectedMatches)
				addDpkgMatches(t, theSource, catalog, provider, &expectedMatches)
				addJavascriptMatches(t, theSource, catalog, provider, &expectedMatches)
				addDotnetMatches(t, theSource, catalog, provider, &expectedMatches)
				addGolangMatches(t, theSource, catalog, provider, &expectedMatches)
				addHaskellMatches(t, theSource, catalog, provider, &expectedMatches)
				addHexMatches(t, theSource, catalog, provider, &expectedMatches)
				return expectedMatches
			},
		},
		{
			name: "image-centos-match-coverage",
			expectedFn: func(theSource source.Source, catalog *syftPkg.Collection, provider vulnerability.Provider) match.Matches {
				expectedMatches := match.NewMatches()
				addRhelMatches(t, theSource, catalog, provider, &expectedMatches)
				return expectedMatches
			},
		},
		{
			name: "image-alpine-match-coverage",
			expectedFn: func(theSource source.Source, catalog *syftPkg.Collection, provider vulnerability.Provider) match.Matches {
				expectedMatches := match.NewMatches()
				addAlpineMatches(t, theSource, catalog, provider, &expectedMatches)
				return expectedMatches
			},
		},
		{
			name: "image-sles-match-coverage",
			expectedFn: func(theSource source.Source, catalog *syftPkg.Collection, provider vulnerability.Provider) match.Matches {
				expectedMatches := match.NewMatches()
				addSlesMatches(t, theSource, catalog, provider, &expectedMatches)
				return expectedMatches
			},
		},
		{
			name: "image-arch-match-coverage",
			expectedFn: func(theSource source.Source, catalog *syftPkg.Collection, provider vulnerability.Provider) match.Matches {
				expectedMatches := match.NewMatches()
				addArchMatches(t, theSource, catalog, provider, &expectedMatches)
				return expectedMatches
			},
		},
		// TODO: add this back in when #744 is fully implemented (see https://github.com/anchore/grype/issues/744#issuecomment-2448163737)
		//{
		//	name: "image-portage-match-coverage",
		//	expectedFn: func(theSource source.Source, catalog *syftPkg.Collection, provider vulnerability.Provider) match.Matches {
		//		expectedMatches := match.NewMatches()
		//		addPortageMatches(t, theSource, catalog, provider, &expectedMatches)
		//		return expectedMatches
		//	},
		//},
		{
			name: "image-rust-auditable-match-coverage",
			expectedFn: func(theSource source.Source, catalog *syftPkg.Collection, provider vulnerability.Provider) match.Matches {
				expectedMatches := match.NewMatches()
				addRustMatches(t, theSource, catalog, provider, &expectedMatches)
				return expectedMatches
			},
		},
		{
			name: "image-jvm-match-coverage",
			expectedFn: func(theSource source.Source, catalog *syftPkg.Collection, provider vulnerability.Provider) match.Matches {
				expectedMatches := match.NewMatches()
				addJvmMatches(t, theSource, catalog, provider, &expectedMatches)
				return expectedMatches
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			theProvider := newMockDbProvider()

			imagetest.GetFixtureImage(t, "docker-archive", test.name)
			tarPath := imagetest.GetFixtureImageTarPath(t, test.name)

			// this is purely done to help setup mocks
			theSource, err := syft.GetSource(context.Background(), tarPath, syft.DefaultGetSourceConfig().WithSources("docker-archive"))
			require.NoError(t, err)
			t.Cleanup(func() {
				require.NoError(t, theSource.Close())
			})

			// TODO: relationships are not verified at this time
			// enable all catalogers to cover non default cases
			config := syft.DefaultCreateSBOMConfig().WithCatalogerSelection(pkgcataloging.NewSelectionRequest().WithDefaults("all"))
			config.Search.Scope = source.SquashedScope

			s, err := syft.CreateSBOM(context.Background(), theSource, config)
			require.NoError(t, err)
			require.NotNil(t, s)

			// TODO: we need to use the API default configuration, not something hard coded here
			matchers := matcher.NewDefaultMatchers(matcher.Config{
				Java: java.MatcherConfig{
					UseCPEs: true,
				},
				Ruby: ruby.MatcherConfig{
					UseCPEs: true,
				},
				Python: python.MatcherConfig{
					UseCPEs: true,
				},
				Dotnet: dotnet.MatcherConfig{
					UseCPEs: true,
				},
				Javascript: javascript.MatcherConfig{
					UseCPEs: true,
				},
				Golang: golang.MatcherConfig{
					UseCPEs: true,
				},
				Rust: rust.MatcherConfig{
					UseCPEs: true,
				},
				Stock: stock.MatcherConfig{
					UseCPEs: true,
				},
			})

			actualResults := grype.FindVulnerabilitiesForPackage(theProvider, matchers, pkg.FromCollection(s.Artifacts.Packages, pkg.SynthesisConfig{
				Distro: pkg.DistroConfig{
					Override: distro.FromRelease(s.Artifacts.LinuxDistribution, distro.DefaultFixChannels()),
				},
			}))
			for _, m := range actualResults.Sorted() {
				for _, d := range m.Details {
					observedMatchers.Add(string(d.Matcher))
				}
			}

			// build expected matches from what's discovered from the catalog
			expectedMatches := test.expectedFn(theSource, s.Artifacts.Packages, theProvider)

			assertMatches(t, expectedMatches.Sorted(), actualResults.Sorted())
		})
	}

	// Test that VEX matchers produce matches when fed documents with "affected"
	// or "under investigation" statuses.
	for n, tc := range map[string]struct {
		vexStatus    vexStatus.Status
		vexDocuments []string
	}{
		"csaf-affected":               {vexStatus.Affected, []string{"test-fixtures/vex/csaf/affected.csaf.json"}},
		"csaf-under_investigation":    {vexStatus.UnderInvestigation, []string{"test-fixtures/vex/csaf/under_investigation.csaf.json"}},
		"openvex-affected":            {vexStatus.Affected, []string{"test-fixtures/vex/openvex/affected.openvex.json"}},
		"openvex-under_investigation": {vexStatus.UnderInvestigation, []string{"test-fixtures/vex/openvex/under_investigation.openvex.json"}},
	} {
		t.Run(n, func(t *testing.T) {
			ignoredMatches := testIgnoredMatches()
			vexedResults := vexMatches(t, ignoredMatches, tc.vexStatus, tc.vexDocuments)
			if len(vexedResults.Sorted()) != 1 {
				t.Errorf("expected one vexed result, got none")
			}

			expectedMatches := match.NewMatches()
			// The single match in the actual results is the same in ignoredMatched
			// but must the details of the VEX matcher appended
			if len(vexedResults.Sorted()) < 1 {
				t.Errorf(
					"Expected VEXed Results to produce an array of vexMatches but got none; len(vexedResults)=%d",
					len(vexedResults.Sorted()),
				)
			}
			result := vexedResults.Sorted()[0]
			if len(result.Details) != len(ignoredMatches[0].Match.Details)+1 {
				t.Errorf(
					"Details in VEXed results don't match (expected %d, got %d)",
					len(ignoredMatches[0].Match.Details)+1, len(result.Details),
				)
			}

			result.Details = result.Details[:len(result.Details)-1]
			actualResults := match.NewMatches()
			actualResults.Add(result)

			expectedMatches.Add(ignoredMatches[0].Match)
			assertMatches(t, expectedMatches.Sorted(), actualResults.Sorted())

			for _, m := range vexedResults.Sorted() {
				for _, d := range m.Details {
					observedMatchers.Add(string(d.Matcher))
				}
			}
		})
	}

	// ensure that integration test cases stay in sync with the implemented matchers
	observedMatchers.Remove(string(match.StockMatcher))
	definedMatchers.Remove(string(match.StockMatcher))
	definedMatchers.Remove(string(match.MsrcMatcher))
	definedMatchers.Remove(string(match.PortageMatcher)) // TODO: add this back in when #744 is complete
	definedMatchers.Remove(string(match.BitnamiMatcher)) // bitnami will be tested via quality gate
	definedMatchers.Remove(string(match.KernelMatcher))  // kernel pkg not present in test img

	if len(observedMatchers) != len(definedMatchers) {
		t.Errorf("matcher coverage incomplete (matchers=%d, coverage=%d)", len(definedMatchers), len(observedMatchers))
		defs := definedMatchers.ToSlice()
		sort.Strings(defs)
		obs := observedMatchers.ToSlice()
		sort.Strings(obs)

		t.Log(cmp.Diff(defs, obs))
	}
}

// testIgnoredMatches returns an list of ignored matches to test the vex
// matchers
func testIgnoredMatches() []match.IgnoredMatch {
	return []match.IgnoredMatch{
		{
			Match: match.Match{
				Vulnerability: vulnerability.Vulnerability{
					Reference: vulnerability.Reference{
						ID:        "CVE-2024-0000",
						Namespace: "alpine:distro:alpine:3.12",
					},
				},
				Package: pkg.Package{
					ID:       "44fa3691ae360cac",
					Name:     "libvncserver",
					Version:  "0.9.9",
					Licenses: []string{"GPL-2.0-or-later"},
					Type:     "apk",
					CPEs: []cpe.CPE{
						{
							Attributes: cpe.Attributes{
								Part:    "a",
								Vendor:  "libvncserver",
								Product: "libvncserver",
								Version: "0.9.9",
							},
						},
					},
					PURL:      "pkg:apk/alpine/libvncserver@0.9.9?arch=x86_64&distro=alpine-3.12.0",
					Upstreams: []pkg.UpstreamPackage{{Name: "libvncserver"}},
				},
				Details: []match.Detail{
					{
						Type: match.ExactIndirectMatch,
						SearchedBy: match.DistroParameters{
							Distro: match.DistroIdentification{
								Type:    "alpine",
								Version: "3.12.0",
							},
							Namespace: "alpine:distro:alpine:3.12",
							Package: match.PackageParameter{
								Name:    "libvncserver",
								Version: "0.9.9",
							},
						},
						Found: match.DistroResult{
							VersionConstraint: "< 0.9.10 (unknown)",
							VulnerabilityID:   "CVE-2024-0000",
						},
						Matcher:    match.ApkMatcher,
						Confidence: 1,
					},
				},
			},
			AppliedIgnoreRules: []match.IgnoreRule{},
		},
	}
}

// vexMatches moves the first match of a matches list to an ignore list and
// applies a VEX "affected" document to it to move it to the matches list.
func vexMatches(t *testing.T, ignoredMatches []match.IgnoredMatch, vexStatus vexStatus.Status, vexDocuments []string) match.Matches {
	matches := match.NewMatches()
	vexMatcher, err := vex.NewProcessor(vex.ProcessorOptions{
		Documents: vexDocuments,
		IgnoreRules: []match.IgnoreRule{
			{VexStatus: string(vexStatus)},
		},
	})
	if err != nil {
		t.Errorf("creating VEX processor: %s", err)
	}

	pctx := &pkg.Context{
		Source: &source.Description{
			Metadata: source.ImageMetadata{
				RepoDigests: []string{
					"alpine@sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
				},
			},
		},
	}

	vexedMatches, ignoredMatches, err := vexMatcher.ApplyVEX(pctx, &matches, ignoredMatches)
	if err != nil {
		t.Errorf("applying VEX data: %s", err)
	}

	if len(ignoredMatches) != 0 {
		t.Errorf("VEX text fixture %s must affect all ignored matches (%d left)", vexDocuments, len(ignoredMatches))
	}

	return *vexedMatches
}

func assertMatches(t *testing.T, expected, actual []match.Match) {
	t.Helper()
	opts := []cmp.Option{
		cmpopts.EquateEmpty(),
		cmpopts.IgnoreFields(vulnerability.Vulnerability{}, "Constraint"),
		cmpopts.IgnoreFields(pkg.Package{}, "Locations", "Distro"),
		cmpopts.SortSlices(func(a, b match.Match) bool {
			return a.Package.ID < b.Package.ID
		}),
	}

	if diff := cmp.Diff(expected, actual, opts...); diff != "" {
		t.Errorf("mismatch (-want +got):\n%s", diff)
	}
}

func byNamespace(ns string) vulnerability.Criteria {
	return search.ByFunc(func(v vulnerability.Vulnerability) (bool, string, error) {
		return v.Reference.Namespace == ns, "", nil
	})
}
