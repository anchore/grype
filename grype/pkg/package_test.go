package pkg

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/file"
	syftFile "github.com/anchore/syft/syft/file"
	syftPkg "github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/testutil"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name      string
		syftPkg   syftPkg.Package
		metadata  interface{}
		upstreams []UpstreamPackage
	}{
		{
			name: "alpm package with source info",
			syftPkg: syftPkg.Package{
				Metadata: syftPkg.AlpmMetadata{
					BasePackage:  "base-pkg-info",
					Package:      "pkg-info",
					Version:      "version-info",
					Architecture: "arch-info",
					Files: []syftPkg.AlpmFileRecord{{
						Path: "/this/path/exists",
					}},
				},
			},
		},
		{
			name: "dpkg with source info",
			syftPkg: syftPkg.Package{
				Metadata: syftPkg.DpkgMetadata{
					Package:       "pkg-info",
					Source:        "src-info",
					Version:       "version-info",
					SourceVersion: "src-version-info",
					Architecture:  "arch-info",
					Maintainer:    "maintainer-info",
					InstalledSize: 10,
					Files: []syftPkg.DpkgFileRecord{
						{
							Path: "path-info",
							Digest: &file.Digest{
								Algorithm: "algo-info",
								Value:     "digest-info",
							},
							IsConfigFile: true,
						},
					},
				},
			},
			upstreams: []UpstreamPackage{
				{
					Name:    "src-info",
					Version: "src-version-info",
				},
			},
		},
		{
			name: "rpm db entry with source info",
			syftPkg: syftPkg.Package{
				Metadata: syftPkg.RpmDBMetadata{
					Name:      "name-info",
					Version:   "version-info",
					Epoch:     intRef(30),
					Arch:      "arch-info",
					Release:   "release-info",
					SourceRpm: "sqlite-3.26.0-6.el8.src.rpm",
					Size:      40,
					Vendor:    "vendor-info",
					Files: []syftPkg.RpmFileRecord{
						{
							Path: "path-info",
							Mode: 20,
							Size: 10,
							Digest: file.Digest{
								Algorithm: "algo-info",
								Value:     "digest-info",
							},
							UserName:  "user-info",
							GroupName: "group-info",
							Flags:     "flag-info",
						},
					},
				},
			},
			metadata: RpmMetadata{
				Epoch: intRef(30),
			},
			upstreams: []UpstreamPackage{
				{
					Name:    "sqlite",
					Version: "3.26.0-6.el8",
				},
			},
		},
		{
			name: "rpm archive with source info",
			syftPkg: syftPkg.Package{
				Metadata: syftPkg.RpmArchiveMetadata{
					Name:      "name-info",
					Version:   "version-info",
					Epoch:     intRef(30),
					Arch:      "arch-info",
					Release:   "release-info",
					SourceRpm: "sqlite-3.26.0-6.el8.src.rpm",
					Size:      40,
					Vendor:    "vendor-info",
					Files: []syftPkg.RpmFileRecord{
						{
							Path: "path-info",
							Mode: 20,
							Size: 10,
							Digest: file.Digest{
								Algorithm: "algo-info",
								Value:     "digest-info",
							},
							UserName:  "user-info",
							GroupName: "group-info",
							Flags:     "flag-info",
						},
					},
				},
			},
			metadata: RpmMetadata{
				Epoch: intRef(30),
			},
			upstreams: []UpstreamPackage{
				{
					Name:    "sqlite",
					Version: "3.26.0-6.el8",
				},
			},
		},
		{
			name: "rpm db entry with source info that matches the package info",
			syftPkg: syftPkg.Package{
				Name: "sqlite",
				Metadata: syftPkg.RpmDBMetadata{
					SourceRpm: "sqlite-3.26.0-6.el8.src.rpm",
				},
			},
			metadata: RpmMetadata{},
		},
		{
			name: "rpm archive with source info that matches the package info",
			syftPkg: syftPkg.Package{
				Name: "sqlite",
				Metadata: syftPkg.RpmArchiveMetadata{
					SourceRpm: "sqlite-3.26.0-6.el8.src.rpm",
				},
			},
			metadata: RpmMetadata{},
		},
		{
			name: "rpm db entry with modularity label",
			syftPkg: syftPkg.Package{
				Name: "sqlite",
				Metadata: syftPkg.RpmDBMetadata{
					SourceRpm:       "sqlite-3.26.0-6.el8.src.rpm",
					ModularityLabel: "abc:2",
				},
			},
			metadata: RpmMetadata{ModularityLabel: "abc:2"},
		},
		{
			name: "rpm archive with modularity label",
			syftPkg: syftPkg.Package{
				Name: "sqlite",
				Metadata: syftPkg.RpmArchiveMetadata{
					SourceRpm:       "sqlite-3.26.0-6.el8.src.rpm",
					ModularityLabel: "abc:2",
				},
			},
			metadata: RpmMetadata{ModularityLabel: "abc:2"},
		},
		{
			name: "java pkg",
			syftPkg: syftPkg.Package{
				Metadata: syftPkg.JavaMetadata{
					VirtualPath: "virtual-path-info",
					Manifest: &syftPkg.JavaManifest{
						Main: map[string]string{
							"Name": "main-section-name-info",
						},
						NamedSections: map[string]map[string]string{
							"named-section": {
								"named-section-key": "named-section-value",
							},
						},
					},
					PomProperties: &syftPkg.PomProperties{
						Path:       "pom-path-info",
						Name:       "pom-name-info",
						GroupID:    "pom-group-ID-info",
						ArtifactID: "pom-artifact-ID-info",
						Version:    "pom-version-info",
						Extra: map[string]string{
							"extra-key": "extra-value",
						},
					},
					ArchiveDigests: []syftFile.Digest{{
						Algorithm: "sha1",
						Value:     "236e3bfdbdc6c86629237a74f0f11414adb4e211",
					}},
				},
			},
			metadata: JavaMetadata{
				VirtualPath:   "virtual-path-info",
				PomArtifactID: "pom-artifact-ID-info",
				PomGroupID:    "pom-group-ID-info",
				ManifestName:  "main-section-name-info",
				ArchiveDigests: []Digest{{
					Algorithm: "sha1",
					Value:     "236e3bfdbdc6c86629237a74f0f11414adb4e211",
				}},
			},
		},
		{
			name: "apk with source info",
			syftPkg: syftPkg.Package{
				Metadata: syftPkg.ApkMetadata{
					Package:       "libcurl-tools",
					OriginPackage: "libcurl",
					Maintainer:    "somone",
					Version:       "1.2.3",
					Architecture:  "a",
					URL:           "a",
					Description:   "a",
					Size:          1,
					InstalledSize: 1,
				},
			},
			upstreams: []UpstreamPackage{
				{
					Name: "libcurl",
				},
			},
		},
		// the below packages are those that have no metadata or upstream info to parse out
		{
			name: "npm-metadata",
			syftPkg: syftPkg.Package{
				Metadata: syftPkg.NpmPackageJSONMetadata{
					Author:      "a",
					Homepage:    "a",
					Description: "a",
					URL:         "a",
				},
			},
		},
		{
			name: "python-metadata",
			syftPkg: syftPkg.Package{
				Metadata: syftPkg.PythonPackageMetadata{
					Name:                 "a",
					Version:              "a",
					Author:               "a",
					AuthorEmail:          "a",
					Platform:             "a",
					SitePackagesRootPath: "a",
				},
			},
		},
		{
			name: "gem-metadata",
			syftPkg: syftPkg.Package{
				Metadata: syftPkg.GemMetadata{
					Name:     "a",
					Version:  "a",
					Homepage: "a",
				},
			},
		},
		{
			name: "kb-metadata",
			syftPkg: syftPkg.Package{
				Metadata: syftPkg.KbPatchMetadata{
					ProductID: "a",
					Kb:        "a",
				},
			},
		},
		{
			name: "rust-metadata",
			syftPkg: syftPkg.Package{
				Metadata: syftPkg.CargoPackageMetadata{
					Name:     "a",
					Version:  "a",
					Source:   "a",
					Checksum: "a",
				},
			},
		},
		{
			name: "golang-metadata",
			syftPkg: syftPkg.Package{
				Metadata: syftPkg.GolangBinMetadata{
					BuildSettings:     map[string]string{},
					GoCompiledVersion: "1.0.0",
					H1Digest:          "a",
					MainModule:        "myMainModule",
				},
			},
			metadata: GolangBinMetadata{
				BuildSettings:     map[string]string{},
				GoCompiledVersion: "1.0.0",
				H1Digest:          "a",
				MainModule:        "myMainModule",
			},
		},
		{
			name: "golang-mod-metadata",
			syftPkg: syftPkg.Package{
				Metadata: syftPkg.GolangModMetadata{
					H1Digest: "h1:as234NweNNTNWEtt13nwNENTt",
				},
			},
			metadata: GolangModMetadata{
				H1Digest: "h1:as234NweNNTNWEtt13nwNENTt",
			},
		},
		{
			name: "php-composer-lock-metadata",
			syftPkg: syftPkg.Package{
				Metadata: syftPkg.PhpComposerLockMetadata{
					Name:    "a",
					Version: "a",
				},
			},
		},
		{
			name: "php-composer-installed-metadata",
			syftPkg: syftPkg.Package{
				Metadata: syftPkg.PhpComposerInstalledMetadata{
					Name:    "a",
					Version: "a",
				},
			},
		},
		{
			name: "dart-pub-metadata",
			syftPkg: syftPkg.Package{
				Metadata: syftPkg.DartPubMetadata{
					Name:    "a",
					Version: "a",
				},
			},
		},
		{
			name: "dotnet-metadata",
			syftPkg: syftPkg.Package{
				Metadata: syftPkg.DotnetDepsMetadata{
					Name:     "a",
					Version:  "a",
					Path:     "a",
					Sha512:   "a",
					HashPath: "a",
				},
			},
		},
		{
			name: "cpp conan-metadata",
			syftPkg: syftPkg.Package{
				Metadata: syftPkg.ConanMetadata{
					Ref: "catch2/2.13.8",
				},
			},
		},
		{
			name: "cpp conan lock metadata",
			syftPkg: syftPkg.Package{
				Metadata: syftPkg.ConanLockMetadata{
					Ref: "zlib/1.2.12",
					Options: map[string]string{
						"fPIC":   "True",
						"shared": "False",
					},
					Path:    "all/conanfile.py",
					Context: "host",
				},
			},
		},
		{
			name: "cocoapods cocoapods-metadata",
			syftPkg: syftPkg.Package{
				Metadata: syftPkg.CocoapodsMetadata{
					Checksum: "123eere234",
				},
			},
		},
		{
			name: "portage-metadata",
			syftPkg: syftPkg.Package{
				Metadata: syftPkg.PortageMetadata{
					InstalledSize: 1,
					Files:         []syftPkg.PortageFileRecord{},
				},
			},
		},
		{
			name: "hackage-stack-lock-metadata",
			syftPkg: syftPkg.Package{
				Metadata: syftPkg.HackageStackYamlLockMetadata{
					PkgHash: "some-hash",
				},
			},
		},
		{
			name: "hackage-stack-metadata",
			syftPkg: syftPkg.Package{
				Metadata: syftPkg.HackageStackYamlMetadata{
					PkgHash: "some-hash",
				},
			},
		},
		{
			name: "rebar-metadata",
			syftPkg: syftPkg.Package{
				Metadata: syftPkg.RebarLockMetadata{
					Name:    "rebar",
					Version: "v0.1.1",
				},
			},
		},
		{
			name: "npm-package-lock-metadata",
			syftPkg: syftPkg.Package{
				Metadata: syftPkg.NpmPackageLockJSONMetadata{
					Resolved:  "resolved",
					Integrity: "sha1:ab7d8979989b7a98d97",
				},
			},
		},
		{
			name: "mix-lock-metadata",
			syftPkg: syftPkg.Package{
				Metadata: syftPkg.MixLockMetadata{
					Name:    "mix-lock",
					Version: "v0.1.2",
				},
			},
		},
		{
			name: "pipfile-lock-metadata",
			syftPkg: syftPkg.Package{
				Metadata: syftPkg.PythonPipfileLockMetadata{
					Hashes: []string{
						"sha1:ab8v88a8b88d8d8c88b8s765s47",
					},
					Index: "1",
				},
			},
		},
		{
			name: "python-requirements-metadata",
			syftPkg: syftPkg.Package{
				Metadata: syftPkg.PythonRequirementsMetadata{
					Name:              "a",
					Extras:            []string{"a"},
					VersionConstraint: "a",
					URL:               "a",
					Markers:           "a",
				},
			},
		},
		{
			name: "binary-metadata",
			syftPkg: syftPkg.Package{
				Metadata: syftPkg.BinaryMetadata{
					Matches: []syftPkg.ClassifierMatch{
						{
							Classifier: "node",
						},
					},
				},
			},
		},
		{
			name: "nix-store-metadata",
			syftPkg: syftPkg.Package{
				Metadata: syftPkg.NixStoreMetadata{
					OutputHash: "a",
					Output:     "a",
					Files: []string{
						"a",
					},
				},
			},
		},
		{
			name: "linux-kernel-metadata",
			syftPkg: syftPkg.Package{
				Metadata: syftPkg.LinuxKernelMetadata{
					Name:            "a",
					Architecture:    "a",
					Version:         "a",
					ExtendedVersion: "a",
					BuildTime:       "a",
					Author:          "a",
					Format:          "a",
					RWRootFS:        true,
					SwapDevice:      10,
					RootDevice:      11,
					VideoMode:       "a",
				},
			},
		},
		{
			name: "linux-kernel-module-metadata",
			syftPkg: syftPkg.Package{
				Metadata: syftPkg.LinuxKernelModuleMetadata{
					Name:          "a",
					Version:       "a",
					SourceVersion: "a",
					Path:          "a",
					Description:   "a",
					Author:        "a",
					License:       "a",
					KernelVersion: "a",
					VersionMagic:  "a",
					Parameters: map[string]syftPkg.LinuxKernelModuleParameter{
						"a": {
							Type:        "a",
							Description: "a",
						},
					},
				},
			},
		},
		{
			name: "r-description-file-metadata",
			syftPkg: syftPkg.Package{
				Metadata: syftPkg.RDescriptionFileMetadata{
					Title:            "a",
					Description:      "a",
					Author:           "a",
					Maintainer:       "a",
					URL:              []string{"a"},
					Repository:       "a",
					Built:            "a",
					NeedsCompilation: true,
					Imports:          []string{"a"},
					Depends:          []string{"a"},
					Suggests:         []string{"a"},
				},
			},
		},
		{
			name: "dotnet-portable-executable-metadata",
			syftPkg: syftPkg.Package{
				Metadata: syftPkg.DotnetPortableExecutableMetadata{
					AssemblyVersion: "a",
					LegalCopyright:  "a",
					Comments:        "a",
					InternalName:    "a",
					CompanyName:     "a",
					ProductName:     "a",
					ProductVersion:  "a",
				},
			},
		},
		{
			name: "swift-package-manager-metadata",
			syftPkg: syftPkg.Package{
				Metadata: syftPkg.SwiftPackageManagerMetadata{
					Revision: "a",
				},
			},
		},
	}

	// capture each observed metadata type, we should see all of them relate to what syft provides by the end of testing
	tester := testutil.NewPackageMetadataCompletionTester(t)

	// run all of our cases
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tester.Tested(t, test.syftPkg.Metadata)
			p := New(test.syftPkg)
			assert.Equal(t, test.metadata, p.Metadata, "unexpected metadata")
			assert.Equal(t, test.upstreams, p.Upstreams, "unexpected upstream")
		})
	}
}

func TestFromCollection_DoesNotPanic(t *testing.T) {
	collection := syftPkg.NewCollection()

	examplePackage := syftPkg.Package{
		Name:    "test",
		Version: "1.2.3",
		Locations: file.NewLocationSet(
			file.NewLocation("/test-path"),
		),
		Type: syftPkg.NpmPkg,
	}

	collection.Add(examplePackage)
	// add it again!
	collection.Add(examplePackage)

	assert.NotPanics(t, func() {
		_ = FromCollection(collection, SynthesisConfig{})
	})
}

func TestFromCollection_GeneratesCPEs(t *testing.T) {
	collection := syftPkg.NewCollection()

	collection.Add(syftPkg.Package{
		Name:    "first",
		Version: "1",
		CPEs: []cpe.CPE{
			{},
		},
	})

	collection.Add(syftPkg.Package{
		Name:    "second",
		Version: "2",
	})

	// doesn't generate cpes when no flag
	pkgs := FromCollection(collection, SynthesisConfig{})
	assert.Len(t, pkgs[0].CPEs, 1)
	assert.Len(t, pkgs[1].CPEs, 0)

	// does generate cpes with the flag
	pkgs = FromCollection(collection, SynthesisConfig{
		GenerateMissingCPEs: true,
	})
	assert.Len(t, pkgs[0].CPEs, 1)
	assert.Len(t, pkgs[1].CPEs, 1)
}

func Test_getNameAndELVersion(t *testing.T) {
	tests := []struct {
		name            string
		sourceRPM       string
		expectedName    string
		expectedVersion string
	}{
		{
			name:            "sqlite-3.26.0-6.el8.src.rpm",
			sourceRPM:       "sqlite-3.26.0-6.el8.src.rpm",
			expectedName:    "sqlite",
			expectedVersion: "3.26.0-6.el8",
		},
		{
			name:            "util-linux-ng-2.17.2-12.28.el6_9.src.rpm",
			sourceRPM:       "util-linux-ng-2.17.2-12.28.el6_9.src.rpm",
			expectedName:    "util-linux-ng",
			expectedVersion: "2.17.2-12.28.el6_9",
		},
		{
			name:            "util-linux-ng-2.17.2-12.28.el6_9.2.src.rpm",
			sourceRPM:       "util-linux-ng-2.17.2-12.28.el6_9.2.src.rpm",
			expectedName:    "util-linux-ng",
			expectedVersion: "2.17.2-12.28.el6_9.2",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actualName, actualVersion := getNameAndELVersion(test.sourceRPM)
			assert.Equal(t, test.expectedName, actualName)
			assert.Equal(t, test.expectedVersion, actualVersion)
		})
	}
}

func intRef(i int) *int {
	return &i
}

func Test_RemoveBinaryPackagesByOverlap(t *testing.T) {
	tests := []struct {
		name             string
		sbom             catalogRelationships
		expectedPackages []string
	}{
		{
			name: "includes all packages without overlap",
			sbom: catalogWithOverlaps(
				[]string{":go@1.18", "apk:node@19.2-r1", "binary:python@3.9"},
				[]string{}),
			expectedPackages: []string{":go@1.18", "apk:node@19.2-r1", "binary:python@3.9"},
		},
		{
			name: "excludes single package by overlap",
			sbom: catalogWithOverlaps(
				[]string{"apk:go@1.18", "apk:node@19.2-r1", "binary:node@19.2"},
				[]string{"apk:node@19.2-r1 -> binary:node@19.2"}),
			expectedPackages: []string{"apk:go@1.18", "apk:node@19.2-r1"},
		},
		{
			name: "excludes multiple package by overlap",
			sbom: catalogWithOverlaps(
				[]string{"apk:go@1.18", "apk:node@19.2-r1", "binary:node@19.2", "apk:python@3.9-r9", ":python@3.9"},
				[]string{"apk:node@19.2-r1 -> binary:node@19.2", "apk:python@3.9-r9 -> :python@3.9"}),
			expectedPackages: []string{"apk:go@1.18", "apk:node@19.2-r1", "apk:python@3.9-r9"},
		},
		{
			name: "does not exclude with different types",
			sbom: catalogWithOverlaps(
				[]string{"rpm:node@19.2-r1", "apk:node@19.2"},
				[]string{"rpm:node@19.2-r1 -> apk:node@19.2"}),
			expectedPackages: []string{"apk:node@19.2", "rpm:node@19.2-r1"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			catalog := removePackagesByOverlap(test.sbom.collection, test.sbom.relationships)
			pkgs := FromCollection(catalog, SynthesisConfig{})
			var pkgNames []string
			for _, p := range pkgs {
				pkgNames = append(pkgNames, fmt.Sprintf("%s:%s@%s", p.Type, p.Name, p.Version))
			}
			assert.EqualValues(t, test.expectedPackages, pkgNames)
		})
	}
}

type catalogRelationships struct {
	collection    *syftPkg.Collection
	relationships []artifact.Relationship
}

func catalogWithOverlaps(packages []string, overlaps []string) catalogRelationships {
	var pkgs []syftPkg.Package
	var relationships []artifact.Relationship

	toPkg := func(str string) syftPkg.Package {
		var typ, name, version string
		s := strings.Split(strings.TrimSpace(str), ":")
		if len(s) > 1 {
			typ = s[0]
			str = s[1]
		}
		s = strings.Split(str, "@")
		name = s[0]
		if len(s) > 1 {
			version = s[1]
		}

		p := syftPkg.Package{
			Type:    syftPkg.Type(typ),
			Name:    name,
			Version: version,
		}
		p.SetID()

		return p
	}

	for _, pkg := range packages {
		p := toPkg(pkg)
		pkgs = append(pkgs, p)
	}

	for _, overlap := range overlaps {
		parts := strings.Split(overlap, "->")
		if len(parts) < 2 {
			panic("invalid overlap, use -> to specify, e.g.: pkg1->pkg2")
		}
		from := toPkg(parts[0])
		to := toPkg(parts[1])

		relationships = append(relationships, artifact.Relationship{
			From: from,
			To:   to,
			Type: artifact.OwnershipByFileOverlapRelationship,
		})
	}

	catalog := syftPkg.NewCollection(pkgs...)

	return catalogRelationships{
		collection:    catalog,
		relationships: relationships,
	}
}
