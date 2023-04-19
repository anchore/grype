package pkg

import (
	"fmt"
	"strings"
	"testing"

	"github.com/scylladb/go-set"
	"github.com/scylladb/go-set/strset"
	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/file"
	syftFile "github.com/anchore/syft/syft/file"
	syftPkg "github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
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
				MetadataType: syftPkg.AlpmMetadataType,
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
				MetadataType: syftPkg.DpkgMetadataType,
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
			name: "rpm with source info",
			syftPkg: syftPkg.Package{
				MetadataType: syftPkg.RpmMetadataType,
				Metadata: syftPkg.RpmMetadata{
					Name:      "name-info",
					Version:   "version-info",
					Epoch:     intRef(30),
					Arch:      "arch-info",
					Release:   "release-info",
					SourceRpm: "sqlite-3.26.0-6.el8.src.rpm",
					Size:      40,
					License:   "license-info",
					Vendor:    "vendor-info",
					Files: []syftPkg.RpmdbFileRecord{
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
			name: "rpm with source info that matches the package info",
			syftPkg: syftPkg.Package{
				Name:         "sqlite",
				MetadataType: syftPkg.RpmMetadataType,
				Metadata: syftPkg.RpmMetadata{
					SourceRpm: "sqlite-3.26.0-6.el8.src.rpm",
				},
			},
			metadata: RpmMetadata{},
		},
		{
			name: "rpm with modularity label",
			syftPkg: syftPkg.Package{
				Name:         "sqlite",
				MetadataType: syftPkg.RpmMetadataType,
				Metadata: syftPkg.RpmMetadata{
					SourceRpm:       "sqlite-3.26.0-6.el8.src.rpm",
					ModularityLabel: "abc:2",
				},
			},
			metadata: RpmMetadata{ModularityLabel: "abc:2"},
		},
		{
			name: "java pkg",
			syftPkg: syftPkg.Package{
				MetadataType: syftPkg.JavaMetadataType,
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
				MetadataType: syftPkg.ApkMetadataType,
				Metadata: syftPkg.ApkMetadata{
					Package:       "libcurl-tools",
					OriginPackage: "libcurl",
					Maintainer:    "somone",
					Version:       "1.2.3",
					License:       "Apache",
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
				MetadataType: syftPkg.NpmPackageJSONMetadataType,
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
				MetadataType: syftPkg.PythonPackageMetadataType,
				Metadata: syftPkg.PythonPackageMetadata{
					Name:                 "a",
					Version:              "a",
					License:              "a",
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
				MetadataType: syftPkg.GemMetadataType,
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
				MetadataType: syftPkg.KbPackageMetadataType,
				Metadata: syftPkg.KbPackageMetadata{
					ProductID: "a",
					Kb:        "a",
				},
			},
		},
		{
			name: "rust-metadata",
			syftPkg: syftPkg.Package{
				MetadataType: syftPkg.RustCargoPackageMetadataType,
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
				MetadataType: syftPkg.GolangBinMetadataType,
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
				MetadataType: syftPkg.GolangModMetadataType,
				Metadata: syftPkg.GolangModMetadata{
					H1Digest: "h1:as234NweNNTNWEtt13nwNENTt",
				},
			},
			metadata: GolangModMetadata{
				H1Digest: "h1:as234NweNNTNWEtt13nwNENTt",
			},
		},
		{
			name: "php-composer-metadata",
			syftPkg: syftPkg.Package{
				MetadataType: syftPkg.PhpComposerJSONMetadataType,
				Metadata: syftPkg.PhpComposerJSONMetadata{
					Name:    "a",
					Version: "a",
				},
			},
		},
		{
			name: "dart-pub-metadata",
			syftPkg: syftPkg.Package{
				MetadataType: syftPkg.DartPubMetadataType,
				Metadata: syftPkg.DartPubMetadata{
					Name:    "a",
					Version: "a",
				},
			},
		},
		{
			name: "dotnet-metadata",
			syftPkg: syftPkg.Package{
				MetadataType: syftPkg.DotnetDepsMetadataType,
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
				MetadataType: syftPkg.ConanMetadataType,
				Metadata: syftPkg.ConanMetadata{
					Ref: "catch2/2.13.8",
				},
			},
		},
		{
			name: "cpp conan lock metadata",
			syftPkg: syftPkg.Package{
				MetadataType: syftPkg.ConanLockMetadataType,
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
				MetadataType: syftPkg.CocoapodsMetadataType,
				Metadata: syftPkg.CocoapodsMetadata{
					Checksum: "123eere234",
				},
			},
		},
		{
			name: "portage-metadata",
			syftPkg: syftPkg.Package{
				MetadataType: syftPkg.PortageMetadataType,
				Metadata: syftPkg.PortageMetadata{
					InstalledSize: 1,
					Files:         []syftPkg.PortageFileRecord{},
				},
			},
		},
		{
			name: "hackage-metadata",
			syftPkg: syftPkg.Package{
				MetadataType: syftPkg.HackageMetadataType,
				Metadata: syftPkg.HackageMetadata{
					Name:    "hackage",
					Version: "v0.0.1",
				},
			},
		},
		{
			name: "rebar-metadata",
			syftPkg: syftPkg.Package{
				MetadataType: syftPkg.RebarLockMetadataType,
				Metadata: syftPkg.RebarLockMetadata{
					Name:    "rebar",
					Version: "v0.1.1",
				},
			},
		},
		{
			name: "npm-package-lock-metadata",
			syftPkg: syftPkg.Package{
				MetadataType: syftPkg.NpmPackageLockJSONMetadataType,
				Metadata: syftPkg.NpmPackageLockJSONMetadata{
					Resolved:  "resolved",
					Integrity: "sha1:ab7d8979989b7a98d97",
				},
			},
		},
		{
			name: "mix-lock-metadata",
			syftPkg: syftPkg.Package{
				MetadataType: syftPkg.MixLockMetadataType,
				Metadata: syftPkg.MixLockMetadata{
					Name:    "mix-lock",
					Version: "v0.1.2",
				},
			},
		},
		{
			name: "pipfile-lock-metadata",
			syftPkg: syftPkg.Package{
				MetadataType: syftPkg.PythonPipfileLockMetadataType,
				Metadata: syftPkg.PythonPipfileLockMetadata{
					Hashes: []string{
						"sha1:ab8v88a8b88d8d8c88b8s765s47",
					},
					Index: "1",
				},
			},
		},
		{
			name: "binary-metadata",
			syftPkg: syftPkg.Package{
				MetadataType: syftPkg.BinaryMetadataType,
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
				MetadataType: syftPkg.NixStoreMetadataType,
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
				MetadataType: syftPkg.LinuxKernelMetadataType,
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
				MetadataType: syftPkg.LinuxKernelModuleMetadataType,
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
	}

	// capture each observed metadata type, we should see all of them relate to what syft provides by the end of testing
	expectedMetadataTypes := set.NewStringSet()
	for _, ty := range syftPkg.AllMetadataTypes {
		expectedMetadataTypes.Add(string(ty))
	}

	// run all of our cases
	observedMetadataTypes := set.NewStringSet()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if string(test.syftPkg.MetadataType) != "" {
				observedMetadataTypes.Add(string(test.syftPkg.MetadataType))
			}
			assert.Equal(t, test.metadata, New(test.syftPkg).Metadata, "unexpected metadata")
			assert.Equal(t, test.upstreams, New(test.syftPkg).Upstreams, "unexpected upstream")
		})
	}

	// did we see all possible metadata types? if not, then there is an uncovered case and this test should error out
	if !expectedMetadataTypes.IsEqual(observedMetadataTypes) {
		t.Errorf("did not observe all possible package metadata types: missing: %+v extra: %+v",
			strset.Difference(expectedMetadataTypes, observedMetadataTypes),
			strset.Difference(observedMetadataTypes, expectedMetadataTypes),
		)
	}
}

func TestFromCatalog_DoesNotPanic(t *testing.T) {
	catalog := syftPkg.NewCatalog()

	examplePackage := syftPkg.Package{
		Name:    "test",
		Version: "1.2.3",
		Locations: source.NewLocationSet(
			source.NewLocation("/test-path"),
		),
		Type: syftPkg.NpmPkg,
	}

	catalog.Add(examplePackage)
	// add it again!
	catalog.Add(examplePackage)

	assert.NotPanics(t, func() {
		_ = FromCatalog(catalog, SynthesisConfig{})
	})
}

func TestFromCatalog_GeneratesCPEs(t *testing.T) {
	catalog := syftPkg.NewCatalog()

	catalog.Add(syftPkg.Package{
		Name:    "first",
		Version: "1",
		CPEs: []cpe.CPE{
			{},
		},
	})

	catalog.Add(syftPkg.Package{
		Name:    "second",
		Version: "2",
	})

	// doesn't generate cpes when no flag
	pkgs := FromCatalog(catalog, SynthesisConfig{})
	assert.Len(t, pkgs[0].CPEs, 1)
	assert.Len(t, pkgs[1].CPEs, 0)

	// does generate cpes with the flag
	pkgs = FromCatalog(catalog, SynthesisConfig{
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
			catalog := removePackagesByOverlap(test.sbom.catalog, test.sbom.relationships)
			pkgs := FromCatalog(catalog, SynthesisConfig{})
			var pkgNames []string
			for _, p := range pkgs {
				pkgNames = append(pkgNames, fmt.Sprintf("%s:%s@%s", p.Type, p.Name, p.Version))
			}
			assert.EqualValues(t, test.expectedPackages, pkgNames)
		})
	}
}

type catalogRelationships struct {
	catalog       *syftPkg.Catalog
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

	catalog := syftPkg.NewCatalog(pkgs...)

	return catalogRelationships{
		catalog:       catalog,
		relationships: relationships,
	}
}
