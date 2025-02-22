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
	"github.com/anchore/syft/syft/linux"
	syftPkg "github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
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
				Metadata: syftPkg.AlpmDBEntry{
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
				Metadata: syftPkg.DpkgDBEntry{
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
			name: "rpm archive with source info",
			syftPkg: syftPkg.Package{
				Metadata: syftPkg.RpmArchive{
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
			name: "rpm db entry with source info",
			syftPkg: syftPkg.Package{
				Metadata: syftPkg.RpmDBEntry{
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
			name: "rpm archive with source info that matches the package info",
			syftPkg: syftPkg.Package{
				Name: "sqlite",
				Metadata: syftPkg.RpmArchive{
					SourceRpm: "sqlite-3.26.0-6.el8.src.rpm",
				},
			},
			metadata: RpmMetadata{},
		},
		{
			name: "rpm archive with modularity label",
			syftPkg: syftPkg.Package{
				Name: "sqlite",
				Metadata: syftPkg.RpmArchive{
					SourceRpm:       "sqlite-3.26.0-6.el8.src.rpm",
					ModularityLabel: strRef("abc:2"),
				},
			},
			metadata: RpmMetadata{ModularityLabel: strRef("abc:2")},
		},
		{
			name: "java pkg",
			syftPkg: syftPkg.Package{
				Metadata: syftPkg.JavaArchive{
					VirtualPath: "virtual-path-info",
					Manifest: &syftPkg.JavaManifest{
						Main: syftPkg.KeyValues{
							{
								Key:   "Name",
								Value: "main-section-name-info",
							},
						},
						Sections: []syftPkg.KeyValues{
							{
								{
									Key:   "named-section-key",
									Value: "named-section-value",
								},
							},
						},
					},
					PomProperties: &syftPkg.JavaPomProperties{
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
				Metadata: syftPkg.ApkDBEntry{
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
			metadata: ApkMetadata{Files: []ApkFileRecord{}},
		},
		// the below packages are those that have no metadata or upstream info to parse out
		{
			name: "npm-metadata",
			syftPkg: syftPkg.Package{
				Metadata: syftPkg.NpmPackage{
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
				Metadata: syftPkg.PythonPackage{
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
				Metadata: syftPkg.RubyGemspec{
					Name:     "a",
					Version:  "a",
					Homepage: "a",
				},
			},
		},
		{
			name: "kb-metadata",
			syftPkg: syftPkg.Package{
				Metadata: syftPkg.MicrosoftKbPatch{
					ProductID: "a",
					Kb:        "a",
				},
			},
		},
		{
			name: "rust-metadata",
			syftPkg: syftPkg.Package{
				Metadata: syftPkg.RustCargoLockEntry{
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
				Metadata: syftPkg.GolangBinaryBuildinfoEntry{
					BuildSettings:     syftPkg.KeyValues{},
					GoCompiledVersion: "1.0.0",
					H1Digest:          "a",
					MainModule:        "myMainModule",
				},
			},
			metadata: GolangBinMetadata{
				BuildSettings:     syftPkg.KeyValues{},
				GoCompiledVersion: "1.0.0",
				H1Digest:          "a",
				MainModule:        "myMainModule",
			},
		},
		{
			name: "golang-mod-metadata",
			syftPkg: syftPkg.Package{
				Metadata: syftPkg.GolangModuleEntry{
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
				Metadata: syftPkg.PhpComposerLockEntry{
					Name:    "a",
					Version: "a",
				},
			},
		},
		{
			name: "php-composer-installed-metadata",
			syftPkg: syftPkg.Package{
				Metadata: syftPkg.PhpComposerInstalledEntry{
					Name:    "a",
					Version: "a",
				},
			},
		},
		{
			name: "dart-pub-metadata",
			syftPkg: syftPkg.Package{
				Metadata: syftPkg.DartPubspecLockEntry{
					Name:    "a",
					Version: "a",
				},
			},
		},
		{
			name: "dotnet-metadata",
			syftPkg: syftPkg.Package{
				Metadata: syftPkg.DotnetDepsEntry{
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
				Metadata: syftPkg.ConanfileEntry{
					Ref: "catch2/2.13.8",
				},
			},
		},
		{
			name: "cpp conan v1 lock metadata",
			syftPkg: syftPkg.Package{
				Metadata: syftPkg.ConanV1LockEntry{
					Ref: "zlib/1.2.12",
					Options: syftPkg.KeyValues{
						{
							Key:   "fPIC",
							Value: "True",
						},
						{
							Key:   "shared",
							Value: "false",
						},
					},
					Path:    "all/conanfile.py",
					Context: "host",
				},
			},
		},
		{
			name: "cpp conan v2 lock metadata",
			syftPkg: syftPkg.Package{
				Metadata: syftPkg.ConanV2LockEntry{
					Ref:       "zlib/1.2.12",
					PackageID: "some-id",
				},
			},
		},
		{
			name: "cocoapods cocoapods-metadata",
			syftPkg: syftPkg.Package{
				Metadata: syftPkg.CocoaPodfileLockEntry{
					Checksum: "123eere234",
				},
			},
		},
		{
			name: "portage-metadata",
			syftPkg: syftPkg.Package{
				Metadata: syftPkg.PortageEntry{
					InstalledSize: 1,
					Files:         []syftPkg.PortageFileRecord{},
				},
			},
		},
		{
			name: "hackage-stack-lock-metadata",
			syftPkg: syftPkg.Package{
				Metadata: syftPkg.HackageStackYamlLockEntry{
					PkgHash: "some-hash",
				},
			},
		},
		{
			name: "hackage-stack-metadata",
			syftPkg: syftPkg.Package{
				Metadata: syftPkg.HackageStackYamlEntry{
					PkgHash: "some-hash",
				},
			},
		},
		{
			name: "rebar-metadata",
			syftPkg: syftPkg.Package{
				Metadata: syftPkg.ErlangRebarLockEntry{
					Name:    "rebar",
					Version: "v0.1.1",
				},
			},
		},
		{
			name: "npm-package-lock-metadata",
			syftPkg: syftPkg.Package{
				Metadata: syftPkg.NpmPackageLockEntry{
					Resolved:  "resolved",
					Integrity: "sha1:ab7d8979989b7a98d97",
				},
			},
		},
		{
			name: "mix-lock-metadata",
			syftPkg: syftPkg.Package{
				Metadata: syftPkg.ElixirMixLockEntry{
					Name:    "mix-lock",
					Version: "v0.1.2",
				},
			},
		},
		{
			name: "pipfile-lock-metadata",
			syftPkg: syftPkg.Package{
				Metadata: syftPkg.PythonPipfileLockEntry{
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
				Metadata: syftPkg.PythonRequirementsEntry{
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
				Metadata: syftPkg.BinarySignature{
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
				Metadata: syftPkg.NixStoreEntry{
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
				Metadata: syftPkg.LinuxKernel{
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
				Metadata: syftPkg.LinuxKernelModule{
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
				Metadata: syftPkg.RDescription{
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
				Metadata: syftPkg.DotnetPortableExecutableEntry{
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
				Metadata: syftPkg.SwiftPackageManagerResolvedEntry{
					Revision: "a",
				},
			},
		},
		{
			name: "swipl-pack-entry",
			syftPkg: syftPkg.Package{
				Metadata: syftPkg.SwiplPackEntry{
					Name:          "a",
					Version:       "a",
					Author:        "a",
					AuthorEmail:   "a",
					Packager:      "a",
					PackagerEmail: "a",
					Homepage:      "a",
					Dependencies: []string{
						"a",
					},
				},
			},
		},
		{
			name: "conaninfo-entry",
			syftPkg: syftPkg.Package{
				Metadata: syftPkg.ConaninfoEntry{
					Ref:       "a",
					PackageID: "a",
				},
			},
		},
		{
			name: "rust-binary-audit-entry",
			syftPkg: syftPkg.Package{
				Metadata: syftPkg.RustBinaryAuditEntry{
					Name:    "a",
					Version: "a",
					Source:  "a",
				},
			},
		},
		{
			name: "python-poetry-lock-entry",
			syftPkg: syftPkg.Package{
				Metadata: syftPkg.PythonPoetryLockEntry{Index: "some-index"},
			},
		},
		{
			name: "yarn-lock-entry",
			syftPkg: syftPkg.Package{
				Metadata: syftPkg.YarnLockEntry{
					Resolved:  "some-resolution",
					Integrity: "some-digest",
				},
			},
		},
		{
			name: "wordpress-plugin-entry",
			syftPkg: syftPkg.Package{
				Metadata: syftPkg.WordpressPluginEntry{
					PluginInstallDirectory: "a",
					Author:                 "a",
					AuthorURI:              "a",
				},
			},
		},
		{
			name: "elf-binary-package",
			syftPkg: syftPkg.Package{
				Metadata: syftPkg.ELFBinaryPackageNoteJSONPayload{
					Type:       "a",
					Vendor:     "a",
					System:     "a",
					SourceRepo: "a",
					Commit:     "a",
				},
			},
		},
		{
			name: "Php-pecl-entry",
			syftPkg: syftPkg.Package{
				Metadata: syftPkg.PhpPeclEntry{
					Name:    "a",
					Version: "a",
					License: []string{"a"},
				},
			},
		},
		{
			name: "lua-rocks-entry",
			syftPkg: syftPkg.Package{
				Metadata: syftPkg.LuaRocksPackage{
					Name:         "a",
					Version:      "a",
					License:      "a",
					Homepage:     "a",
					Description:  "a",
					URL:          "a",
					Dependencies: map[string]string{"b": "c"},
				},
			},
		},
		{
			name: "ocaml-entry",
			syftPkg: syftPkg.Package{
				Metadata: syftPkg.OpamPackage{
					Name:         "a",
					Version:      "a",
					Licenses:     []string{"a"},
					URL:          "a",
					Checksums:    []string{"a"},
					Homepage:     "a",
					Dependencies: []string{"a"},
				},
			},
		},
		{
			name: "jvm-installation-entry",
			syftPkg: syftPkg.Package{
				Metadata: syftPkg.JavaVMInstallation{
					Release: syftPkg.JavaVMRelease{
						Implementor:        "a",
						ImplementorVersion: "a",
						JavaRuntimeVersion: "b",
						JavaVersion:        "c",
						JavaVersionDate:    "a",
						Libc:               "a",
						Modules:            []string{"a"},
						OsArch:             "a",
						OsName:             "a",
						OsVersion:          "a",
						Source:             "a",
						BuildSource:        "a",
						BuildSourceRepo:    "a",
						SourceRepo:         "a",
						FullVersion:        "d",
						SemanticVersion:    "e",
						BuildInfo:          "a",
						JvmVariant:         "a",
						JvmVersion:         "a",
						ImageType:          "a",
						BuildType:          "a",
					},
					Files: []string{"a"},
				},
			},
			metadata: JavaVMInstallationMetadata{
				Release: JavaVMReleaseMetadata{
					JavaRuntimeVersion: "b",
					JavaVersion:        "c",
					FullVersion:        "d",
					SemanticVersion:    "e",
				},
			},
		},
		{
			name: "dotnet-package-lock-entry",
			syftPkg: syftPkg.Package{
				Metadata: syftPkg.DotnetPackagesLockEntry{
					Name:        "AutoMapper",
					Version:     "13.0.1",
					ContentHash: "/Fx1SbJ16qS7dU4i604Sle+U9VLX+WSNVJggk6MupKVkYvvBm4XqYaeFuf67diHefHKHs50uQIS2YEDFhPCakQ==",
					Type:        "Direct",
				},
			},
		},
		{
			name: "bitnami-sbom-entry",
			syftPkg: syftPkg.Package{
				Metadata: syftPkg.BitnamiSBOMEntry{
					Name:    "a",
					Version: "1",
				},
			},
		},
		{
			name: "terraform-lock-provider-entry",
			syftPkg: syftPkg.Package{
				Metadata: syftPkg.TerraformLockProviderEntry{
					URL:         "registry.terraform.io/hashicorp/aws",
					Version:     "5.72.1",
					Constraints: "> 5.72.0",
					Hashes: []string{
						"h1:jhd5O5o0CfZCNEwwN0EiDAzb7ApuFrtxJqa6HXW4EKE=",
						"zh:0dea6843836e926d33469b48b948744079023816d16a2ff7666bcfb6aa3522d4",
						"zh:195fa9513f75800a0d62797ebec75ee73e9b8c28d713fe9b63d3b1d1eec129b3",
					},
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

func Test_RemovePackagesByOverlap(t *testing.T) {
	tests := []struct {
		name             string
		sbom             *sbom.SBOM
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
			name: "does not exclude if OS package owns OS package",
			sbom: catalogWithOverlaps(
				[]string{"rpm:perl@5.3-r1", "rpm:libperl@5.3"},
				[]string{"rpm:perl@5.3-r1 -> rpm:libperl@5.3"}),
			expectedPackages: []string{"rpm:libperl@5.3", "rpm:perl@5.3-r1"},
		},
		{
			name: "does not exclude if owning package is non-OS",
			sbom: catalogWithOverlaps(
				[]string{"python:urllib3@1.2.3", "python:otherlib@1.2.3"},
				[]string{"python:urllib3@1.2.3 -> python:otherlib@1.2.3"}),
			expectedPackages: []string{"python:otherlib@1.2.3", "python:urllib3@1.2.3"},
		},
		{
			name: "excludes multiple package by overlap",
			sbom: catalogWithOverlaps(
				[]string{"apk:go@1.18", "apk:node@19.2-r1", "binary:node@19.2", "apk:python@3.9-r9", "binary:python@3.9"},
				[]string{"apk:node@19.2-r1 -> binary:node@19.2", "apk:python@3.9-r9 -> binary:python@3.9"}),
			expectedPackages: []string{"apk:go@1.18", "apk:node@19.2-r1", "apk:python@3.9-r9"},
		},
		{
			name: "does not exclude with different types",
			sbom: catalogWithOverlaps(
				[]string{"rpm:node@19.2-r1", "apk:node@19.2"},
				[]string{"rpm:node@19.2-r1 -> apk:node@19.2"}),
			expectedPackages: []string{"apk:node@19.2", "rpm:node@19.2-r1"},
		},
		{
			name: "does not exclude if OS package owns OS package",
			sbom: catalogWithOverlaps(
				[]string{"rpm:perl@5.3-r1", "rpm:libperl@5.3"},
				[]string{"rpm:perl@5.3-r1 -> rpm:libperl@5.3"}),
			expectedPackages: []string{"rpm:libperl@5.3", "rpm:perl@5.3-r1"},
		},
		{
			name: "does not exclude if owning package is non-OS",
			sbom: catalogWithOverlaps(
				[]string{"python:urllib3@1.2.3", "python:otherlib@1.2.3"},
				[]string{"python:urllib3@1.2.3 -> python:otherlib@1.2.3"}),
			expectedPackages: []string{"python:otherlib@1.2.3", "python:urllib3@1.2.3"},
		},
		{
			name: "python bindings for system RPM install",
			sbom: withDistro(catalogWithOverlaps(
				[]string{"rpm:python3-rpm@4.14.3-26.el8", "python:rpm@4.14.3"},
				[]string{"rpm:python3-rpm@4.14.3-26.el8 -> python:rpm@4.14.3"}), "rhel"),
			expectedPackages: []string{"rpm:python3-rpm@4.14.3-26.el8"},
		},
		{
			name: "amzn linux doesn't remove packages in this way",
			sbom: withDistro(catalogWithOverlaps(
				[]string{"rpm:python3-rpm@4.14.3-26.el8", "python:rpm@4.14.3"},
				[]string{"rpm:python3-rpm@4.14.3-26.el8 -> python:rpm@4.14.3"}), "amzn"),
			expectedPackages: []string{"rpm:python3-rpm@4.14.3-26.el8", "python:rpm@4.14.3"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			catalog := removePackagesByOverlap(test.sbom.Artifacts.Packages, test.sbom.Relationships, test.sbom.Artifacts.LinuxDistribution)
			pkgs := FromCollection(catalog, SynthesisConfig{})
			var pkgNames []string
			for _, p := range pkgs {
				pkgNames = append(pkgNames, fmt.Sprintf("%s:%s@%s", p.Type, p.Name, p.Version))
			}
			assert.EqualValues(t, test.expectedPackages, pkgNames)
		})
	}
}

func catalogWithOverlaps(packages []string, overlaps []string) *sbom.SBOM {
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

	for i, overlap := range overlaps {
		parts := strings.Split(overlap, "->")
		if len(parts) < 2 {
			panic("invalid overlap, use -> to specify, e.g.: pkg1->pkg2")
		}
		from := toPkg(parts[0])
		to := toPkg(parts[1])

		// The catalog will type check whether To or From is a pkg.Package or a *pkg.Package.
		// Previously, there was a bug where Grype assumed that From was always a pkg.Package.
		// Therefore, intentionally mix pointer and non-pointer packages to prevent Grype from
		// assuming which is which again. (The correct usage, calling catalog.Package, always
		// returns a *pkg.Package, and doesn't rely on any type assertion.)
		if i%2 == 0 {
			relationships = append(relationships, artifact.Relationship{
				From: &from,
				To:   &to,
				Type: artifact.OwnershipByFileOverlapRelationship,
			})
		} else {
			relationships = append(relationships, artifact.Relationship{
				From: from,
				To:   to,
				Type: artifact.OwnershipByFileOverlapRelationship,
			})
		}
	}

	catalog := syftPkg.NewCollection(pkgs...)

	return &sbom.SBOM{
		Artifacts: sbom.Artifacts{
			Packages: catalog,
		},
		Relationships: relationships,
	}
}

func withDistro(s *sbom.SBOM, id string) *sbom.SBOM {
	s.Artifacts.LinuxDistribution = &linux.Release{
		ID: id,
	}
	return s
}

func strRef(s string) *string {
	return &s
}
