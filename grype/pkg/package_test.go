package pkg

import (
	"testing"

	"github.com/scylladb/go-set"
	"github.com/scylladb/go-set/strset"
	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/file"
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
			name: "rpmdb with source info",
			syftPkg: syftPkg.Package{
				MetadataType: syftPkg.RpmdbMetadataType,
				Metadata: syftPkg.RpmdbMetadata{
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
			metadata: RpmdbMetadata{
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
			name: "rpmdb with source info that matches the package info",
			syftPkg: syftPkg.Package{
				Name:         "sqlite",
				MetadataType: syftPkg.RpmdbMetadataType,
				Metadata: syftPkg.RpmdbMetadata{
					SourceRpm: "sqlite-3.26.0-6.el8.src.rpm",
				},
			},
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
				},
			},
			metadata: JavaMetadata{
				VirtualPath:   "virtual-path-info",
				PomArtifactID: "pom-artifact-ID-info",
				PomGroupID:    "pom-group-ID-info",
				ManifestName:  "main-section-name-info",
			},
		},
		{
			name: "apk with source info",
			syftPkg: syftPkg.Package{
				MetadataType: syftPkg.ApkMetadataType,
				Metadata: syftPkg.ApkMetadata{
					Package:          "libcurl-tools",
					OriginPackage:    "libcurl",
					Maintainer:       "somone",
					Version:          "1.2.3",
					License:          "Apache",
					Architecture:     "a",
					URL:              "a",
					Description:      "a",
					Size:             1,
					InstalledSize:    1,
					PullDependencies: "a",
					PullChecksum:     "a",
					GitCommitOfAport: "a",
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
			name: "golang-bin-metadata",
			syftPkg: syftPkg.Package{
				MetadataType: syftPkg.GolangBinMetadataType,
				Metadata: syftPkg.GolangBinMetadata{
					GoCompiledVersion: "1.0.0",
					H1Digest:          "a",
				},
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
		Locations: []source.Location{
			source.NewLocation("/test-path"),
		},
		Type: syftPkg.NpmPkg,
	}

	catalog.Add(examplePackage)
	// add it again!
	catalog.Add(examplePackage)

	assert.NotPanics(t, func() {
		_ = FromCatalog(catalog, ProviderConfig{})
	})
}

func TestFromCatalog_GeneratesCPEs(t *testing.T) {
	catalog := syftPkg.NewCatalog()

	catalog.Add(syftPkg.Package{
		Name:    "first",
		Version: "1",
		CPEs: []syftPkg.CPE{
			{},
		},
	})

	catalog.Add(syftPkg.Package{
		Name:    "second",
		Version: "2",
	})

	// doesn't generate cpes when no flag
	pkgs := FromCatalog(catalog, ProviderConfig{})
	assert.Len(t, pkgs[0].CPEs, 1)
	assert.Len(t, pkgs[1].CPEs, 0)

	// does generate cpes with the flag
	pkgs = FromCatalog(catalog, ProviderConfig{
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
