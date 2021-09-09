package pkg

import (
	"testing"

	"github.com/anchore/syft/syft/file"
	syftPkg "github.com/anchore/syft/syft/pkg"
	"github.com/scylladb/go-set"
	"github.com/scylladb/go-set/strset"
	"github.com/stretchr/testify/assert"
)

func TestNew_MetadataExtraction(t *testing.T) {
	tests := []struct {
		name     string
		syftPkg  syftPkg.Package
		metadata interface{}
	}{
		{
			name: "dpkg-metadata",
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
			metadata: DpkgMetadata{
				Source: "src-info",
			},
		},
		{
			name: "rpmdb-metadata",
			syftPkg: syftPkg.Package{
				MetadataType: syftPkg.RpmdbMetadataType,
				Metadata: syftPkg.RpmdbMetadata{
					Name:      "name-info",
					Version:   "version-info",
					Epoch:     intRef(30),
					Arch:      "arch-info",
					Release:   "release-info",
					SourceRpm: "src-rpm-info",
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
				SourceRpm: "src-rpm-info",
			},
		},
		{
			name: "java-metadata",
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
		// below cases we assert that there is no mapped metadata
		{
			name: "apk-metadata",
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
			metadata: ApkMetadata{OriginPackage: "libcurl"},
		},
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
			metadata: nil,
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
			metadata: nil,
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
			metadata: nil,
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
			metadata: nil,
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
			metadata: nil,
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
			observedMetadataTypes.Add(string(test.syftPkg.MetadataType))
			assert.Equal(t, test.metadata, New(&test.syftPkg).Metadata)
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

func intRef(i int) *int {
	return &i
}
