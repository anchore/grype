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
)

func TestNew_UpstreamFromMetadata(t *testing.T) {
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
			name: "rpm archove with source info that matches the package info",
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
					ModularityLabel: "abc:2",
				},
			},
			metadata: RpmMetadata{ModularityLabel: "abc:2"},
		},
		{
			name: "java pkg",
			syftPkg: syftPkg.Package{
				Metadata: syftPkg.JavaArchive{
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
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.metadata, New(test.syftPkg).Metadata, "unexpected metadata")
			assert.Equal(t, test.upstreams, New(test.syftPkg).Upstreams, "unexpected upstream")
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
