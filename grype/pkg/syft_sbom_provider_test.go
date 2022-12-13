package pkg

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/go-test/deep"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

func must(c pkg.CPE, e error) pkg.CPE {
	if e != nil {
		panic(e)
	}
	return c
}

func assertAs(expected string) assert.ErrorAssertionFunc {
	return func(t assert.TestingT, err error, i ...interface{}) bool {
		return assert.ErrorContains(t, errors.New(expected), err.Error())
	}
}

func TestDecodeStdin(t *testing.T) {
	tests := []struct {
		Name    string
		Input   string
		Key     string
		WantErr assert.ErrorAssertionFunc
		PkgsLen int
	}{
		{
			Name:    "no key",
			Input:   "test-fixtures/alpine.att.json",
			WantErr: assertAs("--key parameter is required to validate attestations"),
		},
		{
			Name:    "happy path",
			Input:   "test-fixtures/alpine.att.json",
			Key:     "test-fixtures/cosign.pub",
			WantErr: assert.NoError,
			PkgsLen: 14,
		},
		{
			Name:    "cycloneDX format",
			Input:   "test-fixtures/alpine.cdx.att.json",
			Key:     "test-fixtures/cosign.pub",
			WantErr: assert.NoError,
			PkgsLen: 14,
		},
		{
			Name:    "broken key",
			Input:   "test-fixtures/alpine.att.json",
			Key:     "test-fixtures/cosign_broken.pub",
			WantErr: assertAs("failed to verify attestation signature: cannot decode public key"),
		},
		{
			Name:    "different but valid key",
			Input:   "test-fixtures/alpine.att.json",
			Key:     "test-fixtures/another_cosign.pub",
			WantErr: assertAs("failed to verify attestation signature: key and signature don't match"),
		},
		{
			Name:    "sbom with intoto mime string",
			Input:   "test-fixtures/sbom-with-intoto-string.json",
			WantErr: assert.NoError,
			PkgsLen: 4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			f, err := os.Open(tt.Input)
			require.NoError(t, err)
			r, info, err := decodeStdin(f, ProviderConfig{
				SyftProviderConfig: SyftProviderConfig{
					AttestationPublicKey: tt.Key,
				},
			})
			tt.WantErr(t, err)

			if err == nil {
				require.NotNil(t, info)
				sbom, format, err := syft.Decode(r)
				require.NoError(t, err)
				require.NotNil(t, format)
				assert.Len(t, FromCatalog(sbom.Artifacts.PackageCatalog, SynthesisConfig{}), tt.PkgsLen)
			}
		})
	}
}

func TestParseAttestation(t *testing.T) {
	tests := []struct {
		Name    string
		Input   string
		Key     string
		WantErr assert.ErrorAssertionFunc
		PkgsLen int
	}{
		{
			Name:    "happy path with scheme",
			Input:   "att:test-fixtures/alpine.att.json",
			Key:     "test-fixtures/cosign.pub",
			WantErr: assert.NoError,
			PkgsLen: 14,
		},
		{
			Name:    "no scheme and no key",
			Input:   "test-fixtures/alpine.att.json",
			WantErr: assertAs("--key parameter is required to validate attestations"),
		},
		{
			Name:    "happy path without scheme",
			Input:   "test-fixtures/alpine.att.json",
			Key:     "test-fixtures/cosign.pub",
			WantErr: assert.NoError,
			PkgsLen: 14,
		},
		{
			Name:    "cycloneDX format",
			Input:   "test-fixtures/alpine.cdx.att.json",
			Key:     "test-fixtures/cosign.pub",
			WantErr: assert.NoError,
			PkgsLen: 14,
		},
		{
			Name:    "broken key",
			Input:   "test-fixtures/alpine.att.json",
			Key:     "test-fixtures/cosign_broken.pub",
			WantErr: assertAs("failed to verify attestation signature: cannot decode public key"),
		},
		{
			Name:    "different but valid key",
			Input:   "test-fixtures/alpine.att.json",
			Key:     "test-fixtures/another_cosign.pub",
			WantErr: assertAs("failed to verify attestation signature: key and signature don't match"),
		},
		{
			Name:    "not an attestation but has the scheme",
			Input:   "att:test-fixtures/syft-spring.json",
			WantErr: assertAs("invalid attestation payload"),
		},
		{
			Name:    "not an attestation but has key",
			Input:   "test-fixtures/syft-spring.json",
			Key:     "test-fixtures/cosign.pub",
			WantErr: assertAs("key is meant for attestation verification, your input is a plain SBOM and doesn't need it"),
		},
		{
			Name:    "not an attestation but has key and scheme",
			Input:   "att:test-fixtures/syft-spring.json",
			Key:     "test-fixtures/cosign.pub",
			WantErr: assertAs("invalid attestation payload"),
		},
		{
			Name:    "tampered attestation payload",
			Input:   "att:test-fixtures/alpine-tampered.att.json",
			Key:     "test-fixtures/cosign.pub",
			WantErr: assertAs("failed to verify attestation signature: key and signature don't match"),
		},
		{
			Name:    "tampered envelope predicate type",
			Input:   "att:test-fixtures/alpine-tampered.cdx.att.json",
			Key:     "test-fixtures/cosign.pub",
			WantErr: assertAs("failed to verify attestation signature: key and signature don't match"),
		},
		{
			Name:    "sbom with intoto mime string",
			Input:   "test-fixtures/sbom-with-intoto-string.json",
			WantErr: assert.NoError,
			PkgsLen: 4,
		},
		{
			Name:    "empty file",
			Input:   "test-fixtures/empty.json",
			WantErr: assertAs("cannot provide packages from the given source"),
		},
		{
			Name:    "invalid json",
			Input:   "test-fixtures/empty.json",
			WantErr: assertAs("cannot provide packages from the given source"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			pkgs, _, _, err := syftSBOMProvider(tt.Input, ProviderConfig{
				SyftProviderConfig: SyftProviderConfig{
					AttestationPublicKey: tt.Key,
				},
			})
			tt.WantErr(t, err)
			require.Len(t, pkgs, tt.PkgsLen)
		})
	}

}

func TestParseSyftJSON(t *testing.T) {
	tests := []struct {
		Fixture  string
		Packages []Package
		Context  Context
	}{
		{
			Fixture: "test-fixtures/syft-multiple-ecosystems.json",
			Packages: []Package{
				{
					Name:    "alpine-baselayout",
					Version: "3.2.0-r6",
					Locations: source.NewLocationSet(
						source.NewLocationFromCoordinates(source.Coordinates{
							RealPath:     "/lib/apk/db/installed",
							FileSystemID: "sha256:8d3ac3489996423f53d6087c81180006263b79f206d3fdec9e66f0e27ceb8759",
						}),
					),
					Language: "",
					Licenses: []string{
						"GPL-2.0-only",
					},
					Type: "apk",
					CPEs: []pkg.CPE{
						must(pkg.NewCPE("cpe:2.3:a:alpine:alpine_baselayout:3.2.0-r6:*:*:*:*:*:*:*")),
					},
					PURL: "pkg:alpine/alpine-baselayout@3.2.0-r6?arch=x86_64",
					Upstreams: []UpstreamPackage{
						{
							Name: "alpine-baselayout",
						},
					},
				},
				{
					Name:    "fake",
					Version: "1.2.0",
					Locations: source.NewLocationSet(
						source.NewLocationFromCoordinates(source.Coordinates{
							RealPath:     "/lib/apk/db/installed",
							FileSystemID: "sha256:93cf4cfb673c7e16a9e74f731d6767b70b92a0b7c9f59d06efd72fbff535371c",
						}),
					),
					Language: "lang",
					Licenses: []string{
						"LGPL-3.0-or-later",
					},
					Type: "dpkg",
					CPEs: []pkg.CPE{
						must(pkg.NewCPE("cpe:2.3:a:*:fake:1.2.0:*:*:*:*:*:*:*")),
						must(pkg.NewCPE("cpe:2.3:a:fake:fake:1.2.0:*:*:*:*:*:*:*")),
					},
					PURL: "pkg:deb/debian/fake@1.2.0?arch=x86_64",
					Upstreams: []UpstreamPackage{
						{
							Name:    "a-source",
							Version: "1.4.5",
						},
					},
				},
				{
					Name:    "gmp",
					Version: "6.2.0-r0",
					Locations: source.NewLocationSet(
						source.NewLocationFromCoordinates(source.Coordinates{
							RealPath:     "/lib/apk/db/installed",
							FileSystemID: "sha256:93cf4cfb673c7e16a9e74f731d6767b70b92a0b7c9f59d06efd72fbff535371c",
						}),
					),
					Language: "the-lang",
					Licenses: []string{
						"LGPL-3.0-or-later",
					},
					Type: "java-archive",
					CPEs: []pkg.CPE{
						must(pkg.NewCPE("cpe:2.3:a:*:gmp:6.2.0-r0:*:*:*:*:*:*:*")),
						must(pkg.NewCPE("cpe:2.3:a:gmp:gmp:6.2.0-r0:*:*:*:*:*:*:*")),
					},
					PURL:         "pkg:alpine/gmp@6.2.0-r0?arch=x86_64",
					MetadataType: JavaMetadataType,
					Metadata: JavaMetadata{
						PomArtifactID: "aid",
						PomGroupID:    "gid",
						ManifestName:  "a-name",
					},
				},
			},
			Context: Context{
				Source: &source.Metadata{
					Scheme: source.ImageScheme,
					ImageMetadata: source.ImageMetadata{
						UserInput: "alpine:fake",
						Layers: []source.LayerMetadata{
							{
								MediaType: "application/vnd.docker.image.rootfs.diff.tar.gzip",
								Digest:    "sha256:50644c29ef5a27c9a40c393a73ece2479de78325cae7d762ef3cdc19bf42dd0a",
								Size:      5570176,
							},
						},
						Size:           15879684,
						ID:             "sha256:fadf1294c09213b20d4d6fc84109584e1c102d185c2cae15144a87d29de65c6d",
						ManifestDigest: "sha256:1f6495428fb363e2d233e5df078b2b200635c4e51f0a3be34ecf09d44b547590",
						MediaType:      "application/vnd.docker.distribution.manifest.v2+json",
						Tags: []string{
							"alpine:fake",
						},
					},
					Path: "",
				},
				Distro: &linux.Release{
					Name:    "alpine",
					Version: "3.12.0",
				},
			},
		},
		springImageTestCase,
	}

	for _, test := range tests {
		t.Run(test.Fixture, func(t *testing.T) {
			pkgs, context, _, err := syftSBOMProvider(test.Fixture, ProviderConfig{})
			if err != nil {
				t.Fatalf("unable to parse: %+v", err)
			}

			context.Source.ImageMetadata.RawConfig = nil
			context.Source.ImageMetadata.RawManifest = nil

			for _, d := range deep.Equal(test.Packages, pkgs) {
				if strings.Contains(d, ".ID: ") {
					// today ID's get assigned by the catalog, which will change in the future. But in the meantime
					// that means that these IDs are random and should not be counted as a difference we care about in
					// this test.
					continue
				}
				t.Errorf("pkg diff: %s", d)
			}

			for _, d := range deep.Equal(test.Context, context) {
				if strings.Contains(d, "Distro.IDLike: <nil slice> != []") {
					continue
				}
				t.Errorf("ctx diff: %s", d)
			}
		})
	}
}

func TestParseSyftJSON_BadCPEs(t *testing.T) {
	pkgs, _, _, err := syftSBOMProvider("test-fixtures/syft-java-bad-cpes.json", ProviderConfig{})
	assert.NoError(t, err)
	assert.Len(t, pkgs, 1)
}

// Note that the fixture has been modified from the real syft output to include fewer packages, CPEs, layers,
// and package IDs are removed so that the test case variable isn't unwieldingly huge.
var springImageTestCase = struct {
	Fixture  string
	Packages []Package
	Context  Context
}{
	Fixture: "test-fixtures/syft-spring.json",
	Packages: []Package{
		{
			Name:    "charsets",
			Version: "",
			Locations: source.NewLocationSet(
				source.NewLocationFromCoordinates(source.Coordinates{
					RealPath:     "/usr/lib/jvm/java-8-openjdk-amd64/jre/lib/charsets.jar",
					FileSystemID: "sha256:a1a6ceadb701ab4e6c93b243dc2a0daedc8cee23a24203845ecccd5784cd1393",
				}),
			),
			Language: "java",
			Licenses: []string{},
			Type:     "java-archive",
			CPEs: []pkg.CPE{
				must(pkg.NewCPE("cpe:2.3:a:charsets:charsets:*:*:*:*:*:java:*:*")),
				must(pkg.NewCPE("cpe:2.3:a:charsets:charsets:*:*:*:*:*:maven:*:*")),
			},
			PURL:         "",
			MetadataType: JavaMetadataType,
			Metadata:     JavaMetadata{VirtualPath: "/usr/lib/jvm/java-8-openjdk-amd64/jre/lib/charsets.jar"},
		},
		{
			Name:    "tomcat-embed-el",
			Version: "9.0.27",
			Locations: source.NewLocationSet(
				source.NewLocationFromCoordinates(source.Coordinates{
					RealPath:     "/app/libs/tomcat-embed-el-9.0.27.jar",
					FileSystemID: "sha256:89504f083d3f15322f97ae240df44650203f24427860db1b3d32e66dd05940e4",
				}),
			),
			Language: "java",
			Licenses: []string{},
			Type:     "java-archive",
			CPEs: []pkg.CPE{
				must(pkg.NewCPE("cpe:2.3:a:tomcat_embed_el:tomcat-embed-el:9.0.27:*:*:*:*:java:*:*")),
				must(pkg.NewCPE("cpe:2.3:a:tomcat-embed-el:tomcat_embed_el:9.0.27:*:*:*:*:maven:*:*")),
			},
			PURL:         "",
			MetadataType: JavaMetadataType,
			Metadata:     JavaMetadata{VirtualPath: "/app/libs/tomcat-embed-el-9.0.27.jar"},
		},
	},
	Context: Context{
		Source: &source.Metadata{
			Scheme: source.ImageScheme,
			ImageMetadata: source.ImageMetadata{
				UserInput: "springio/gs-spring-boot-docker:latest",
				Layers: []source.LayerMetadata{
					{
						MediaType: "application/vnd.docker.image.rootfs.diff.tar.gzip",
						Digest:    "sha256:42a3027eaac150d2b8f516100921f4bd83b3dbc20bfe64124f686c072b49c602",
						Size:      1809479,
					},
				},
				Size:           142807921,
				ID:             "sha256:9065659c6e537b0364b7b1d3e5442a3a5aa56d755fb883d221e9e8b3637fb58e",
				ManifestDigest: "sha256:be3d8a5f700d4c45f3ed324b95d9f028f587c135bc85cf87e193414db521d533",
				MediaType:      "application/vnd.docker.distribution.manifest.v2+json",
				Tags: []string{
					"springio/gs-spring-boot-docker:latest",
				},
				RepoDigests: []string{"springio/gs-spring-boot-docker@sha256:39c2ffc784f5f34862e22c1f2ccdbcb62430736114c13f60111eabdb79decb08"},
			},
			Path: "",
		},
		Distro: &linux.Release{
			Name:    "debian",
			Version: "9",
		},
	},
}

func TestGetSBOMReader_EmptySBOM(t *testing.T) {
	sbomFile, err := os.CreateTemp("", "empty.sbom")
	require.NoError(t, err)
	defer func() {
		err := sbomFile.Close()
		assert.NoError(t, err)
	}()

	filepath := sbomFile.Name()
	userInput := "sbom:" + filepath

	_, err = getSBOMReader(userInput, ProviderConfig{})
	assert.ErrorAs(t, err, &errEmptySBOM{})
}
