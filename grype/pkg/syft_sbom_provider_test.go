package pkg

import (
	"slices"
	"strings"
	"testing"

	"github.com/go-test/deep"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

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
					Locations: file.NewLocationSet(
						file.NewLocationFromCoordinates(file.Coordinates{
							RealPath:     "/lib/apk/db/installed",
							FileSystemID: "sha256:8d3ac3489996423f53d6087c81180006263b79f206d3fdec9e66f0e27ceb8759",
						}),
					),
					Language: "",
					Licenses: []string{
						"GPL-2.0-only",
					},
					Type: "apk",
					CPEs: []cpe.CPE{
						cpe.Must("cpe:2.3:a:alpine:alpine_baselayout:3.2.0-r6:*:*:*:*:*:*:*", ""),
					},
					PURL: "pkg:alpine/alpine-baselayout@3.2.0-r6?arch=x86_64",
					Upstreams: []UpstreamPackage{
						{
							Name: "alpine-baselayout",
						},
					},
					Metadata: ApkMetadata{
						Files: []ApkFileRecord{
							{Path: "/dev"},
							{Path: "/dev/pts"},
							{Path: "/dev/shm"},
							{Path: "/etc"},
							{Path: "/etc/fstab"},
							{Path: "/etc/group"},
							{Path: "/etc/hostname"},
							{Path: "/etc/hosts"},
							{Path: "/etc/inittab"},
							{Path: "/etc/modules"},
							{Path: "/etc/motd"},
							{Path: "/etc/mtab"},
							{Path: "/etc/passwd"},
							{Path: "/etc/profile"},
							{Path: "/etc/protocols"},
							{Path: "/etc/services"},
							{Path: "/etc/shadow"},
							{Path: "/etc/shells"},
							{Path: "/etc/sysctl.conf"},
							{Path: "/etc/apk"},
							{Path: "/etc/conf.d"},
							{Path: "/etc/crontabs"},
							{Path: "/etc/crontabs/root"},
							{Path: "/etc/init.d"},
							{Path: "/etc/modprobe.d"},
							{Path: "/etc/modprobe.d/aliases.conf"},
							{Path: "/etc/modprobe.d/blacklist.conf"},
							{Path: "/etc/modprobe.d/i386.conf"},
							{Path: "/etc/modprobe.d/kms.conf"},
							{Path: "/etc/modules-load.d"},
							{Path: "/etc/network"},
							{Path: "/etc/network/if-down.d"},
							{Path: "/etc/network/if-post-down.d"},
							{Path: "/etc/network/if-pre-up.d"},
							{Path: "/etc/network/if-up.d"},
							{Path: "/etc/opt"},
							{Path: "/etc/periodic"},
							{Path: "/etc/periodic/15min"},
							{Path: "/etc/periodic/daily"},
							{Path: "/etc/periodic/hourly"},
							{Path: "/etc/periodic/monthly"},
							{Path: "/etc/periodic/weekly"},
							{Path: "/etc/profile.d"},
							{Path: "/etc/profile.d/README"},
							{Path: "/etc/profile.d/color_prompt.sh.disabled"},
							{Path: "/etc/profile.d/locale.sh"},
							{Path: "/etc/sysctl.d"},
							{Path: "/home"},
							{Path: "/lib"},
							{Path: "/lib/firmware"},
							{Path: "/lib/mdev"},
							{Path: "/lib/modules-load.d"},
							{Path: "/lib/sysctl.d"},
							{Path: "/lib/sysctl.d/00-alpine.conf"},
							{Path: "/media"},
							{Path: "/media/cdrom"},
							{Path: "/media/floppy"},
							{Path: "/media/usb"},
							{Path: "/mnt"},
							{Path: "/opt"},
							{Path: "/proc"},
							{Path: "/root"},
							{Path: "/run"},
							{Path: "/sbin"},
							{Path: "/sbin/mkmntdirs"},
							{Path: "/srv"},
							{Path: "/sys"},
							{Path: "/tmp"},
							{Path: "/usr"},
							{Path: "/usr/lib"},
							{Path: "/usr/lib/modules-load.d"},
							{Path: "/usr/local"},
							{Path: "/usr/local/bin"},
							{Path: "/usr/local/lib"},
							{Path: "/usr/local/share"},
							{Path: "/usr/sbin"},
							{Path: "/usr/share"},
							{Path: "/usr/share/man"},
							{Path: "/usr/share/misc"},
							{Path: "/var"},
							{Path: "/var/run"},
							{Path: "/var/cache"},
							{Path: "/var/cache/misc"},
							{Path: "/var/empty"},
							{Path: "/var/lib"},
							{Path: "/var/lib/misc"},
							{Path: "/var/local"},
							{Path: "/var/lock"},
							{Path: "/var/lock/subsys"},
							{Path: "/var/log"},
							{Path: "/var/mail"},
							{Path: "/var/opt"},
							{Path: "/var/spool"},
							{Path: "/var/spool/mail"},
							{Path: "/var/spool/cron"},
							{Path: "/var/spool/cron/crontabs"},
							{Path: "/var/tmp"},
						},
					},
				},
				{
					Name:    "fake",
					Version: "1.2.0",
					Locations: file.NewLocationSet(
						file.NewLocationFromCoordinates(file.Coordinates{
							RealPath:     "/lib/apk/db/installed",
							FileSystemID: "sha256:93cf4cfb673c7e16a9e74f731d6767b70b92a0b7c9f59d06efd72fbff535371c",
						}),
					),
					Language: "lang",
					Licenses: []string{
						"LGPL-3.0-or-later",
					},
					Type: "dpkg",
					CPEs: []cpe.CPE{
						cpe.Must("cpe:2.3:a:*:fake:1.2.0:*:*:*:*:*:*:*", ""),
						cpe.Must("cpe:2.3:a:fake:fake:1.2.0:*:*:*:*:*:*:*", ""),
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
					Locations: file.NewLocationSet(
						file.NewLocationFromCoordinates(file.Coordinates{
							RealPath:     "/lib/apk/db/installed",
							FileSystemID: "sha256:93cf4cfb673c7e16a9e74f731d6767b70b92a0b7c9f59d06efd72fbff535371c",
						}),
					),
					Language: "the-lang",
					Licenses: []string{
						"LGPL-3.0-or-later",
					},
					Type: "java-archive",
					CPEs: []cpe.CPE{
						cpe.Must("cpe:2.3:a:*:gmp:6.2.0-r0:*:*:*:*:*:*:*", ""),
						cpe.Must("cpe:2.3:a:gmp:gmp:6.2.0-r0:*:*:*:*:*:*:*", ""),
					},
					PURL: "pkg:alpine/gmp@6.2.0-r0?arch=x86_64",
					Metadata: JavaMetadata{
						PomArtifactID: "aid",
						PomGroupID:    "gid",
						ManifestName:  "a-name",
					},
				},
			},
			Context: Context{
				Source: &source.Description{
					Metadata: source.ImageMetadata{
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
				},
				Distro: &distro.Distro{
					Type:    "alpine",
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

			if m, ok := context.Source.Metadata.(source.ImageMetadata); ok {
				m.RawConfig = nil
				m.RawManifest = nil

				context.Source.Metadata = m
			}

			for _, d := range deep.Equal(test.Packages, pkgs) {
				if strings.Contains(d, ".ID: ") {
					// today ID's get assigned by the collection, which will change in the future. But in the meantime
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
			Locations: file.NewLocationSet(
				file.NewLocationFromCoordinates(file.Coordinates{
					RealPath:     "/usr/lib/jvm/java-8-openjdk-amd64/jre/lib/charsets.jar",
					FileSystemID: "sha256:a1a6ceadb701ab4e6c93b243dc2a0daedc8cee23a24203845ecccd5784cd1393",
				}),
			),
			Language: "java",
			Licenses: []string{},
			Type:     "java-archive",
			CPEs: []cpe.CPE{
				cpe.Must("cpe:2.3:a:charsets:charsets:*:*:*:*:*:java:*:*", ""),
				cpe.Must("cpe:2.3:a:charsets:charsets:*:*:*:*:*:maven:*:*", ""),
			},
			PURL:     "",
			Metadata: JavaMetadata{VirtualPath: "/usr/lib/jvm/java-8-openjdk-amd64/jre/lib/charsets.jar"},
		},
		{
			Name:    "tomcat-embed-el",
			Version: "9.0.27",
			Locations: file.NewLocationSet(
				file.NewLocationFromCoordinates(file.Coordinates{
					RealPath:     "/app/libs/tomcat-embed-el-9.0.27.jar",
					FileSystemID: "sha256:89504f083d3f15322f97ae240df44650203f24427860db1b3d32e66dd05940e4",
				}),
			),
			Language: "java",
			Licenses: []string{},
			Type:     "java-archive",
			CPEs: []cpe.CPE{
				cpe.Must("cpe:2.3:a:tomcat_embed_el:tomcat-embed-el:9.0.27:*:*:*:*:java:*:*", ""),
				cpe.Must("cpe:2.3:a:tomcat-embed-el:tomcat_embed_el:9.0.27:*:*:*:*:maven:*:*", ""),
			},
			PURL:     "",
			Metadata: JavaMetadata{VirtualPath: "/app/libs/tomcat-embed-el-9.0.27.jar"},
		},
	},
	Context: Context{
		Source: &source.Description{
			Metadata: source.ImageMetadata{
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
		},
		Distro: &distro.Distro{
			Type:    "debian",
			Version: "9",
		},
	},
}

func Test_PurlList(t *testing.T) {
	tests := []struct {
		name      string
		userInput string
		context   Context
		pkgs      []Package
		wantErr   require.ErrorAssertionFunc
	}{
		{
			name:      "takes multiple purls",
			userInput: "purl:test-fixtures/purl/valid-purl.txt",
			context: Context{
				Distro: &distro.Distro{
					Type:    "debian",
					IDLike:  []string{"debian"},
					Version: "8",
				},
				Source: &source.Description{
					Metadata: SBOMFileMetadata{
						Path: "test-fixtures/purl/valid-purl.txt",
					},
				},
			},
			pkgs: []Package{
				{
					Name:    "ant",
					Version: "1.10.8",
					Type:    pkg.JavaPkg,
					PURL:    "pkg:maven/org.apache.ant/ant@1.10.8",
					Metadata: JavaMetadata{
						PomArtifactID: "ant",
						PomGroupID:    "org.apache.ant",
					},
				},
				{
					Name:    "log4j-core",
					Version: "2.14.1",
					Type:    pkg.JavaPkg,
					PURL:    "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
					Metadata: JavaMetadata{
						PomArtifactID: "log4j-core",
						PomGroupID:    "org.apache.logging.log4j",
					},
				},
				{
					Name:    "sysv-rc",
					Version: "2.88dsf-59",
					Type:    pkg.DebPkg,
					PURL:    "pkg:deb/debian/sysv-rc@2.88dsf-59?arch=all&distro=debian-8&upstream=sysvinit",
					Distro:  &distro.Distro{Type: distro.Debian, Version: "8", Codename: "", IDLike: []string{"debian"}},
					Upstreams: []UpstreamPackage{
						{
							Name: "sysvinit",
						},
					},
				},
			},
		},
		{
			name:      "infer context when distro is present for multiple similar purls",
			userInput: "purl:test-fixtures/purl/homogeneous-os.txt",
			context: Context{
				Distro: &distro.Distro{
					Type:    "alpine",
					IDLike:  []string{"alpine"},
					Version: "3.20.3",
				},
				Source: &source.Description{
					Metadata: SBOMFileMetadata{
						Path: "test-fixtures/purl/homogeneous-os.txt",
					},
				},
			},
			pkgs: []Package{
				{
					Name:    "openssl",
					Version: "3.2.1",
					Type:    pkg.ApkPkg,
					PURL:    "pkg:apk/openssl@3.2.1?arch=aarch64&distro=alpine-3.20.3",
					Distro:  &distro.Distro{Type: distro.Alpine, Version: "3.20.3", Codename: "", IDLike: []string{"alpine"}},
				},
				{
					Name:    "curl",
					Version: "7.61.1",
					Type:    pkg.ApkPkg,
					PURL:    "pkg:apk/curl@7.61.1?arch=aarch64&distro=alpine-3.20.3",
					Distro:  &distro.Distro{Type: distro.Alpine, Version: "3.20.3", Codename: "", IDLike: []string{"alpine"}},
				},
			},
		},
		{
			name:      "different distro info in purls does not infer context",
			userInput: "purl:test-fixtures/purl/different-os.txt",
			context: Context{
				// important: no distro info inferred
				Source: &source.Description{
					Metadata: SBOMFileMetadata{
						Path: "test-fixtures/purl/different-os.txt",
					},
				},
			},
			pkgs: []Package{
				{
					Name:    "openssl",
					Version: "3.2.1",
					Type:    pkg.ApkPkg,
					PURL:    "pkg:apk/openssl@3.2.1?arch=aarch64&distro=alpine-3.20.3",
					Distro:  &distro.Distro{Type: distro.Alpine, Version: "3.20.3", Codename: "", IDLike: []string{"alpine"}},
				},
				{
					Name:    "curl",
					Version: "7.61.1",
					Type:    pkg.ApkPkg,
					PURL:    "pkg:apk/curl@7.61.1?arch=aarch64&distro=alpine-3.20.2",
					Distro:  &distro.Distro{Type: distro.Alpine, Version: "3.20.2", Codename: "", IDLike: []string{"alpine"}},
				},
			},
		},
		{
			name:      "fails on path with nonexistent file",
			userInput: "purl:tttt/empty.txt",
			wantErr:   require.Error,
		},
		{
			name:      "fails on invalid path",
			userInput: "purl:~&&",
			wantErr:   require.Error,
		},
		{
			name:      "fails for empty purl file",
			userInput: "purl:test-fixtures/purl/empty.json",
			wantErr:   require.Error,
		},
		{
			name:      "fails on invalid purl in file",
			userInput: "purl:test-fixtures/purl/invalid-purl.txt",
			wantErr:   require.Error,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.wantErr == nil {
				tc.wantErr = require.NoError
			}

			packages, ctx, _, err := Provide(tc.userInput, ProviderConfig{})

			tc.wantErr(t, err)
			if err != nil {
				require.Nil(t, packages)
				return
			}

			if d := cmp.Diff(tc.context, ctx, diffOpts...); d != "" {
				t.Errorf("unexpected context (-want +got):\n%s", d)
			}
			require.Len(t, packages, len(tc.pkgs))

			slices.SortFunc(packages, func(a, b Package) int {
				return strings.Compare(a.Name, b.Name)
			})
			slices.SortFunc(tc.pkgs, func(a, b Package) int {
				return strings.Compare(a.Name, b.Name)
			})

			for idx, expected := range tc.pkgs {
				if d := cmp.Diff(expected, packages[idx], diffOpts...); d != "" {
					t.Errorf("unexpected context (-want +got):\n%s", d)
				}
			}
		})
	}
}
