package pkg

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

func Test_PurlProvider(t *testing.T) {
	tests := []struct {
		name      string
		userInput string
		context   Context
		pkgs      []Package
		wantErr   require.ErrorAssertionFunc
	}{
		{
			name:      "takes a single purl",
			userInput: "pkg:apk/curl@7.61.1",
			context: Context{
				Source: &source.Description{
					Metadata: PURLLiteralMetadata{
						PURL: "pkg:apk/curl@7.61.1",
					},
				},
			},
			pkgs: []Package{
				{
					Name:    "curl",
					Version: "7.61.1",
					Type:    pkg.ApkPkg,
					PURL:    "pkg:apk/curl@7.61.1",
				},
			},
		},
		{
			name:      "os with codename",
			userInput: "pkg:deb/debian/sysv-rc@2.88dsf-59?arch=all&distro=debian-jessie&upstream=sysvinit",
			context: Context{
				Distro: &distro.Distro{
					Type:     "debian",
					IDLike:   []string{"debian"},
					Codename: "jessie", // important!
				},
				Source: &source.Description{
					Metadata: PURLLiteralMetadata{
						PURL: "pkg:deb/debian/sysv-rc@2.88dsf-59?arch=all&distro=debian-jessie&upstream=sysvinit",
					},
				},
			},
			pkgs: []Package{
				{
					Name:    "sysv-rc",
					Version: "2.88dsf-59",
					Type:    pkg.DebPkg,
					PURL:    "pkg:deb/debian/sysv-rc@2.88dsf-59?arch=all&distro=debian-jessie&upstream=sysvinit",
					Distro:  &distro.Distro{Type: distro.Debian, Version: "", Codename: "jessie", IDLike: []string{"debian"}},
					Upstreams: []UpstreamPackage{
						{
							Name: "sysvinit",
						},
					},
				},
			},
		},
		{
			name:      "default upstream",
			userInput: "pkg:apk/libcrypto3@3.3.2?upstream=openssl",
			context: Context{
				Source: &source.Description{
					Metadata: PURLLiteralMetadata{
						PURL: "pkg:apk/libcrypto3@3.3.2?upstream=openssl",
					},
				},
			},
			pkgs: []Package{
				{
					Name:    "libcrypto3",
					Version: "3.3.2",
					Type:    pkg.ApkPkg,
					PURL:    "pkg:apk/libcrypto3@3.3.2?upstream=openssl",
					Upstreams: []UpstreamPackage{
						{
							Name: "openssl",
						},
					},
				},
			},
		},
		{
			name:      "upstream with version",
			userInput: "pkg:apk/libcrypto3@3.3.2?upstream=openssl%403.2.1", // %40 is @
			context: Context{
				Source: &source.Description{
					Metadata: PURLLiteralMetadata{
						PURL: "pkg:apk/libcrypto3@3.3.2?upstream=openssl%403.2.1",
					},
				},
			},
			pkgs: []Package{
				{
					Name:    "libcrypto3",
					Version: "3.3.2",
					Type:    pkg.ApkPkg,
					PURL:    "pkg:apk/libcrypto3@3.3.2?upstream=openssl%403.2.1",
					Upstreams: []UpstreamPackage{
						{
							Name:    "openssl",
							Version: "3.2.1",
						},
					},
				},
			},
		},
		{
			name:      "upstream for source RPM",
			userInput: "pkg:rpm/redhat/systemd-x@239-82.el8_10.2?arch=aarch64&distro=rhel-8.10&upstream=systemd-239-82.el8_10.2.src.rpm",
			context: Context{
				Distro: &distro.Distro{
					Type:    "redhat",
					IDLike:  []string{"rhel"},
					Version: "8.10",
				},
				Source: &source.Description{
					Metadata: PURLLiteralMetadata{
						PURL: "pkg:rpm/redhat/systemd-x@239-82.el8_10.2?arch=aarch64&distro=rhel-8.10&upstream=systemd-239-82.el8_10.2.src.rpm",
					},
				},
			},
			pkgs: []Package{
				{
					Name:    "systemd-x",
					Version: "239-82.el8_10.2",
					Type:    pkg.RpmPkg,
					PURL:    "pkg:rpm/redhat/systemd-x@239-82.el8_10.2?arch=aarch64&distro=rhel-8.10&upstream=systemd-239-82.el8_10.2.src.rpm",
					Distro:  &distro.Distro{Type: distro.RedHat, Version: "8.10", Codename: "", IDLike: []string{"rhel"}},
					Upstreams: []UpstreamPackage{
						{
							Name:    "systemd",
							Version: "239-82.el8_10.2",
						},
					},
				},
			},
		},
		{
			name:      "RPM with epoch",
			userInput: "pkg:rpm/redhat/dbus-common@1.12.8-26.el8?arch=noarch&distro=rhel-8.10&epoch=1&upstream=dbus-1.12.8-26.el8.src.rpm",
			context: Context{
				Distro: &distro.Distro{
					Type:    "redhat",
					IDLike:  []string{"rhel"},
					Version: "8.10",
				},
				Source: &source.Description{
					Metadata: PURLLiteralMetadata{
						PURL: "pkg:rpm/redhat/dbus-common@1.12.8-26.el8?arch=noarch&distro=rhel-8.10&epoch=1&upstream=dbus-1.12.8-26.el8.src.rpm",
					},
				},
			},
			pkgs: []Package{
				{
					Name:    "dbus-common",
					Version: "1:1.12.8-26.el8",
					Type:    pkg.RpmPkg,
					PURL:    "pkg:rpm/redhat/dbus-common@1.12.8-26.el8?arch=noarch&distro=rhel-8.10&epoch=1&upstream=dbus-1.12.8-26.el8.src.rpm",
					Distro:  &distro.Distro{Type: distro.RedHat, Version: "8.10", Codename: "", IDLike: []string{"rhel"}},
					Upstreams: []UpstreamPackage{
						{
							Name:    "dbus",
							Version: "1.12.8-26.el8",
						},
					},
				},
			},
		},
		{
			name:      "infer context when distro is present for single purl",
			userInput: "pkg:apk/curl@7.61.1?arch=aarch64&distro=alpine-3.20.3",
			context: Context{
				Distro: &distro.Distro{
					Type:    "alpine",
					IDLike:  []string{"alpine"},
					Version: "3.20.3",
				},
				Source: &source.Description{
					Metadata: PURLLiteralMetadata{
						PURL: "pkg:apk/curl@7.61.1?arch=aarch64&distro=alpine-3.20.3",
					},
				},
			},
			pkgs: []Package{
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
			name:      "include namespace in name when purl is type Golang",
			userInput: "pkg:golang/k8s.io/ingress-nginx@v1.11.2",
			context: Context{
				Source: &source.Description{
					Metadata: PURLLiteralMetadata{PURL: "pkg:golang/k8s.io/ingress-nginx@v1.11.2"},
				},
			},
			pkgs: []Package{
				{
					Name:    "k8s.io/ingress-nginx",
					Version: "v1.11.2",
					Type:    pkg.GoModulePkg,
					PURL:    "pkg:golang/k8s.io/ingress-nginx@v1.11.2",
				},
			},
		},
		{
			name:      "include complex namespace in name when purl is type Golang",
			userInput: "pkg:golang/github.com/wazuh/wazuh@v4.5.0",
			context: Context{
				Source: &source.Description{
					Metadata: PURLLiteralMetadata{PURL: "pkg:golang/github.com/wazuh/wazuh@v4.5.0"},
				},
			},
			pkgs: []Package{
				{
					Name:    "github.com/wazuh/wazuh",
					Version: "v4.5.0",
					Type:    pkg.GoModulePkg,
					PURL:    "pkg:golang/github.com/wazuh/wazuh@v4.5.0",
				},
			},
		},
		{
			name:      "do not include namespace when given blank input blank",
			userInput: "pkg:golang/wazuh@v4.5.0",
			context: Context{
				Source: &source.Description{
					Metadata: PURLLiteralMetadata{PURL: "pkg:golang/wazuh@v4.5.0"},
				},
			},
			pkgs: []Package{
				{
					Name:    "wazuh",
					Version: "v4.5.0",
					Type:    pkg.GoModulePkg,
					PURL:    "pkg:golang/wazuh@v4.5.0",
				},
			},
		},
		{
			name:      "fails on purl list input",
			userInput: "purl:test-fixtures/purl/invalid-purl.txt",
			wantErr:   require.Error,
		},
		{
			name:      "invalid prefix",
			userInput: "dir:test-fixtures/purl",
			wantErr:   require.Error,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.wantErr == nil {
				tc.wantErr = require.NoError
			}

			packages, ctx, gotSBOM, err := purlProvider(tc.userInput, ProviderConfig{})
			setContextDistro(packages, &ctx, gotSBOM)

			tc.wantErr(t, err)
			if err != nil {
				require.Nil(t, packages)
				return
			}

			if d := cmp.Diff(tc.context, ctx, diffOpts...); d != "" {
				t.Errorf("unexpected context (-want +got):\n%s", d)
			}
			require.Len(t, packages, len(tc.pkgs))
			for idx, expected := range tc.pkgs {
				if d := cmp.Diff(expected, packages[idx], diffOpts...); d != "" {
					t.Errorf("unexpected context (-want +got):\n%s", d)
				}
			}
		})
	}
}

var diffOpts = []cmp.Option{
	cmpopts.IgnoreFields(Package{}, "ID", "Locations", "Licenses", "Language", "CPEs"),
	cmpopts.IgnoreUnexported(distro.Distro{}),
}
