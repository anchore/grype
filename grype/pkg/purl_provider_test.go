package pkg

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

var diffOpts = []cmp.Option{
	cmpopts.IgnoreFields(Package{}, "ID", "Locations", "Licenses", "Language", "CPEs"),
	cmpopts.IgnoreUnexported(distro.Distro{}),
}

func Test_PurlProvider(t *testing.T) {

	tests := []struct {
		name        string
		userInput   string
		channels    []distro.FixChannel
		wantContext Context
		wantPkgs    []Package
		wantErr     require.ErrorAssertionFunc
	}{
		{
			name:      "takes a single purl",
			userInput: "pkg:apk/curl@7.61.1",
			channels:  testFixChannels(),
			wantContext: Context{
				Source: &source.Description{
					Metadata: PURLLiteralMetadata{
						PURL: "pkg:apk/curl@7.61.1",
					},
				},
			},
			wantPkgs: []Package{
				{
					Name:    "curl",
					Version: "7.61.1",
					Type:    pkg.ApkPkg,
					PURL:    "pkg:apk/curl@7.61.1",
				},
			},
		},
		{
			name:      "java metadata decoded from purl",
			userInput: "pkg:maven/org.apache.commons/commons-lang3@3.12.0",
			channels:  testFixChannels(),
			wantContext: Context{
				Source: &source.Description{
					Metadata: PURLLiteralMetadata{
						PURL: "pkg:maven/org.apache.commons/commons-lang3@3.12.0",
					},
				},
			},
			wantPkgs: []Package{
				{
					Name:    "commons-lang3",
					Version: "3.12.0",
					Type:    pkg.JavaPkg,
					PURL:    "pkg:maven/org.apache.commons/commons-lang3@3.12.0",
					Metadata: JavaMetadata{
						PomArtifactID: "commons-lang3",
						PomGroupID:    "org.apache.commons",
					},
				},
			},
		},
		{
			name:      "os with codename",
			userInput: "pkg:deb/debian/sysv-rc@2.88dsf-59?arch=all&distro=debian-jessie&upstream=sysvinit",
			channels:  testFixChannels(),
			wantContext: Context{
				Source: &source.Description{
					Metadata: PURLLiteralMetadata{
						PURL: "pkg:deb/debian/sysv-rc@2.88dsf-59?arch=all&distro=debian-jessie&upstream=sysvinit",
					},
				},
			},
			wantPkgs: []Package{
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
			channels:  testFixChannels(),
			wantContext: Context{
				Source: &source.Description{
					Metadata: PURLLiteralMetadata{
						PURL: "pkg:apk/libcrypto3@3.3.2?upstream=openssl",
					},
				},
			},
			wantPkgs: []Package{
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
			channels:  testFixChannels(),
			wantContext: Context{
				Source: &source.Description{
					Metadata: PURLLiteralMetadata{
						PURL: "pkg:apk/libcrypto3@3.3.2?upstream=openssl%403.2.1",
					},
				},
			},
			wantPkgs: []Package{
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
			channels:  testFixChannels(),
			wantContext: Context{
				Source: &source.Description{
					Metadata: PURLLiteralMetadata{
						PURL: "pkg:rpm/redhat/systemd-x@239-82.el8_10.2?arch=aarch64&distro=rhel-8.10&upstream=systemd-239-82.el8_10.2.src.rpm",
					},
				},
			},
			wantPkgs: []Package{
				{
					Name:    "systemd-x",
					Version: "239-82.el8_10.2",
					Type:    pkg.RpmPkg,
					PURL:    "pkg:rpm/redhat/systemd-x@239-82.el8_10.2?arch=aarch64&distro=rhel-8.10&upstream=systemd-239-82.el8_10.2.src.rpm",
					Distro:  &distro.Distro{Type: distro.RedHat, Version: "8.10", Codename: "", IDLike: []string{"redhat"}},
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
			channels:  testFixChannels(),
			wantContext: Context{
				Source: &source.Description{
					Metadata: PURLLiteralMetadata{
						PURL: "pkg:rpm/redhat/dbus-common@1.12.8-26.el8?arch=noarch&distro=rhel-8.10&epoch=1&upstream=dbus-1.12.8-26.el8.src.rpm",
					},
				},
			},
			wantPkgs: []Package{
				{
					Name:    "dbus-common",
					Version: "1:1.12.8-26.el8",
					Type:    pkg.RpmPkg,
					PURL:    "pkg:rpm/redhat/dbus-common@1.12.8-26.el8?arch=noarch&distro=rhel-8.10&epoch=1&upstream=dbus-1.12.8-26.el8.src.rpm",
					Distro:  &distro.Distro{Type: distro.RedHat, Version: "8.10", Codename: "", IDLike: []string{"redhat"}},
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
			name:      "RPM with rpmmod",
			userInput: "pkg:rpm/redhat/httpd@2.4.37-51?arch=x86_64&distro=rhel-8.7&rpmmod=httpd:2.4",
			channels:  testFixChannels(),
			wantContext: Context{
				Source: &source.Description{
					Metadata: PURLLiteralMetadata{
						PURL: "pkg:rpm/redhat/httpd@2.4.37-51?arch=x86_64&distro=rhel-8.7&rpmmod=httpd:2.4",
					},
				},
			},
			wantPkgs: []Package{
				{
					Name:    "httpd",
					Version: "2.4.37-51",
					Type:    pkg.RpmPkg,
					PURL:    "pkg:rpm/redhat/httpd@2.4.37-51?arch=x86_64&distro=rhel-8.7&rpmmod=httpd:2.4",
					Distro:  &distro.Distro{Type: distro.RedHat, Version: "8.7", Codename: "", IDLike: []string{"redhat"}},
					Metadata: RpmMetadata{
						ModularityLabel: strRef("httpd:2.4"),
					},
				},
			},
		},
		{
			name:      "infer context when distro is present for single purl",
			userInput: "pkg:apk/curl@7.61.1?arch=aarch64&distro=alpine-3.20.3",
			channels:  testFixChannels(),
			wantContext: Context{
				Source: &source.Description{
					Metadata: PURLLiteralMetadata{
						PURL: "pkg:apk/curl@7.61.1?arch=aarch64&distro=alpine-3.20.3",
					},
				},
			},
			wantPkgs: []Package{
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
			channels:  testFixChannels(),
			wantContext: Context{
				Source: &source.Description{
					Metadata: PURLLiteralMetadata{PURL: "pkg:golang/k8s.io/ingress-nginx@v1.11.2"},
				},
			},
			wantPkgs: []Package{
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
			channels:  testFixChannels(),
			wantContext: Context{
				Source: &source.Description{
					Metadata: PURLLiteralMetadata{PURL: "pkg:golang/github.com/wazuh/wazuh@v4.5.0"},
				},
			},
			wantPkgs: []Package{
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
			channels:  testFixChannels(),
			wantContext: Context{
				Source: &source.Description{
					Metadata: PURLLiteralMetadata{PURL: "pkg:golang/wazuh@v4.5.0"},
				},
			},
			wantPkgs: []Package{
				{
					Name:    "wazuh",
					Version: "v4.5.0",
					Type:    pkg.GoModulePkg,
					PURL:    "pkg:golang/wazuh@v4.5.0",
				},
			},
		},
		{
			name:      "RPM with extended support (auto)",
			userInput: "pkg:rpm/redhat/systemd-x@239-82.el8_10.2?distro=rhel-8.10+eus",
			channels:  testFixChannels(), // important! auto applies EUS
			wantContext: Context{
				Source: &source.Description{
					Metadata: PURLLiteralMetadata{
						PURL: "pkg:rpm/redhat/systemd-x@239-82.el8_10.2?distro=rhel-8.10+eus",
					},
				},
			},
			wantPkgs: []Package{
				{
					Name:    "systemd-x",
					Version: "239-82.el8_10.2",
					Type:    pkg.RpmPkg,
					PURL:    "pkg:rpm/redhat/systemd-x@239-82.el8_10.2?distro=rhel-8.10+eus",
					Distro:  &distro.Distro{Type: distro.RedHat, Version: "8.10", Channels: names("eus"), IDLike: []string{"redhat"}},
				},
			},
		},
		{
			name:      "RPM with extended support (never)",
			userInput: "pkg:rpm/redhat/systemd-x@239-82.el8_10.2?distro=rhel-8.10+eus",
			channels: []distro.FixChannel{
				{
					Name:  "eus",
					IDs:   []string{"rhel"},
					Apply: distro.ChannelNeverEnabled, // important!
				},
			},
			wantContext: Context{
				Source: &source.Description{
					Metadata: PURLLiteralMetadata{
						PURL: "pkg:rpm/redhat/systemd-x@239-82.el8_10.2?distro=rhel-8.10+eus", // the input did hint hat eus, so we leave it
					},
				},
			},
			wantPkgs: []Package{
				{
					Name:    "systemd-x",
					Version: "239-82.el8_10.2",
					Type:    pkg.RpmPkg,
					PURL:    "pkg:rpm/redhat/systemd-x@239-82.el8_10.2?distro=rhel-8.10+eus",                                 // important! we are NOT patching the channel out of the PURL
					Distro:  &distro.Distro{Type: distro.RedHat, Version: "8.10", Channels: nil, IDLike: []string{"redhat"}}, // important! no channel applied
				},
			},
		},
		{
			name:      "RPM without extended support (always)",
			userInput: "pkg:rpm/redhat/systemd-x@239-82.el8_10.2?distro=rhel-8.10", // important! no channel hint
			channels: []distro.FixChannel{
				{
					Name:  "eus",
					IDs:   []string{"rhel"},
					Apply: distro.ChannelAlwaysEnabled, // important!
				},
			},
			wantContext: Context{
				Source: &source.Description{
					Metadata: PURLLiteralMetadata{
						PURL: "pkg:rpm/redhat/systemd-x@239-82.el8_10.2?distro=rhel-8.10",
					},
				},
			},
			wantPkgs: []Package{
				{
					Name:    "systemd-x",
					Version: "239-82.el8_10.2",
					Type:    pkg.RpmPkg,
					PURL:    "pkg:rpm/redhat/systemd-x@239-82.el8_10.2?distro=rhel-8.10",                                              // important! we are NOT patching the channel into the PURL
					Distro:  &distro.Distro{Type: distro.RedHat, Version: "8.10", Channels: names("eus"), IDLike: []string{"redhat"}}, // important! channel applied
				},
			},
		},
		{
			name:      "RPM without extended support (always) outside of version range",
			userInput: "pkg:rpm/redhat/systemd-x@239-82.el8_10.2?distro=rhel-8.10", // important! no channel hint
			channels: []distro.FixChannel{
				{
					Name:     "eus",
					IDs:      []string{"rhel"},
					Apply:    distro.ChannelAlwaysEnabled,                               // important!
					Versions: version.MustGetConstraint(">= 9", version.SemanticFormat), // important! outside of the version range
				},
			},
			wantContext: Context{
				Source: &source.Description{
					Metadata: PURLLiteralMetadata{
						PURL: "pkg:rpm/redhat/systemd-x@239-82.el8_10.2?distro=rhel-8.10",
					},
				},
			},
			wantPkgs: []Package{
				{
					Name:    "systemd-x",
					Version: "239-82.el8_10.2",
					Type:    pkg.RpmPkg,
					PURL:    "pkg:rpm/redhat/systemd-x@239-82.el8_10.2?distro=rhel-8.10",                      // important! we are NOT patching the channel into the PURL
					Distro:  &distro.Distro{Type: distro.RedHat, Version: "8.10", IDLike: []string{"redhat"}}, // important! channel NOT applied because outside of version range
				},
			},
		},
		{
			name:      "fails on purl list input",
			userInput: "purl:test-fixtures/purl/invalid-purl.txt",
			channels:  testFixChannels(),
			wantErr:   require.Error,
		},
		{
			name:      "invalid prefix",
			userInput: "dir:test-fixtures/purl",
			channels:  testFixChannels(),
			wantErr:   require.Error,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.wantErr == nil {
				tc.wantErr = require.NoError
			}

			packages, ctx, _, err := purlProvider(tc.userInput, ProviderConfig{}, getDistroChannelApplier(tc.channels))

			tc.wantErr(t, err)
			if err != nil {
				require.Nil(t, packages)
				return
			}

			if d := cmp.Diff(tc.wantContext, ctx, diffOpts...); d != "" {
				t.Errorf("unexpected context (-want +got):\n%s", d)
			}
			require.Len(t, packages, len(tc.wantPkgs))
			for idx, expected := range tc.wantPkgs {
				if d := cmp.Diff(expected, packages[idx], diffOpts...); d != "" {
					t.Errorf("unexpected context (-want +got):\n%s", d)
				}
			}
		})
	}
}

func names(ns ...string) []string {
	return ns
}
