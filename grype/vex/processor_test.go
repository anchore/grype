package vex

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vex/status"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/source"
)

func TestProcessor_ApplyVEX(t *testing.T) {
	pkgContext := &pkg.Context{
		Source: &source.Description{
			Name:    "alpine",
			Version: "3.17",
			Metadata: source.ImageMetadata{
				RepoDigests: []string{
					"alpine@sha256:124c7d2707904eea7431fffe91522a01e5a861a624ee31d03372cc1d138a3126",
				},
			},
		},
	}

	libCryptoPackage := pkg.Package{
		ID:      "cc8f90662d91481d",
		Name:    "libcrypto3",
		Version: "3.0.8-r3",

		Type: "apk",
		PURL: "pkg:apk/alpine/libcrypto3@3.0.8-r3?arch=x86_64&upstream=openssl&distro=alpine-3.17.3",
		Upstreams: []pkg.UpstreamPackage{
			{
				Name: "openssl",
			},
		},
	}

	libCryptoCVE_2023_3817 := match.Match{
		Vulnerability: vulnerability.Vulnerability{
			Reference: vulnerability.Reference{
				ID:        "CVE-2023-3817",
				Namespace: "alpine:distro:alpine:3.17",
			},
			Fix: vulnerability.Fix{
				Versions: []string{"3.0.10-r0"},
				State:    vulnerability.FixStateFixed,
			},
		},
		Package: libCryptoPackage,
	}

	libCryptoCVE_2023_1255 := match.Match{
		Vulnerability: vulnerability.Vulnerability{
			Reference: vulnerability.Reference{
				ID:        "CVE-2023-1255",
				Namespace: "alpine:distro:alpine:3.17",
			},
			Fix: vulnerability.Fix{
				Versions: []string{"3.0.8-r4"},
				State:    vulnerability.FixStateFixed,
			},
		},
		Package: libCryptoPackage,
	}

	libCryptoCVE_2023_2975 := match.Match{
		Vulnerability: vulnerability.Vulnerability{
			Reference: vulnerability.Reference{
				ID:        "CVE-2023-2975",
				Namespace: "alpine:distro:alpine:3.17",
			},
			Fix: vulnerability.Fix{
				Versions: []string{"3.0.9-r2"},
				State:    vulnerability.FixStateFixed,
			},
		},
		Package: libCryptoPackage,
	}

	getSubject := func() *match.Matches {
		s := match.NewMatches(
			// not-affected justification example
			libCryptoCVE_2023_3817,

			// fixed status example + matching CVE
			libCryptoCVE_2023_1255,

			// fixed status example
			libCryptoCVE_2023_2975,
		)

		return &s
	}

	matchesRef := func(ms ...match.Match) *match.Matches {
		m := match.NewMatches(ms...)
		return &m
	}

	type args struct {
		pkgContext     *pkg.Context
		matches        *match.Matches
		ignoredMatches []match.IgnoredMatch
	}

	tests := []struct {
		name               string
		options            ProcessorOptions
		args               args
		wantMatches        *match.Matches
		wantIgnoredMatches []match.IgnoredMatch
		wantErr            require.ErrorAssertionFunc
	}{
		{
			name: "csaf-demo1 - ignore by fixed status",
			options: ProcessorOptions{
				Documents: []string{
					"testdata/vex-docs/csaf-demo1.json",
				},
				IgnoreRules: []match.IgnoreRule{{
					VexStatus: string(status.Fixed),
				}},
			},
			args: args{
				pkgContext: pkgContext,
				matches:    getSubject(),
			},
			wantMatches: matchesRef(libCryptoCVE_2023_3817, libCryptoCVE_2023_2975),
			wantIgnoredMatches: []match.IgnoredMatch{{
				Match: libCryptoCVE_2023_1255,
				AppliedIgnoreRules: []match.IgnoreRule{{
					Namespace: "vex",
					VexStatus: string(status.Fixed),
				}},
			}},
		},
		{
			name: "csaf-demo1 - ignore by fixed status and CVE",
			options: ProcessorOptions{
				Documents: []string{
					"testdata/vex-docs/csaf-demo1.json",
				},
				IgnoreRules: []match.IgnoreRule{{
					VexStatus:     string(status.Fixed),
					Vulnerability: "CVE-2023-1255", // note: and previous tests
				}},
			},
			args: args{
				pkgContext: pkgContext,
				matches:    getSubject(),
			},
			wantMatches: matchesRef(libCryptoCVE_2023_3817, libCryptoCVE_2023_2975),
			wantIgnoredMatches: []match.IgnoredMatch{{
				Match: libCryptoCVE_2023_1255,
				AppliedIgnoreRules: []match.IgnoreRule{{
					Namespace:     "vex",
					Vulnerability: "CVE-2023-1255",
					VexStatus:     string(status.Fixed),
				}},
			}},
		},
		{
			name: "csaf-demo2 - ignore by not_affected status and vulnerable_code_not_present justification",
			options: ProcessorOptions{
				Documents: []string{
					"testdata/vex-docs/csaf-demo2.json",
				},
				IgnoreRules: []match.IgnoreRule{{
					VexStatus:        string(status.NotAffected),
					VexJustification: "vulnerable_code_not_present", // note: this is the difference between this test and previous tests
				}},
			},
			args: args{
				pkgContext: pkgContext,
				matches:    getSubject(),
			},
			wantMatches: matchesRef(libCryptoCVE_2023_1255, libCryptoCVE_2023_2975),
			wantIgnoredMatches: []match.IgnoredMatch{{
				Match: libCryptoCVE_2023_3817,
				AppliedIgnoreRules: []match.IgnoreRule{{
					Namespace:        "vex",
					VexJustification: "vulnerable_code_not_present",
					VexStatus:        string(status.NotAffected),
				}},
			}},
		},
		{
			name: "openvex-demo1 - ignore by fixed status",
			options: ProcessorOptions{
				Documents: []string{
					"testdata/vex-docs/openvex-demo1.json",
				},
				IgnoreRules: []match.IgnoreRule{{
					VexStatus: string(status.Fixed),
				}},
			},
			args: args{
				pkgContext: pkgContext,
				matches:    getSubject(),
			},
			wantMatches: matchesRef(libCryptoCVE_2023_3817, libCryptoCVE_2023_2975),
			wantIgnoredMatches: []match.IgnoredMatch{{
				Match: libCryptoCVE_2023_1255,
				AppliedIgnoreRules: []match.IgnoreRule{{
					Namespace: "vex",
					VexStatus: string(status.Fixed),
				}},
			}},
		},
		{
			name: "openvex-demo1 - ignore by fixed status and CVE", // no real difference from the first test other than the AppliedIgnoreRules
			options: ProcessorOptions{
				Documents: []string{
					"testdata/vex-docs/openvex-demo1.json",
				},
				IgnoreRules: []match.IgnoreRule{{
					Vulnerability: "CVE-2023-1255", // note: this is the difference between this test and the last test
					VexStatus:     string(status.Fixed),
				}},
			},
			args: args{
				pkgContext: pkgContext,
				matches:    getSubject(),
			},
			wantMatches: matchesRef(libCryptoCVE_2023_3817, libCryptoCVE_2023_2975),
			wantIgnoredMatches: []match.IgnoredMatch{{
				Match: libCryptoCVE_2023_1255,
				AppliedIgnoreRules: []match.IgnoreRule{{
					Namespace:     "vex",
					Vulnerability: "CVE-2023-1255", // note: this is the difference between this test and the last test
					VexStatus:     string(status.Fixed),
				}},
			}},
		},
		{
			name: "openvex-demo2 - ignore by fixed status",
			options: ProcessorOptions{
				Documents: []string{
					"testdata/vex-docs/openvex-demo2.json",
				},
				IgnoreRules: []match.IgnoreRule{{
					VexStatus: string(status.Fixed),
				}},
			},
			args: args{
				pkgContext: pkgContext,
				matches:    getSubject(),
			},
			wantMatches: matchesRef(libCryptoCVE_2023_3817),
			wantIgnoredMatches: []match.IgnoredMatch{{
				Match: libCryptoCVE_2023_1255,
				AppliedIgnoreRules: []match.IgnoreRule{{
					Namespace: "vex",
					VexStatus: string(status.Fixed),
				}},
			}, {
				Match: libCryptoCVE_2023_2975,
				AppliedIgnoreRules: []match.IgnoreRule{{
					Namespace: "vex",
					VexStatus: string(status.Fixed),
				}},
			}},
		},
		{
			name: "openvex-demo2 - ignore by fixed status and CVE",
			options: ProcessorOptions{
				Documents: []string{
					"testdata/vex-docs/openvex-demo2.json",
				},
				IgnoreRules: []match.IgnoreRule{{
					Vulnerability: "CVE-2023-1255", // note: this is the difference between this test and the last test
					VexStatus:     string(status.Fixed),
				}},
			},
			args: args{
				pkgContext: pkgContext,
				matches:    getSubject(),
			},
			wantMatches: matchesRef(libCryptoCVE_2023_3817, libCryptoCVE_2023_2975),
			wantIgnoredMatches: []match.IgnoredMatch{{
				Match: libCryptoCVE_2023_1255,
				AppliedIgnoreRules: []match.IgnoreRule{{
					Namespace:     "vex",
					Vulnerability: "CVE-2023-1255", // note: this is the difference between this test and the last test
					VexStatus:     string(status.Fixed),
				}},
			}},
		},
		{
			name: "openvex-demo1 - ignore by not_affected status and vulnerable_code_not_present justification",
			options: ProcessorOptions{
				Documents: []string{
					"testdata/vex-docs/openvex-demo1.json",
				},
				IgnoreRules: []match.IgnoreRule{{
					VexStatus:        "not_affected",
					VexJustification: "vulnerable_code_not_present",
				}},
			},
			args: args{
				pkgContext: pkgContext,
				matches:    getSubject(),
			},
			// nothing gets ignored!
			wantMatches:        matchesRef(libCryptoCVE_2023_3817, libCryptoCVE_2023_2975, libCryptoCVE_2023_1255),
			wantIgnoredMatches: []match.IgnoredMatch{},
		},
		{
			name: "openvex-demo2 - ignore by not_affected status and vulnerable_code_not_present justification",
			options: ProcessorOptions{
				Documents: []string{
					"testdata/vex-docs/openvex-demo2.json",
				},
				IgnoreRules: []match.IgnoreRule{{
					VexStatus:        "not_affected",
					VexJustification: "vulnerable_code_not_present",
				}},
			},
			args: args{
				pkgContext: pkgContext,
				matches:    getSubject(),
			},
			wantMatches: matchesRef(libCryptoCVE_2023_2975, libCryptoCVE_2023_1255),
			wantIgnoredMatches: []match.IgnoredMatch{{
				Match: libCryptoCVE_2023_3817,
				AppliedIgnoreRules: []match.IgnoreRule{{
					Namespace:        "vex",
					VexStatus:        "not_affected",
					VexJustification: "vulnerable_code_not_present",
				}},
			}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr == nil {
				tt.wantErr = require.NoError
			}

			p, err := NewProcessor(tt.options)
			tt.wantErr(t, err)
			if err != nil {
				return
			}
			actualMatches, actualIgnoredMatches, err := p.ApplyVEX(tt.args.pkgContext, tt.args.matches, tt.args.ignoredMatches)
			tt.wantErr(t, err)
			if err != nil {
				return
			}

			assert.Equal(t, tt.wantMatches.Sorted(), actualMatches.Sorted())
			assert.Equal(t, tt.wantIgnoredMatches, actualIgnoredMatches)

		})
	}
}
