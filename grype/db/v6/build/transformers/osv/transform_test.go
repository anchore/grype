package osv

import (
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scanner/pkg/models"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/db/internal/provider/unmarshal"
	"github.com/anchore/grype/grype/db/provider"
	db "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/build/transformers"
)

var timeVal = time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)
var listing = provider.File{
	Path:      "some",
	Digest:    "123456",
	Algorithm: "sha256",
}

func inputProviderState() provider.State {
	return provider.State{
		Provider:  "osv",
		Version:   12,
		Processor: "vunnel@1.2.3",
		Timestamp: timeVal,
		Listing:   &listing,
	}
}

func expectedProvider() *db.Provider {
	return &db.Provider{
		ID:           "osv",
		Version:      "12",
		Processor:    "vunnel@1.2.3",
		DateCaptured: &timeVal,
		InputDigest:  "sha256:123456",
	}
}

func timeRef(t time.Time) *time.Time {
	return &t
}

func loadFixture(t *testing.T, fixturePath string) []unmarshal.OSVVulnerability {
	t.Helper()

	f, err := os.Open(fixturePath)
	require.NoError(t, err)
	defer func() {
		require.NoError(t, f.Close())
	}()

	entries, err := unmarshal.OSVVulnerabilityEntries(f)
	require.NoError(t, err)
	return entries
}

func affectedPkgSlice(a ...db.AffectedPackageHandle) []any {
	var r []any
	for _, v := range a {
		r = append(r, v)
	}
	return r
}

func unaffectedPkgSlice(u ...db.UnaffectedPackageHandle) []any {
	var r []any
	for _, v := range u {
		r = append(r, v)
	}
	return r
}

func TestTransform(t *testing.T) {
	tests := []struct {
		name        string
		fixturePath string
		want        []transformers.RelatedEntries
	}{
		{
			name:        "Apache 2020-11984",
			fixturePath: "testdata/BIT-apache-2020-11984.json",
			want: []transformers.RelatedEntries{{
				VulnerabilityHandle: &db.VulnerabilityHandle{
					Name:          "BIT-apache-2020-11984",
					Status:        db.VulnerabilityActive,
					ProviderID:    "osv",
					Provider:      expectedProvider(),
					ModifiedDate:  timeRef(time.Date(2025, time.January, 17, 15, 26, 01, 971000000, time.UTC)),
					PublishedDate: timeRef(time.Date(2024, time.March, 6, 10, 57, 57, 770000000, time.UTC)),
					BlobValue: &db.VulnerabilityBlob{
						ID:          "BIT-apache-2020-11984",
						Description: "Apache HTTP server 2.4.32 to 2.4.44 mod_proxy_uwsgi info disclosure and possible RCE",
						References: []db.Reference{{
							URL:  "http://www.openwall.com/lists/oss-security/2020/08/08/1",
							Tags: []string{"WEB"},
						}, {
							URL:  "http://www.openwall.com/lists/oss-security/2020/08/08/10",
							Tags: []string{"WEB"},
						}},
						Aliases: []string{"CVE-2020-11984"},
						Severities: []db.Severity{{
							Scheme: db.SeveritySchemeCVSS,
							Value: db.CVSSSeverity{
								Vector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
								Version: "3.1",
							},
						}},
					},
				},
				Related: affectedPkgSlice(
					db.AffectedPackageHandle{
						Package: &db.Package{
							Name:      "apache",
							Ecosystem: "Bitnami",
						},
						BlobValue: &db.PackageBlob{
							CVEs: []string{"CVE-2020-11984"},
							Ranges: []db.Range{{
								Version: db.Version{
									Type:       "bitnami",
									Constraint: ">=2.4.32,<=2.4.43",
								},
							}},
						},
					},
				),
			}},
		},
		{
			name:        "Node 2020-8201",
			fixturePath: "testdata/BIT-node-2020-8201.json",
			want: []transformers.RelatedEntries{{
				VulnerabilityHandle: &db.VulnerabilityHandle{
					Name:          "BIT-node-2020-8201",
					Status:        db.VulnerabilityActive,
					ProviderID:    "osv",
					Provider:      expectedProvider(),
					ModifiedDate:  timeRef(time.Date(2024, time.March, 6, 11, 25, 28, 861000000, time.UTC)),
					PublishedDate: timeRef(time.Date(2024, time.March, 6, 11, 8, 9, 371000000, time.UTC)),
					BlobValue: &db.VulnerabilityBlob{
						ID:          "BIT-node-2020-8201",
						Description: "Node.js < 12.18.4 and < 14.11 can be exploited to perform HTTP desync attacks and deliver malicious payloads to unsuspecting users. The payloads can be crafted by an attacker to hijack user sessions, poison cookies, perform clickjacking, and a multitude of other attacks depending on the architecture of the underlying system. The attack was possible due to a bug in processing of carrier-return symbols in the HTTP header names.",
						References: []db.Reference{{
							URL:  "https://nodejs.org/en/blog/vulnerability/september-2020-security-releases/",
							Tags: []string{"WEB"},
						}, {
							URL:  "https://security.gentoo.org/glsa/202101-07",
							Tags: []string{"WEB"},
						}},
						Aliases: []string{"CVE-2020-8201"},
						Severities: []db.Severity{{
							Scheme: db.SeveritySchemeCVSS,
							Value: db.CVSSSeverity{
								Vector:  "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
								Version: "3.1",
							},
						}},
					},
				},
				Related: affectedPkgSlice(
					db.AffectedPackageHandle{
						Package: &db.Package{
							Name:      "node",
							Ecosystem: "Bitnami",
						},
						BlobValue: &db.PackageBlob{
							CVEs: []string{"CVE-2020-8201"},
							Ranges: []db.Range{{
								Version: db.Version{
									Type:       "bitnami",
									Constraint: ">=12.0.0,<12.18.4",
								},
								Fix: &db.Fix{
									Version: "12.18.4",
									State:   db.FixedStatus,
									Detail: &db.FixDetail{
										Available: &db.FixAvailability{
											Date: timeRef(time.Date(2020, time.September, 15, 0, 0, 0, 0, time.UTC)),
											Kind: "first-observed",
										},
									},
								},
							}, {
								Version: db.Version{
									Type:       "bitnami",
									Constraint: ">=14.0.0,<14.11.0",
								},
								Fix: &db.Fix{
									Version: "14.11.0",
									State:   db.FixedStatus,
									Detail: &db.FixDetail{
										Available: &db.FixAvailability{
											Date: timeRef(time.Date(2020, time.September, 15, 0, 0, 0, 0, time.UTC)),
											Kind: "first-observed",
										},
									},
								},
							}},
						},
					},
				),
			}},
		},
		{
			// ALSA-2020:1636 is a real alma record where the CVE info lives in
			// `related` only (input `aliases` is nil) — the dominant shape for
			// alma advisories. The transformer is supposed to append `related`
			// onto `aliases` for advisory records; this case is the regression
			// net for that augmentation.
			name:        "AlmaLinux Advisory with related-only aliases",
			fixturePath: "testdata/ALSA-2020-1636.json",
			want: []transformers.RelatedEntries{{
				VulnerabilityHandle: &db.VulnerabilityHandle{
					Name:          "ALSA-2020:1636",
					Status:        db.VulnerabilityActive,
					ProviderID:    "osv",
					Provider:      expectedProvider(),
					ModifiedDate:  timeRef(time.Date(2021, time.August, 11, 8, 54, 0, 0, time.UTC)),
					PublishedDate: timeRef(time.Date(2020, time.April, 28, 8, 59, 15, 0, time.UTC)),
					BlobValue: &db.VulnerabilityBlob{
						ID:          "ALSA-2020:1636",
						Description: "libsndfile is a C library for reading and writing files containing sampled sound, such as AIFF, AU, or WAV. \n\nSecurity Fix(es):\n\n* libsndfile: stack-based buffer overflow in sndfile-deinterleave utility (CVE-2018-13139)\n\n* libsndfile: buffer over-read in the function i2alaw_array in alaw.c (CVE-2018-19662)\n\nFor more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and other related information, refer to the CVE page(s) listed in the References section.\n\nAdditional Changes:\n\nFor detailed information on changes in this release, see the AlmaLinux Release Notes linked from the References section.",
						References: []db.Reference{
							{URL: "https://vulners.com/cve/CVE-2018-13139", Tags: []string{"REPORT"}},
							{URL: "https://vulners.com/cve/CVE-2018-19662", Tags: []string{"REPORT"}},
						},
						Aliases:    []string{"CVE-2018-13139", "CVE-2018-19662"},
						Severities: nil,
					},
				},
				Related: unaffectedPkgSlice(
					db.UnaffectedPackageHandle{
						Package: &db.Package{
							Name:      "libsndfile-devel",
							Ecosystem: "rpm",
						},
						OperatingSystem: &db.OperatingSystem{
							Name:         "almalinux",
							MajorVersion: "8",
						},
						BlobValue: &db.PackageBlob{
							// PackageBlob.CVEs is currently built from the un-augmented
							// vuln.Aliases (nil for this record), so the package-level CVE
							// list is empty even though VulnerabilityBlob.Aliases above
							// correctly carries CVE-2018-13139 + CVE-2018-19662. Whether to
							// populate this from the augmented list is a per-strategy decision
							// in the upcoming refactor; this assertion locks down current
							// behavior as the regression baseline. Functionally low-impact:
							// only read site (vulnerability.go::getRelatedVulnerabilities)
							// already sees the same CVEs via vuln.BlobValue.Aliases and dedups.
							CVEs: nil,
							Ranges: []db.Range{{
								Version: db.Version{
									Type:       "rpm",
									Constraint: ">= 1.0.28-10.el8",
								},
								Fix: &db.Fix{
									Version: "1.0.28-10.el8",
									State:   db.FixedStatus,
								},
							}},
						},
					},
				),
			}},
		},
		{
			// ALSA-2021:4156 is a real alma record that carries
			// ecosystem_specific.rpm_modularity ("go-toolset:rhel8"); modular
			// records make up ~63% of alma 8 data and the modularity qualifier
			// is load-bearing for the rpm matcher. This case is the regression
			// net for the modularity round-trip through the advisory path.
			name:        "AlmaLinux Advisory with rpm_modularity",
			fixturePath: "testdata/ALSA-2021-4156.json",
			want: []transformers.RelatedEntries{{
				VulnerabilityHandle: &db.VulnerabilityHandle{
					Name:          "ALSA-2021:4156",
					Status:        db.VulnerabilityActive,
					ProviderID:    "osv",
					Provider:      expectedProvider(),
					ModifiedDate:  timeRef(time.Date(2021, time.December, 16, 11, 29, 11, 0, time.UTC)),
					PublishedDate: timeRef(time.Date(2021, time.November, 9, 8, 25, 49, 0, time.UTC)),
					BlobValue: &db.VulnerabilityBlob{
						ID:          "ALSA-2021:4156",
						Description: "Go Toolset provides the Go programming language tools and libraries. Go is alternatively known as golang. \n\nThe following packages have been upgraded to a later upstream version: golang (1.16.7). (BZ#1938071)\n\nSecurity Fix(es):\n\n* golang: net: lookup functions may return invalid host names (CVE-2021-33195)\n\n* golang: net/http/httputil: ReverseProxy forwards connection headers if first one is empty (CVE-2021-33197)\n\n* golang: math/big.Rat: may cause a panic or an unrecoverable fatal error if passed inputs with very large exponents (CVE-2021-33198)\n\n* golang: net/http/httputil: panic due to racy read of persistConn after handler panic (CVE-2021-36221)\n\nFor more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and other related information, refer to the CVE page(s) listed in the References section.\n\nAdditional Changes:\n\nFor detailed information on changes in this release, see the AlmaLinux Release Notes linked from the References section.",
						References: []db.Reference{
							{URL: "https://vulners.com/cve/CVE-2021-33195", Tags: []string{"REPORT"}},
							{URL: "https://vulners.com/cve/CVE-2021-33197", Tags: []string{"REPORT"}},
							{URL: "https://vulners.com/cve/CVE-2021-33198", Tags: []string{"REPORT"}},
							{URL: "https://vulners.com/cve/CVE-2021-36221", Tags: []string{"REPORT"}},
						},
						Aliases:    []string{"CVE-2021-33195", "CVE-2021-33197", "CVE-2021-33198", "CVE-2021-36221"},
						Severities: nil,
					},
				},
				Related: unaffectedPkgSlice(
					db.UnaffectedPackageHandle{
						Package: &db.Package{
							Name:      "delve",
							Ecosystem: "rpm",
						},
						OperatingSystem: &db.OperatingSystem{
							Name:         "almalinux",
							MajorVersion: "8",
						},
						BlobValue: &db.PackageBlob{
							// Same per-strategy-decision call-out as ALSA-2020:1636 above:
							// the 4 related CVEs surface on VulnerabilityBlob.Aliases but not
							// in PackageBlob.CVEs today. Locking down current behavior; the
							// upcoming refactor's alma strategy will decide.
							CVEs: nil,
							Qualifiers: &db.PackageQualifiers{
								RpmModularity: stringRef("go-toolset:rhel8"),
							},
							Ranges: []db.Range{{
								Version: db.Version{
									Type:       "rpm",
									Constraint: ">= 1.6.0-1.module_el8.5.0+2604+960c7771",
								},
								Fix: &db.Fix{
									Version: "1.6.0-1.module_el8.5.0+2604+960c7771",
									State:   db.FixedStatus,
								},
							}},
						},
					},
				),
			}},
		},
		{
			name:        "AlmaLinux Advisory",
			fixturePath: "testdata/ALSA-2025-7467.json",
			want: []transformers.RelatedEntries{{
				VulnerabilityHandle: &db.VulnerabilityHandle{
					Name:          "ALSA-2025:7467",
					Status:        db.VulnerabilityActive,
					ProviderID:    "osv",
					Provider:      expectedProvider(),
					ModifiedDate:  timeRef(time.Date(2025, time.July, 2, 12, 50, 6, 0, time.UTC)),
					PublishedDate: timeRef(time.Date(2025, time.May, 13, 0, 0, 0, 0, time.UTC)),
					BlobValue: &db.VulnerabilityBlob{
						ID:          "ALSA-2025:7467",
						Description: "The skopeo command lets you inspect images from container image registries.",
						References: []db.Reference{{
							ID:   "ALSA-2025:7467",
							URL:  "https://errata.almalinux.org/10/ALSA-2025-7467.html",
							Tags: []string{"ADVISORY"},
						}},
						Aliases:    []string{"CVE-2025-27144"},
						Severities: nil,
					},
				},
				Related: unaffectedPkgSlice(
					db.UnaffectedPackageHandle{
						Package: &db.Package{
							Name:      "skopeo",
							Ecosystem: "rpm",
						},
						OperatingSystem: &db.OperatingSystem{
							Name:         "almalinux",
							MajorVersion: "10",
						},
						BlobValue: &db.PackageBlob{
							CVEs: []string{"CVE-2025-27144"},
							Ranges: []db.Range{{
								Version: db.Version{
									Type:       "rpm",
									Constraint: ">= 2:1.18.1-1.el10_0",
								},
								Fix: &db.Fix{
									Version: "2:1.18.1-1.el10_0",
									State:   db.FixedStatus,
								},
							}},
						},
					},
					db.UnaffectedPackageHandle{
						Package: &db.Package{
							Name:      "skopeo-tests",
							Ecosystem: "rpm",
						},
						OperatingSystem: &db.OperatingSystem{
							Name:         "almalinux",
							MajorVersion: "10",
						},
						BlobValue: &db.PackageBlob{
							CVEs: []string{"CVE-2025-27144"},
							Ranges: []db.Range{{
								Version: db.Version{
									Type:       "rpm",
									Constraint: ">= 2:1.18.1-1.el10_0",
								},
								Fix: &db.Fix{
									Version: "2:1.18.1-1.el10_0",
									State:   db.FixedStatus,
								},
							}},
						},
					},
				),
			}},
		},
	}
	t.Parallel()
	for _, testToRun := range tests {
		test := testToRun
		t.Run(test.name, func(tt *testing.T) {
			tt.Parallel()
			vulns := loadFixture(t, test.fixturePath)
			var actual []transformers.RelatedEntries
			for _, vuln := range vulns {
				entries, err := Transform(vuln, inputProviderState())
				require.NoError(t, err)
				for _, entry := range entries {
					e, ok := entry.Data.(transformers.RelatedEntries)
					require.True(t, ok)
					actual = append(actual, e)
				}
			}

			if diff := cmp.Diff(test.want, actual); diff != "" {
				t.Errorf("data entries mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
func Test_getGrypeRangesFromRange(t *testing.T) {
	tests := []struct {
		name      string
		rnge      models.Range
		ecosystem string
		want      []db.Range
	}{
		{
			name:      "single range with 'fixed' status",
			ecosystem: "npm",
			rnge: models.Range{
				Type: models.RangeSemVer,
				Events: []models.Event{{
					Introduced: "0.0.1",
				}, {
					Fixed: "0.0.5",
				}},
			},
			want: []db.Range{{
				Version: db.Version{
					Type:       "semver",
					Constraint: ">=0.0.1,<0.0.5",
				},
				Fix: &db.Fix{
					Version: "0.0.5",
					State:   db.FixedStatus,
				},
			}},
		},
		{
			name:      "single range with 'last affected' status",
			ecosystem: "npm",
			rnge: models.Range{
				Type: models.RangeSemVer,
				Events: []models.Event{{
					Introduced: "0.0.1",
				}, {
					LastAffected: "0.0.5",
				}},
			},
			want: []db.Range{{
				Version: db.Version{
					Type:       "semver",
					Constraint: ">=0.0.1,<=0.0.5",
				},
			}},
		},
		{
			name:      "single range with no 'fixed' or 'last affected' status",
			ecosystem: "npm",
			rnge: models.Range{
				Type: models.RangeSemVer,
				Events: []models.Event{{
					Introduced: "0.0.1",
				}},
			},
			want: []db.Range{{
				Version: db.Version{
					Type:       "semver",
					Constraint: ">=0.0.1",
				},
			}},
		},
		{
			name:      "single range introduced with '0'",
			ecosystem: "npm",
			rnge: models.Range{
				Type: models.RangeSemVer,
				Events: []models.Event{{
					Introduced: "0",
				}, {
					LastAffected: "0.0.5",
				}},
			},
			want: []db.Range{{
				Version: db.Version{
					Type:       "semver",
					Constraint: "<=0.0.5",
				},
			}},
		},
		{
			name:      "multiple ranges",
			ecosystem: "npm",
			rnge: models.Range{
				Type: models.RangeSemVer,
				Events: []models.Event{{
					Introduced: "0.0.1",
				}, {
					Fixed: "0.0.5",
				}, {
					Introduced: "1.0.1",
				}, {
					Fixed: "1.0.5",
				}},
			},
			want: []db.Range{{
				Version: db.Version{
					Type:       "semver",
					Constraint: ">=0.0.1,<0.0.5",
				},
				Fix: &db.Fix{
					Version: "0.0.5",
					State:   db.FixedStatus,
				},
			}, {
				Version: db.Version{
					Type:       "semver",
					Constraint: ">=1.0.1,<1.0.5",
				},
				Fix: &db.Fix{
					Version: "1.0.5",
					State:   db.FixedStatus,
				},
			},
			},
		},
		{
			name:      "single range with database-specific fix availability",
			ecosystem: "npm",
			rnge: models.Range{
				Type: models.RangeSemVer,
				Events: []models.Event{{
					Introduced: "1.0.0",
				}, {
					Fixed: "1.2.3",
				}},
				DatabaseSpecific: map[string]any{
					"anchore": map[string]any{
						"fixes": []any{
							map[string]any{
								"version": "1.2.3",
								"date":    "2023-06-15",
								"kind":    "first-observed",
							},
						},
					},
				},
			},
			want: []db.Range{{
				Version: db.Version{
					Type:       "semver",
					Constraint: ">=1.0.0,<1.2.3",
				},
				Fix: &db.Fix{
					Version: "1.2.3",
					State:   db.FixedStatus,
					Detail: &db.FixDetail{
						Available: &db.FixAvailability{
							Date: timeRef(time.Date(2023, time.June, 15, 0, 0, 0, 0, time.UTC)),
							Kind: "first-observed",
						},
					},
				},
			}},
		},
	}
	t.Parallel()
	for _, testToRun := range tests {
		test := testToRun
		t.Run(test.name, func(tt *testing.T) {
			tt.Parallel()
			if got := getGrypeRangesFromRange(test.rnge, test.ecosystem); !reflect.DeepEqual(got, test.want) {
				t.Errorf("getGrypeRangesFromRange() = %v, want %v", got, test.want)
			}
		})
	}
}

func Test_extractCVSSInfo(t *testing.T) {
	tests := []struct {
		name        string
		cvss        string
		wantVersion string
		wantVector  string
		wantErr     bool
	}{
		{
			name:        "valid cvss",
			cvss:        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			wantVersion: "3.1",
			wantVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			wantErr:     false,
		},
		{
			name:        "invalid cvss",
			cvss:        "foo:3.1/bar",
			wantVersion: "",
			wantVector:  "",
			wantErr:     true,
		},
		{
			name:        "empty cvss",
			cvss:        "",
			wantVersion: "",
			wantVector:  "",
			wantErr:     true,
		},
		{
			name:        "invalid cvss version",
			cvss:        "CVSS:foo/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			wantVersion: "",
			wantVector:  "",
			wantErr:     true,
		},
	}
	t.Parallel()
	for _, testToRun := range tests {
		test := testToRun
		t.Run(test.name, func(tt *testing.T) {
			tt.Parallel()
			gotVersion, gotVector, err := extractCVSSInfo(test.cvss)
			if (err != nil) != test.wantErr {
				t.Errorf("extractCVSSInfo() error = %v, wantErr %v", err, test.wantErr)
				return
			}
			if gotVersion != test.wantVersion {
				t.Errorf("extractCVSSInfo() got version = %v, want %v", gotVersion, test.wantVersion)
			}
			if gotVector != test.wantVector {
				t.Errorf("extractCVSSInfo() got vector = %v, want %v", gotVector, test.wantVector)
			}
		})
	}
}

func Test_extractRpmModularity(t *testing.T) {
	tests := []struct {
		name     string
		affected models.Affected
		want     string
	}{
		{
			name: "with rpm_modularity",
			affected: models.Affected{
				EcosystemSpecific: map[string]any{
					"rpm_modularity": "mariadb:10.3",
				},
			},
			want: "mariadb:10.3",
		},
		{
			name: "no ecosystem_specific",
			affected: models.Affected{
				EcosystemSpecific: nil,
			},
			want: "",
		},
		{
			name: "no rpm_modularity key",
			affected: models.Affected{
				EcosystemSpecific: map[string]any{
					"other_key": "some_value",
				},
			},
			want: "",
		},
		{
			name: "rpm_modularity not string",
			affected: models.Affected{
				EcosystemSpecific: map[string]any{
					"rpm_modularity": 123,
				},
			},
			want: "",
		},
		{
			name: "nodejs modularity",
			affected: models.Affected{
				EcosystemSpecific: map[string]any{
					"rpm_modularity": "nodejs:16",
				},
			},
			want: "nodejs:16",
		},
	}

	for _, testToRun := range tests {
		test := testToRun
		t.Run(test.name, func(tt *testing.T) {
			got := extractRpmModularity(test.affected)
			if got != test.want {
				t.Errorf("extractRpmModularity() = %v, want %v", got, test.want)
			}
		})
	}
}

func stringRef(s string) *string {
	return &s
}
