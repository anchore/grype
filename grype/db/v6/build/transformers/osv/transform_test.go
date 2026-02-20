package osv

import (
	"os"
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
			fixturePath: "test-fixtures/BIT-apache-2020-11984.json",
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
			fixturePath: "test-fixtures/BIT-node-2020-8201.json",
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
			name:        "AlmaLinux Advisory",
			fixturePath: "test-fixtures/ALSA-2025-7467.json",
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
							ReleaseID:    "almalinux",
							MajorVersion: "10",
						},
						BlobValue: &db.PackageBlob{
							CVEs: []string{"CVE-2025-27144"},
							Ranges: []db.Range{{
								Version: db.Version{
									Type:       "ecosystem",
									Constraint: ">=2:1.18.1-1.el10_0",
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
							ReleaseID:    "almalinux",
							MajorVersion: "10",
						},
						BlobValue: &db.PackageBlob{
							CVEs: []string{"CVE-2025-27144"},
							Ranges: []db.Range{{
								Version: db.Version{
									Type:       "ecosystem",
									Constraint: ">=2:1.18.1-1.el10_0",
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
		{
			// Go Vuln DB: uses standard "aliases" field, SEMVER ranges, and golang PURL.
			// This test should PASS with the current transformer since Go records use
			// the standard OSV "aliases" field (not "upstream").
			name:        "Go Vuln DB - protobuf infinite loop",
			fixturePath: "test-fixtures/GO-2024-2611.json",
			want: []transformers.RelatedEntries{{
				VulnerabilityHandle: &db.VulnerabilityHandle{
					Name:          "GO-2024-2611",
					Status:        db.VulnerabilityActive,
					ProviderID:    "osv",
					Provider:      expectedProvider(),
					ModifiedDate:  timeRef(time.Date(2026, time.January, 28, 3, 41, 22, 146319000, time.UTC)),
					PublishedDate: timeRef(time.Date(2024, time.March, 5, 20, 24, 5, 0, time.UTC)),
					BlobValue: &db.VulnerabilityBlob{
						ID:          "GO-2024-2611",
						Description: "The protojson.Unmarshal function can enter an infinite loop when unmarshaling certain forms of invalid JSON. This condition can occur when unmarshaling into a message which contains a google.protobuf.Any value, or when the UnmarshalOptions.DiscardUnknown option is set.",
						References: []db.Reference{{
							URL:  "https://go.dev/cl/569356",
							Tags: []string{"FIX"},
						}},
						Aliases: []string{"CVE-2024-24786", "GHSA-8r3f-844c-mc37"},
					},
				},
				Related: affectedPkgSlice(
					db.AffectedPackageHandle{
						Package: &db.Package{
							Name:      "google.golang.org/protobuf",
							Ecosystem: "Go",
						},
						BlobValue: &db.PackageBlob{
							CVEs: []string{"CVE-2024-24786", "GHSA-8r3f-844c-mc37"},
							Ranges: []db.Range{{
								Version: db.Version{
									Type:       "semver",
									Constraint: "<1.33.0",
								},
								Fix: &db.Fix{
									Version: "1.33.0",
									State:   db.FixedStatus,
								},
							}},
						},
					},
				),
			}},
		},
		{
			// R (CRAN) ecosystem: uses "upstream" field instead of "aliases" to reference CVEs.
			// KNOWN ISSUE: The osv-scanner models.Vulnerability struct has no "Upstream" field,
			// so "upstream" data is silently dropped during JSON unmarshaling. This causes:
			//   - VulnerabilityBlob.Aliases to be empty (should contain CVE-2020-5238)
			//   - PackageBlob.CVEs to be empty (should contain CVE-2020-5238)
			// The grype transformer needs a custom unmarshal type or post-processing to capture
			// the "upstream" field and merge it into Aliases.
			name:        "R Sec (CRAN) - commonmark DoS",
			fixturePath: "test-fixtures/RSEC-2023-6.json",
			want: []transformers.RelatedEntries{{
				VulnerabilityHandle: &db.VulnerabilityHandle{
					Name:          "RSEC-2023-6",
					Status:        db.VulnerabilityActive,
					ProviderID:    "osv",
					Provider:      expectedProvider(),
					ModifiedDate:  timeRef(time.Date(2025, time.May, 19, 19, 43, 47, 903227000, time.UTC)),
					PublishedDate: timeRef(time.Date(2023, time.October, 6, 5, 0, 0, 600000000, time.UTC)),
					BlobValue: &db.VulnerabilityBlob{
						ID:          "RSEC-2023-6",
						Description: "The commonmark package, specifically in its dependency on GitHub Flavored Markdown before version 0.29.0.gfm.1, has a vulnerability related to time complexity. Parsing certain crafted markdown tables can take O(n * n) time, leading to potential Denial of Service attacks. This issue does not affect the upstream cmark project and has been fixed in version 0.29.0.gfm.1.",
						References: []db.Reference{{
							URL:  "https://security-tracker.debian.org/tracker/CVE-2020-5238",
							Tags: []string{"WEB"},
						}, {
							URL:  "https://github.com/r-lib/commonmark/issues/13",
							Tags: []string{"WEB"},
						}, {
							URL:  "https://github.com/r-lib/commonmark/pull/18",
							Tags: []string{"WEB"},
						}},
						Aliases: []string{"CVE-2020-5238"},
					},
				},
				Related: affectedPkgSlice(
					db.AffectedPackageHandle{
						Package: &db.Package{
							Name:      "commonmark",
							Ecosystem: "CRAN",
						},
						BlobValue: &db.PackageBlob{
							CVEs: []string{"CVE-2020-5238"},
							Ranges: []db.Range{{
								Version: db.Version{
									Type:       "ecosystem",
									Constraint: ">=0.2,<1.8",
								},
								Fix: &db.Fix{
									Version: "1.8",
									State:   db.FixedStatus,
								},
							}},
						},
					},
				),
			}},
		},
		{
			// openEuler (OESA) ecosystem: uses "upstream" field and has a malformed PURL
			// (uses & instead of ? for qualifiers: "pkg:rpm/openEuler/booth&distro=...").
			// KNOWN ISSUES:
			//   1. "upstream" field dropped (same as RSEC above)
			//   2. When PURL is present, getPackage() uses the original ecosystem string
			//      ("openEuler:22.03-LTS-SP3") instead of the package type ("rpm").
			//      For OS packages, the ecosystem should be the package type to match
			//      how matchers search the DB. The no-PURL path (e.g., AlmaLinux) correctly
			//      sets ecosystem to "rpm" via getPackageTypeFromEcosystem().
			//   3. The PURL uses & instead of ? for qualifiers, which may cause purl parsing
			//      to fail or produce incorrect results.
			name:        "openEuler advisory - booth security update",
			fixturePath: "test-fixtures/OESA-2024-2048.json",
			want: []transformers.RelatedEntries{{
				VulnerabilityHandle: &db.VulnerabilityHandle{
					Name:          "OESA-2024-2048",
					Status:        db.VulnerabilityActive,
					ProviderID:    "osv",
					Provider:      expectedProvider(),
					ModifiedDate:  timeRef(time.Date(2025, time.September, 3, 6, 20, 13, 702698000, time.UTC)),
					PublishedDate: timeRef(time.Date(2024, time.August, 23, 11, 8, 56, 0, time.UTC)),
					BlobValue: &db.VulnerabilityBlob{
						ID:          "OESA-2024-2048",
						Description: "Booth manages tickets which authorize cluster sites located in geographically dispersed locations to run resources. It facilitates support of geographically distributed clustering in Pacemaker.\r\n\r\nSecurity Fix(es):\r\n\r\nA flaw was found in Booth, a cluster ticket manager. If a specially-crafted hash is passed to gcry_md_get_algo_dlen(), it may allow an invalid HMAC to be accepted by the Booth server.(CVE-2024-3049)",
						References: []db.Reference{{
							URL:  "https://www.openeuler.org/zh/security/security-bulletins/detail/?id=openEuler-SA-2024-2048",
							Tags: []string{"ADVISORY"},
						}, {
							URL:  "https://nvd.nist.gov/vuln/detail/CVE-2024-3049",
							Tags: []string{"ADVISORY"},
						}},
						Aliases: []string{"CVE-2024-3049"},
					},
				},
				Related: affectedPkgSlice(
					db.AffectedPackageHandle{
						Package: &db.Package{
							Name:      "booth",
							Ecosystem: "rpm",
						},
						OperatingSystem: &db.OperatingSystem{
							Name:         "openeuler",
							ReleaseID:    "openeuler",
							MajorVersion: "22",
							MinorVersion: "03",
							LabelVersion: "LTS-SP3",
						},
						BlobValue: &db.PackageBlob{
							CVEs: []string{"CVE-2024-3049"},
							Ranges: []db.Range{{
								Version: db.Version{
									Type:       "ecosystem",
									Constraint: "<1.0-7.oe2203sp3",
								},
								Fix: &db.Fix{
									Version: "1.0-7.oe2203sp3",
									State:   db.FixedStatus,
								},
							}},
						},
					},
				),
			}},
		},
		{
			// BellSoft / Alpaquita Linux: uses "upstream" field and has two distinct
			// ecosystem variants: "Alpaquita" and "BellSoft Hardened Containers".
			// KNOWN ISSUES:
			//   1. "upstream" field dropped (same as RSEC/OESA above)
			//   2. When PURL is present, ecosystem stays as original string instead of "apk"
			//   3. "BellSoft Hardened Containers" is not in osvOSPackageTypes, so no OS is
			//      detected for those entries. Needs to be added as a separate distro.
			//   4. No "details" or "summary" field → description is empty string
			name:        "BellSoft Alpaquita - sqlite use-after-free",
			fixturePath: "test-fixtures/BELL-CVE-2024-0232.json",
			want: []transformers.RelatedEntries{{
				VulnerabilityHandle: &db.VulnerabilityHandle{
					Name:          "BELL-CVE-2024-0232",
					Status:        db.VulnerabilityActive,
					ProviderID:    "osv",
					Provider:      expectedProvider(),
					ModifiedDate:  timeRef(time.Date(2026, time.January, 26, 9, 34, 44, 321485000, time.UTC)),
					PublishedDate: timeRef(time.Date(2024, time.January, 12, 6, 0, 31, 487567000, time.UTC)),
					BlobValue: &db.VulnerabilityBlob{
						ID: "BELL-CVE-2024-0232",
						References: []db.Reference{{
							URL:  "https://docs.bell-sw.com/security/cves/CVE-2024-0232",
							Tags: []string{"ADVISORY"},
						}},
						Aliases: []string{"CVE-2024-0232"},
						Severities: []db.Severity{{
							Scheme: db.SeveritySchemeCVSS,
							Value: db.CVSSSeverity{
								Vector:  "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
								Version: "3.1",
							},
						}},
					},
				},
				Related: affectedPkgSlice(
					db.AffectedPackageHandle{
						Package: &db.Package{
							Name:      "sqlite",
							Ecosystem: "apk",
						},
						OperatingSystem: &db.OperatingSystem{
							Name:         "alpaquita",
							ReleaseID:    "alpaquita",
							LabelVersion: "stream",
						},
						BlobValue: &db.PackageBlob{
							CVEs: []string{"CVE-2024-0232"},
							Ranges: []db.Range{{
								Version: db.Version{
									Type:       "ecosystem",
									Constraint: ">=3.43.0-r0,<3.43.2-r0",
								},
								Fix: &db.Fix{
									Version: "3.43.2-r0",
									State:   db.FixedStatus,
								},
							}},
						},
					},
					db.AffectedPackageHandle{
						Package: &db.Package{
							Name:      "sqlite",
							Ecosystem: "apk",
						},
						OperatingSystem: &db.OperatingSystem{
							Name:         "bellsoft hardened containers",
							ReleaseID:    "bellsoft hardened containers",
							LabelVersion: "stream",
						},
						BlobValue: &db.PackageBlob{
							CVEs: []string{"CVE-2024-0232"},
							Ranges: []db.Range{{
								Version: db.Version{
									Type:       "ecosystem",
									Constraint: ">=3.43.0-r0,<3.43.2-r0",
								},
								Fix: &db.Fix{
									Version: "3.43.2-r0",
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
			vulns := loadFixture(tt, test.fixturePath)
			var actual []transformers.RelatedEntries
			for _, vuln := range vulns {
				entries, err := Transform(vuln, inputProviderState())
				require.NoError(tt, err)
				for _, entry := range entries {
					e, ok := entry.Data.(transformers.RelatedEntries)
					require.True(tt, ok)
					actual = append(actual, e)
				}
			}

			if diff := cmp.Diff(test.want, actual); diff != "" {
				tt.Errorf("data entries mismatch (-want +got):\n%s", diff)
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
				DatabaseSpecific: map[string]interface{}{
					"anchore": map[string]interface{}{
						"fixes": []interface{}{
							map[string]interface{}{
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
			got := getGrypeRangesFromRange(test.rnge, test.ecosystem)
			if diff := cmp.Diff(test.want, got); diff != "" {
				tt.Errorf("getGrypeRangesFromRange() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func Test_getPackage(t *testing.T) {
	tests := []struct {
		name string
		pkg  models.Package
		want *db.Package
	}{
		{
			name: "valid package",
			pkg: models.Package{
				Ecosystem: "Bitnami",
				Name:      "apache",
				Purl:      "pkg:bitnami/apache",
			},
			want: &db.Package{
				Name:      "apache",
				Ecosystem: "Bitnami",
			},
		},
		{
			name: "package with empty purl",
			pkg: models.Package{
				Ecosystem: "Bitnami",
				Name:      "apache",
				Purl:      "",
			},
			want: &db.Package{
				Name:      "apache",
				Ecosystem: "Bitnami",
			},
		},
		{
			name: "package with empty ecosystem",
			pkg: models.Package{
				Ecosystem: "",
				Name:      "apache",
				Purl:      "pkg:bitnami/apache",
			},
			want: &db.Package{
				Name:      "apache",
				Ecosystem: "",
			},
		},
		// --- New ecosystem test cases ---
		{
			// Go ecosystem: PURL present, ecosystem should stay as original "Go"
			name: "Go package with golang PURL",
			pkg: models.Package{
				Ecosystem: "Go",
				Name:      "google.golang.org/protobuf",
				Purl:      "pkg:golang/google.golang.org/protobuf",
			},
			want: &db.Package{
				Name:      "google.golang.org/protobuf",
				Ecosystem: "Go",
			},
		},
		{
			// CRAN ecosystem: PURL present, ecosystem should stay as original "CRAN"
			name: "CRAN R package with purl",
			pkg: models.Package{
				Ecosystem: "CRAN",
				Name:      "commonmark",
				Purl:      "pkg:cran/commonmark",
			},
			want: &db.Package{
				Name:      "commonmark",
				Ecosystem: "CRAN",
			},
		},
		{
			// CRAN ecosystem without PURL: ecosystem should be normalized to "R-package"
			// (the string value of pkg.Rpkg) since CRAN maps to Rpkg in getPackageTypeFromEcosystem
			name: "CRAN R package without purl",
			pkg: models.Package{
				Ecosystem: "CRAN",
				Name:      "commonmark",
				Purl:      "",
			},
			want: &db.Package{
				Name:      "commonmark",
				Ecosystem: "R-package",
			},
		},
		{
			// AlmaLinux without PURL: ecosystem should be "rpm" (existing working path)
			name: "AlmaLinux package without purl",
			pkg: models.Package{
				Ecosystem: "AlmaLinux:10",
				Name:      "skopeo",
				Purl:      "",
			},
			want: &db.Package{
				Name:      "skopeo",
				Ecosystem: "rpm",
			},
		},
		{
			// openEuler with PURL: ecosystem SHOULD be "rpm" but current code keeps
			// the original ecosystem string when PURL is present.
			// KNOWN BUG: getPackage() returns ecosystem="openEuler:22.03-LTS-SP3"
			// when it should return "rpm" for OS packages.
			name: "openEuler RPM package with purl",
			pkg: models.Package{
				Ecosystem: "openEuler:22.03-LTS-SP3",
				Name:      "booth",
				Purl:      "pkg:rpm/openEuler/booth&distro=openEuler-22.03-LTS-SP3",
			},
			want: &db.Package{
				Name:      "booth",
				Ecosystem: "rpm",
			},
		},
		{
			// Alpaquita with PURL: ecosystem SHOULD be "apk" but current code keeps
			// the original ecosystem string when PURL is present.
			// KNOWN BUG: getPackage() returns ecosystem="Alpaquita:stream"
			name: "Alpaquita APK package with purl",
			pkg: models.Package{
				Ecosystem: "Alpaquita:stream",
				Name:      "sqlite",
				Purl:      "pkg:apk/alpaquita/sqlite?arch=source&distro=stream",
			},
			want: &db.Package{
				Name:      "sqlite",
				Ecosystem: "apk",
			},
		},
		{
			// BellSoft Hardened Containers with PURL: ecosystem SHOULD be "apk"
			// KNOWN BUG: ecosystem is "BellSoft Hardened Containers:stream" and
			// this OS is not in osvOSPackageTypes.
			name: "BellSoft Hardened Containers APK package with purl",
			pkg: models.Package{
				Ecosystem: "BellSoft Hardened Containers:stream",
				Name:      "sqlite",
				Purl:      "pkg:apk/bellsoft-hardened-containers/sqlite?arch=source&distro=stream",
			},
			want: &db.Package{
				Name:      "sqlite",
				Ecosystem: "apk",
			},
		},
	}
	t.Parallel()
	for _, testToRun := range tests {
		test := testToRun
		t.Run(test.name, func(tt *testing.T) {
			tt.Parallel()
			got := getPackage(test.pkg)
			if got.Name != test.want.Name {
				tt.Errorf("getPackage() got name = %v, want %v", got.Name, test.want.Name)
			}
			if got.Ecosystem != test.want.Ecosystem {
				tt.Errorf("getPackage() got ecosystem = %v, want %v", got.Ecosystem, test.want.Ecosystem)
			}
		})
	}
}

func Test_getPackageTypeFromEcosystem(t *testing.T) {
	tests := []struct {
		name      string
		ecosystem string
		want      string // expected pkg.Type string, empty for no match
	}{
		{
			name:      "AlmaLinux",
			ecosystem: "AlmaLinux:10",
			want:      "rpm",
		},
		{
			name:      "Rocky Linux",
			ecosystem: "Rocky:9.2",
			want:      "rpm",
		},
		{
			name:      "openEuler with LTS service pack",
			ecosystem: "openEuler:22.03-LTS-SP3",
			want:      "rpm",
		},
		{
			name:      "Alpaquita numeric version",
			ecosystem: "Alpaquita:23",
			want:      "apk",
		},
		{
			name:      "Alpaquita stream",
			ecosystem: "Alpaquita:stream",
			want:      "apk",
		},
		{
			// BellSoft Hardened Containers is NOT currently in osvOSPackageTypes.
			// This test documents the desired behavior: it should map to apk.
			name:      "BellSoft Hardened Containers",
			ecosystem: "BellSoft Hardened Containers:stream",
			want:      "apk",
		},
		{
			name:      "CRAN maps to R-package",
			ecosystem: "CRAN",
			want:      "R-package",
		},
		{
			name:      "Go has no OS package type",
			ecosystem: "Go",
			want:      "",
		},
		{
			name:      "Bitnami has no OS package type",
			ecosystem: "Bitnami",
			want:      "",
		},
		{
			name:      "empty ecosystem",
			ecosystem: "",
			want:      "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getPackageTypeFromEcosystem(tt.ecosystem)
			if string(got) != tt.want {
				t.Errorf("getPackageTypeFromEcosystem(%q) = %q, want %q", tt.ecosystem, string(got), tt.want)
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
				tt.Errorf("extractCVSSInfo() error = %v, wantErr %v", err, test.wantErr)
				return
			}
			if gotVersion != test.wantVersion {
				tt.Errorf("extractCVSSInfo() got version = %v, want %v", gotVersion, test.wantVersion)
			}
			if gotVector != test.wantVector {
				tt.Errorf("extractCVSSInfo() got vector = %v, want %v", gotVector, test.wantVector)
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
				EcosystemSpecific: map[string]interface{}{
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
				EcosystemSpecific: map[string]interface{}{
					"other_key": "some_value",
				},
			},
			want: "",
		},
		{
			name: "rpm_modularity not string",
			affected: models.Affected{
				EcosystemSpecific: map[string]interface{}{
					"rpm_modularity": 123,
				},
			},
			want: "",
		},
		{
			name: "nodejs modularity",
			affected: models.Affected{
				EcosystemSpecific: map[string]interface{}{
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
				tt.Errorf("extractRpmModularity() = %v, want %v", got, test.want)
			}
		})
	}
}

func Test_getPackageQualifiers(t *testing.T) {
	tests := []struct {
		name     string
		affected models.Affected
		cpes     any
		withCPE  bool
		want     *db.PackageQualifiers
	}{
		{
			name: "with rpm_modularity only",
			affected: models.Affected{
				EcosystemSpecific: map[string]interface{}{
					"rpm_modularity": "mariadb:10.3",
				},
			},
			cpes:    nil,
			withCPE: false,
			want: &db.PackageQualifiers{
				RpmModularity: stringRef("mariadb:10.3"),
			},
		},
		{
			name: "with CPE only",
			affected: models.Affected{
				EcosystemSpecific: nil,
			},
			cpes:    []string{"cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*"},
			withCPE: true,
			want: &db.PackageQualifiers{
				PlatformCPEs: []string{"cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*"},
			},
		},
		{
			name: "with both rpm_modularity and CPE",
			affected: models.Affected{
				EcosystemSpecific: map[string]interface{}{
					"rpm_modularity": "nodejs:16",
				},
			},
			cpes:    []string{"cpe:2.3:a:nodejs:nodejs:*:*:*:*:*:*:*:*"},
			withCPE: true,
			want: &db.PackageQualifiers{
				PlatformCPEs:  []string{"cpe:2.3:a:nodejs:nodejs:*:*:*:*:*:*:*:*"},
				RpmModularity: stringRef("nodejs:16"),
			},
		},
		{
			name: "no qualifiers",
			affected: models.Affected{
				EcosystemSpecific: nil,
			},
			cpes:    nil,
			withCPE: false,
			want:    nil,
		},
	}

	for _, testToRun := range tests {
		test := testToRun
		t.Run(test.name, func(tt *testing.T) {
			got := getPackageQualifiers(test.affected, test.cpes, test.withCPE)
			if diff := cmp.Diff(test.want, got); diff != "" {
				tt.Errorf("getPackageQualifiers() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func Test_getOperatingSystemFromEcosystem(t *testing.T) {
	tests := []struct {
		name      string
		ecosystem string
		want      *db.OperatingSystem
	}{
		{
			name:      "openEuler base LTS",
			ecosystem: "openEuler:20.03-LTS",
			want: &db.OperatingSystem{
				Name:         "openeuler",
				ReleaseID:    "openeuler",
				MajorVersion: "20",
				MinorVersion: "03",
				LabelVersion: "LTS",
			},
		},
		{
			name:      "openEuler LTS service pack",
			ecosystem: "openEuler:20.03-LTS-SP4",
			want: &db.OperatingSystem{
				Name:         "openeuler",
				ReleaseID:    "openeuler",
				MajorVersion: "20",
				MinorVersion: "03",
				LabelVersion: "LTS-SP4",
			},
		},
		{
			name:      "openEuler 24.03 LTS service pack",
			ecosystem: "openEuler:24.03-LTS-SP1",
			want: &db.OperatingSystem{
				Name:         "openeuler",
				ReleaseID:    "openeuler",
				MajorVersion: "24",
				MinorVersion: "03",
				LabelVersion: "LTS-SP1",
			},
		},
		{
			name:      "AlmaLinux major only",
			ecosystem: "AlmaLinux:8",
			want: &db.OperatingSystem{
				Name:         "almalinux",
				ReleaseID:    "almalinux",
				MajorVersion: "8",
			},
		},
		{
			name:      "AlmaLinux major and minor",
			ecosystem: "AlmaLinux:10",
			want: &db.OperatingSystem{
				Name:         "almalinux",
				ReleaseID:    "almalinux",
				MajorVersion: "10",
			},
		},
		{
			name:      "Rocky with minor version",
			ecosystem: "Rocky:9.2",
			want: &db.OperatingSystem{
				Name:         "rocky",
				ReleaseID:    "rocky",
				MajorVersion: "9",
				MinorVersion: "2",
			},
		},
		{
			name:      "Alpaquita stream (non-numeric label)",
			ecosystem: "Alpaquita:stream",
			want: &db.OperatingSystem{
				Name:         "alpaquita",
				ReleaseID:    "alpaquita",
				LabelVersion: "stream",
			},
		},
		{
			name:      "unknown ecosystem returns nil",
			ecosystem: "Bitnami:something",
			want:      nil,
		},
		{
			name:      "no version component returns nil",
			ecosystem: "openEuler",
			want:      nil,
		},
		{
			name:      "empty string returns nil",
			ecosystem: "",
			want:      nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getOperatingSystemFromEcosystem(tt.ecosystem)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("getOperatingSystemFromEcosystem() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func stringRef(s string) *string {
	return &s
}
