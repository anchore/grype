package osv

import (
	"reflect"
	"testing"
	"time"

	"github.com/google/osv-scanner/pkg/models"

	db "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/build/transformers"
)

// TestBitnamiTransform exercises the bitnami strategy end-to-end against real
// BIT-* fixtures.
//
//   - BIT-apache-2020-11984: introduced + last_affected range shape (no fixed
//     event); also has database_specific.cpes which the strategy intentionally
//     does *not* extract — the expected output has nil Qualifiers, locking in
//     the deliberate CPE drop.
//   - BIT-node-2020-8201: two-window range with anchore.fixes range-level
//     metadata; exercises the fix-availability decoding path end-to-end.
func TestBitnamiTransform(t *testing.T) {
	tests := []transformCase{
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
							// Qualifiers intentionally nil: bitnami records carry
							// database_specific.cpes (application CPEs like apache:http_server)
							// but the bitnami strategy doesn't extract them. The platform CPE
							// runtime qualifier is a no-op for application CPEs and the bitnami
							// matcher never queries by CPE, so storing them is dead weight.
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
	}
	runTransformCases(t, tests)
}

// TestBitnamiRangeConversion exercises the bitnami-flavored range-conversion
// path: bitnamiRangeType maps OSV's SEMVER to "bitnami", then
// getGrypeRangesFromRange builds the affected version constraints.
//
// Inputs use real bitnami range shapes (SEMVER with introduced/fixed,
// last_affected, multi-window, with and without anchore.fixes metadata).
func TestBitnamiRangeConversion(t *testing.T) {
	tests := []struct {
		name string
		rnge models.Range
		want []db.Range
	}{
		{
			name: "simple introduced -> fixed semver range",
			rnge: models.Range{
				Type: models.RangeSemVer,
				Events: []models.Event{
					{Introduced: "12.0.0"},
					{Fixed: "12.18.4"},
				},
			},
			want: []db.Range{{
				Version: db.Version{Type: "bitnami", Constraint: ">=12.0.0,<12.18.4"},
				Fix:     &db.Fix{Version: "12.18.4", State: db.FixedStatus},
			}},
		},
		{
			name: "introduced=0 -> fixed produces fixed-only constraint",
			rnge: models.Range{
				Type: models.RangeSemVer,
				Events: []models.Event{
					{Introduced: "0"},
					{Fixed: "3.4.0"},
				},
			},
			want: []db.Range{{
				Version: db.Version{Type: "bitnami", Constraint: "<3.4.0"},
				Fix:     &db.Fix{Version: "3.4.0", State: db.FixedStatus},
			}},
		},
		{
			name: "introduced + last_affected (no fixed event)",
			rnge: models.Range{
				Type: models.RangeSemVer,
				Events: []models.Event{
					{Introduced: "2.4.32"},
					{LastAffected: "2.4.43"},
				},
			},
			want: []db.Range{{
				Version: db.Version{Type: "bitnami", Constraint: ">=2.4.32,<=2.4.43"},
			}},
		},
		{
			name: "two disjoint introduced/fixed windows in one range",
			rnge: models.Range{
				Type: models.RangeSemVer,
				Events: []models.Event{
					{Introduced: "0"},
					{Fixed: "3.2.2"},
					{Introduced: "3.3.0"},
					{Fixed: "3.3.1"},
				},
			},
			want: []db.Range{
				{
					Version: db.Version{Type: "bitnami", Constraint: "<3.2.2"},
					Fix:     &db.Fix{Version: "3.2.2", State: db.FixedStatus},
				},
				{
					Version: db.Version{Type: "bitnami", Constraint: ">=3.3.0,<3.3.1"},
					Fix:     &db.Fix{Version: "3.3.1", State: db.FixedStatus},
				},
			},
		},
		{
			name: "range with anchore.fixes metadata attaches FixDetail",
			rnge: models.Range{
				Type: models.RangeSemVer,
				Events: []models.Event{
					{Introduced: "12.0.0"},
					{Fixed: "12.18.4"},
				},
				DatabaseSpecific: map[string]any{
					"anchore": map[string]any{
						"fixes": []any{
							map[string]any{
								"version": "12.18.4",
								"date":    "2020-09-15",
								"kind":    "first-observed",
							},
						},
					},
				},
			},
			want: []db.Range{{
				Version: db.Version{Type: "bitnami", Constraint: ">=12.0.0,<12.18.4"},
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
			}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getGrypeRangesFromRange(tt.rnge, bitnamiRangeType(tt.rnge.Type))
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}
