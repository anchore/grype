package osv

import (
	"reflect"
	"testing"
	"time"

	"github.com/google/osv-scanner/pkg/models"

	db "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/build/transformers"
)

// TestGoVulnDBTransform exercises the govulndb strategy end-to-end against real
// GO-* fixtures.
//
//   - GO-2020-0001: regular Go module (github.com/gin-gonic/gin) with a single
//     introduced→fixed SEMVER range; the dominant shape for non-stdlib records.
//   - GO-2022-0969: stdlib record with a multi-window SEMVER range
//     (< 1.18.6 || >= 1.19.0-0,< 1.19.1); exercises the comma-separated
//     constraint normalization needed by the Go version comparator.
func TestGoVulnDBTransform(t *testing.T) {
	tests := []transformCase{
		{
			name:        "gin-gonic 2020-0001 single window",
			fixturePath: "testdata/GO-2020-0001.json",
			want: []transformers.RelatedEntries{{
				VulnerabilityHandle: &db.VulnerabilityHandle{
					Name:          "GO-2020-0001",
					Status:        db.VulnerabilityActive,
					ProviderID:    "osv",
					Provider:      expectedProvider(),
					ModifiedDate:  timeRef(time.Date(2024, time.May, 20, 16, 3, 47, 0, time.UTC)),
					PublishedDate: timeRef(time.Date(2021, time.April, 14, 20, 4, 52, 0, time.UTC)),
					BlobValue: &db.VulnerabilityBlob{
						ID:          "GO-2020-0001",
						Description: "The default Formatter for the Logger middleware (LoggerConfig.Formatter), which is included in the Default engine, allows attackers to inject arbitrary log entries by manipulating the request path.",
						References: []db.Reference{{
							URL:  "https://github.com/gin-gonic/gin/pull/2237",
							Tags: []string{"FIX"},
						}, {
							URL:  "https://github.com/gin-gonic/gin/commit/a71af9c144f9579f6dbe945341c1df37aaf09c0d",
							Tags: []string{"FIX"},
						}},
						Aliases: []string{"CVE-2020-36567", "GHSA-6vm3-jj99-7229"},
					},
				},
				Related: affectedPkgSlice(
					db.AffectedPackageHandle{
						Package: &db.Package{
							Name:      "github.com/gin-gonic/gin",
							Ecosystem: "go-module",
						},
						BlobValue: &db.PackageBlob{
							CVEs: []string{"CVE-2020-36567", "GHSA-6vm3-jj99-7229"},
							Ranges: []db.Range{{
								Version: db.Version{
									Type:       "go",
									Constraint: "<1.6.0",
								},
								Fix: &db.Fix{
									Version: "1.6.0",
									State:   db.FixedStatus,
									// FixDetail is populated from
									// range.database_specific.anchore.fixes,
									// which the vunnel govulndb provider
									// attaches via osv.patch_fix_date using
									// the advisory's published date as a
									// low-confidence candidate.
									Detail: &db.FixDetail{
										Available: &db.FixAvailability{
											Date: timeRef(time.Date(2021, time.April, 14, 0, 0, 0, 0, time.UTC)),
											Kind: "advisory",
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
			name:        "stdlib 2022-0969 multi-window",
			fixturePath: "testdata/GO-2022-0969.json",
			want: []transformers.RelatedEntries{{
				VulnerabilityHandle: &db.VulnerabilityHandle{
					Name:          "GO-2022-0969",
					Status:        db.VulnerabilityActive,
					ProviderID:    "osv",
					Provider:      expectedProvider(),
					ModifiedDate:  timeRef(time.Date(2024, time.May, 20, 16, 3, 47, 0, time.UTC)),
					PublishedDate: timeRef(time.Date(2022, time.September, 12, 20, 23, 6, 0, time.UTC)),
					BlobValue: &db.VulnerabilityBlob{
						ID:          "GO-2022-0969",
						Description: "HTTP/2 server connections can hang forever waiting for a clean shutdown that was preempted by a fatal error. This condition can be exploited by a malicious client to cause a denial of service.",
						References: []db.Reference{{
							URL:  "https://groups.google.com/g/golang-announce/c/x49AQzIVX-s",
							Tags: []string{"WEB"},
						}, {
							URL:  "https://go.dev/issue/54658",
							Tags: []string{"REPORT"},
						}, {
							URL:  "https://go.dev/cl/428735",
							Tags: []string{"FIX"},
						}},
						Aliases: []string{"CVE-2022-27664", "GHSA-69cg-p879-7622"},
					},
				},
				Related: affectedPkgSlice(
					db.AffectedPackageHandle{
						Package: &db.Package{
							Name:      "golang.org/x/net",
							Ecosystem: "go-module",
						},
						BlobValue: &db.PackageBlob{
							CVEs: []string{"CVE-2022-27664", "GHSA-69cg-p879-7622"},
							Ranges: []db.Range{{
								Version: db.Version{
									Type:       "go",
									Constraint: "<0.0.0-20220906165146-f3363e06e74c",
								},
								Fix: &db.Fix{
									Version: "0.0.0-20220906165146-f3363e06e74c",
									State:   db.FixedStatus,
								},
							}},
						},
					},
					db.AffectedPackageHandle{
						Package: &db.Package{
							Name:      "stdlib",
							Ecosystem: "go-module",
						},
						BlobValue: &db.PackageBlob{
							CVEs: []string{"CVE-2022-27664", "GHSA-69cg-p879-7622"},
							Ranges: []db.Range{{
								Version: db.Version{
									Type:       "go",
									Constraint: "<1.18.6",
								},
								Fix: &db.Fix{
									Version: "1.18.6",
									State:   db.FixedStatus,
								},
							}, {
								Version: db.Version{
									Type:       "go",
									Constraint: ">=1.19.0-0,<1.19.1",
								},
								Fix: &db.Fix{
									Version: "1.19.1",
									State:   db.FixedStatus,
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

// TestGoVulnDBRangeConversion exercises the Go-flavored range-conversion path:
// govulndbRangeType maps OSV's SEMVER to "go", then getGrypeRangesFromRange
// builds the affected version constraints. Multi-window inputs are the
// load-bearing case — stdlib records carry two disjoint windows in one range,
// and the AND form must come out comma-separated so the Go constraint parser
// accepts it.
func TestGoVulnDBRangeConversion(t *testing.T) {
	tests := []struct {
		name string
		rnge models.Range
		want []db.Range
	}{
		{
			name: "simple introduced=0 -> fixed",
			rnge: models.Range{
				Type: models.RangeSemVer,
				Events: []models.Event{
					{Introduced: "0"},
					{Fixed: "1.6.0"},
				},
			},
			want: []db.Range{{
				Version: db.Version{Type: "go", Constraint: "<1.6.0"},
				Fix:     &db.Fix{Version: "1.6.0", State: db.FixedStatus},
			}},
		},
		{
			name: "two disjoint windows in one range (stdlib shape)",
			rnge: models.Range{
				Type: models.RangeSemVer,
				Events: []models.Event{
					{Introduced: "0"},
					{Fixed: "1.18.6"},
					{Introduced: "1.19.0-0"},
					{Fixed: "1.19.1"},
				},
			},
			want: []db.Range{
				{
					Version: db.Version{Type: "go", Constraint: "<1.18.6"},
					Fix:     &db.Fix{Version: "1.18.6", State: db.FixedStatus},
				},
				{
					Version: db.Version{Type: "go", Constraint: ">=1.19.0-0,<1.19.1"},
					Fix:     &db.Fix{Version: "1.19.1", State: db.FixedStatus},
				},
			},
		},
		{
			name: "pseudo-version fixed (golang.org/x/* shape)",
			rnge: models.Range{
				Type: models.RangeSemVer,
				Events: []models.Event{
					{Introduced: "0"},
					{Fixed: "0.0.0-20220906165146-f3363e06e74c"},
				},
			},
			want: []db.Range{{
				Version: db.Version{Type: "go", Constraint: "<0.0.0-20220906165146-f3363e06e74c"},
				Fix:     &db.Fix{Version: "0.0.0-20220906165146-f3363e06e74c", State: db.FixedStatus},
			}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getGrypeRangesFromRange(tt.rnge, govulndbRangeType(tt.rnge.Type))
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

// TestGoVulnDB_WithdrawnRecord pins down that records with an OSV `withdrawn`
// timestamp surface to grype as Status=Rejected with WithdrawnDate set. The
// matcher's OnlyNonWithdrawnVulnerabilities filter keys off Status, so this is
// the gate that stops withdrawn GO advisories from being matched as live
// vulnerabilities (GO-2022-0617 was the symptom that drove this fix — go.dev
// withdrew it as a "low severity issue with no fix available or planned;
// likely to cause false positives", but the strategy was emitting it Active).
func TestGoVulnDB_WithdrawnRecord(t *testing.T) {
	vulns := loadFixture(t, "testdata/GO-2022-0617.json")
	if len(vulns) != 1 {
		t.Fatalf("expected 1 vuln, got %d", len(vulns))
	}

	entries, err := Transform(vulns[0], inputProviderState())
	if err != nil {
		t.Fatalf("transform: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}

	re, ok := entries[0].Data.(transformers.RelatedEntries)
	if !ok {
		t.Fatalf("unexpected entry type %T", entries[0].Data)
	}
	vh := re.VulnerabilityHandle
	if vh == nil {
		t.Fatal("entry has no VulnerabilityHandle")
	}

	if vh.Status != db.VulnerabilityRejected {
		t.Errorf("Status = %q, want %q (matcher's OnlyNonWithdrawnVulnerabilities only filters \"rejected\"/\"withdrawn\" — anything else lets the record through)",
			vh.Status, db.VulnerabilityRejected)
	}
	wantWithdrawn := time.Date(2024, time.August, 21, 16, 25, 56, 0, time.UTC)
	if vh.WithdrawnDate == nil {
		t.Errorf("WithdrawnDate is nil; want %s", wantWithdrawn)
	} else if !vh.WithdrawnDate.Equal(wantWithdrawn) {
		t.Errorf("WithdrawnDate = %s, want %s", vh.WithdrawnDate, wantWithdrawn)
	}
}
