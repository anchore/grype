package osv

import (
	"reflect"
	"testing"
	"time"

	"github.com/anchore/grype/grype/db/internal/provider/unmarshal/osvmodel"
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

// TestEventsToRanges exercises event-stream → grype-range conversion.
// Multi-window is load-bearing: stdlib carries two disjoint windows in one
// stream, and the Go parser needs the AND form comma-separated. Trailing
// introduced with no fix → open-ended.
func TestEventsToRanges(t *testing.T) {
	tests := []struct {
		name   string
		events []osvmodel.Event
		want   []db.Range
	}{
		{
			name:   "simple introduced=0 -> fixed",
			events: []osvmodel.Event{{Introduced: "0"}, {Fixed: "1.6.0"}},
			want: []db.Range{{
				Version: db.Version{Type: "go", Constraint: "<1.6.0"},
				Fix:     &db.Fix{Version: "1.6.0", State: db.FixedStatus},
			}},
		},
		{
			name: "two disjoint windows (stdlib shape)",
			events: []osvmodel.Event{
				{Introduced: "0"}, {Fixed: "1.18.6"},
				{Introduced: "1.19.0-0"}, {Fixed: "1.19.1"},
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
			name:   "pseudo-version fixed (golang.org/x/* shape)",
			events: []osvmodel.Event{{Introduced: "0"}, {Fixed: "0.0.0-20220906165146-f3363e06e74c"}},
			want: []db.Range{{
				Version: db.Version{Type: "go", Constraint: "<0.0.0-20220906165146-f3363e06e74c"},
				Fix:     &db.Fix{Version: "0.0.0-20220906165146-f3363e06e74c", State: db.FixedStatus},
			}},
		},
		{
			name:   "trailing introduced with no fix is open-ended",
			events: []osvmodel.Event{{Introduced: "1.2.0"}},
			want: []db.Range{{
				Version: db.Version{Type: "go", Constraint: ">=1.2.0"},
			}},
		},
		{
			name:   "lone introduced=0 yields no ranges (all-versions)",
			events: []osvmodel.Event{{Introduced: "0"}},
			want:   nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := eventsToRanges(tt.events, nil, "go")
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

// TestGoVulnDB_CustomRangesFallback pins the GO-2024-2519 case: the standard
// range is empty ([{introduced: "0"}] yields no constraint), so custom_ranges
// supplies the only window, ">=6.0.0,<7.2.1". EcosystemSpecific uses the
// map[string]any shape the unmarshaler produces, so the round-trip decode runs
// for real.
func TestGoVulnDB_CustomRangesFallback(t *testing.T) {
	affected := osvmodel.Affected{
		Package: osvmodel.Package{Name: "github.com/grafana/grafana", Ecosystem: "Go"},
		Ranges: []osvmodel.Range{{
			Type:   osvmodel.RangeSemVer,
			Events: []osvmodel.Event{{Introduced: "0"}},
		}},
		EcosystemSpecific: map[string]any{
			"custom_ranges": []any{
				map[string]any{
					"type": "ECOSYSTEM",
					"events": []any{
						map[string]any{"introduced": "6.0.0"},
						map[string]any{"fixed": "7.2.1"},
					},
				},
			},
		},
	}

	vuln := osvmodel.Vulnerability{
		ID:       "GO-2024-2519",
		Aliases:  []string{"CVE-2020-12459", "GHSA-m25m-5778-fm22"},
		Affected: []osvmodel.Affected{affected},
	}

	got := govulndbAffectedPackages(vuln)

	want := []db.AffectedPackageHandle{{
		Package: &db.Package{Name: "github.com/grafana/grafana", Ecosystem: "go-module"},
		BlobValue: &db.PackageBlob{
			CVEs: []string{"CVE-2020-12459", "GHSA-m25m-5778-fm22"},
			Ranges: []db.Range{{
				Version: db.Version{Type: "go", Constraint: ">=6.0.0,<7.2.1"},
				Fix:     &db.Fix{Version: "7.2.1", State: db.FixedStatus},
			}},
		},
	}}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("custom_ranges fallback:\n got: %+v\nwant: %+v", got, want)
	}
}

// TestGoVulnDB_NoRangeMeansAllVersions pins GO-2024-3240's shape: a lone
// {introduced: "0"} with no fix and no custom_ranges. go.dev is declaring the
// record affected at every version with no fix, so we emit one affected package
// handle with empty Ranges — grype reads a handle with no ranges as vulnerable
// at all versions. We do not second-guess the record by dropping it.
func TestGoVulnDB_NoRangeMeansAllVersions(t *testing.T) {
	vuln := osvmodel.Vulnerability{
		ID:      "GO-2024-3240",
		Aliases: []string{"CVE-2024-10452", "GHSA-66c4-2g2v-54qw"},
		Affected: []osvmodel.Affected{{
			Package: osvmodel.Package{Name: "github.com/grafana/grafana", Ecosystem: "Go"},
			Ranges:  []osvmodel.Range{{Type: osvmodel.RangeSemVer, Events: []osvmodel.Event{{Introduced: "0"}}}},
		}},
	}
	got := govulndbAffectedPackages(vuln)
	if len(got) != 1 {
		t.Fatalf("expected 1 affected package, got %d: %+v", len(got), got)
	}
	if len(got[0].BlobValue.Ranges) != 0 {
		t.Errorf("expected empty ranges (all-versions), got %+v", got[0].BlobValue.Ranges)
	}
}

// TestGoVulnDB_CustomRangesMultiWindow covers the common multi-window shape
// (GO-2024-2629 etc.): several disjoint windows flattened into one ECOSYSTEM
// range. Each introduced→fixed pair becomes its own db.Range, and the gap
// between windows stays unconstrained.
func TestGoVulnDB_CustomRangesMultiWindow(t *testing.T) {
	affected := osvmodel.Affected{
		Package: osvmodel.Package{Name: "github.com/grafana/grafana", Ecosystem: "Go"},
		// unbounded standard range — the trigger for the custom fallback
		Ranges: []osvmodel.Range{{
			Type:   osvmodel.RangeSemVer,
			Events: []osvmodel.Event{{Introduced: "0"}},
		}},
		EcosystemSpecific: map[string]any{
			"custom_ranges": []any{
				map[string]any{
					"type": "ECOSYSTEM",
					"events": []any{
						map[string]any{"introduced": "8.5.0"},
						map[string]any{"fixed": "9.5.7"},
						map[string]any{"introduced": "10.0.0"},
						map[string]any{"fixed": "10.0.12"},
					},
				},
			},
		},
	}

	vuln := osvmodel.Vulnerability{ID: "GO-2024-2629", Affected: []osvmodel.Affected{affected}}
	got := govulndbAffectedPackages(vuln)

	want := []db.Range{
		{
			Version: db.Version{Type: "go", Constraint: ">=8.5.0,<9.5.7"},
			Fix:     &db.Fix{Version: "9.5.7", State: db.FixedStatus},
		},
		{
			Version: db.Version{Type: "go", Constraint: ">=10.0.0,<10.0.12"},
			Fix:     &db.Fix{Version: "10.0.12", State: db.FixedStatus},
		},
	}

	if len(got) != 1 {
		t.Fatalf("expected 1 affected package, got %d", len(got))
	}
	if !reflect.DeepEqual(got[0].BlobValue.Ranges, want) {
		t.Errorf("multi-window custom_ranges:\n got: %+v\nwant: %+v", got[0].BlobValue.Ranges, want)
	}
}

// TestGoVulnDB_OpenEndedStandardWithCustom covers records with both standard
// ranges and custom_ranges:
//   - GO-2025-4153: standard is a fix-less floor (>= a v1.9.2 pseudo-version),
//     grafted onto custom's first window (its introduced:0 becomes the floor).
//   - GO-2026-4916: standard is bounded +incompatible tag windows, kept and
//     unioned with custom; dropping them would be a false negative.
func TestGoVulnDB_OpenEndedStandardWithCustom(t *testing.T) {
	t.Run("floor grafted onto custom first window (grafana GO-2025-4153)", func(t *testing.T) {
		affected := osvmodel.Affected{
			Package: osvmodel.Package{Name: "github.com/grafana/grafana", Ecosystem: "Go"},
			Ranges: []osvmodel.Range{{
				Type:   osvmodel.RangeSemVer,
				Events: []osvmodel.Event{{Introduced: "1.9.2-0.20250310110405-e6fdb746f235"}},
			}},
			EcosystemSpecific: map[string]any{
				"custom_ranges": []any{map[string]any{
					"type": "ECOSYSTEM",
					"events": []any{
						map[string]any{"introduced": "0"},
						map[string]any{"fixed": "1.9.2-0.20251106142618-ca5d89812015"},
						map[string]any{"introduced": "12.0.0"}, map[string]any{"fixed": "12.0.7"},
					},
				}},
			},
		}
		vuln := osvmodel.Vulnerability{ID: "GO-2025-4153", Aliases: []string{"CVE-2025-41115"}, Affected: []osvmodel.Affected{affected}}

		got := govulndbAffectedPackages(vuln)
		want := []db.AffectedPackageHandle{{
			Package: &db.Package{Name: "github.com/grafana/grafana", Ecosystem: "go-module"},
			BlobValue: &db.PackageBlob{
				CVEs: []string{"CVE-2025-41115"},
				// custom's introduced:0 is raised to the standard floor.
				Ranges: []db.Range{
					{
						Version: db.Version{Type: "go", Constraint: ">=1.9.2-0.20250310110405-e6fdb746f235,<1.9.2-0.20251106142618-ca5d89812015"},
						Fix:     &db.Fix{Version: "1.9.2-0.20251106142618-ca5d89812015", State: db.FixedStatus},
					},
					{
						Version: db.Version{Type: "go", Constraint: ">=12.0.0,<12.0.7"},
						Fix:     &db.Fix{Version: "12.0.7", State: db.FixedStatus},
					},
				},
			},
		}}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("open-ended drop:\n got: %+v\nwant: %+v", got, want)
		}
	})

	t.Run("bounded standard kept, custom appended (mattermost GO-2026-4916)", func(t *testing.T) {
		affected := osvmodel.Affected{
			Package: osvmodel.Package{Name: "github.com/mattermost/mattermost-server", Ecosystem: "Go"},
			Ranges: []osvmodel.Range{{
				Type: osvmodel.RangeSemVer,
				Events: []osvmodel.Event{
					{Introduced: "11.2.0-rc1+incompatible"},
					{Fixed: "11.2.4+incompatible"},
				},
			}},
			EcosystemSpecific: map[string]any{
				"custom_ranges": []any{map[string]any{
					"type": "ECOSYSTEM",
					"events": []any{
						map[string]any{"introduced": "8.0.0-20260105080200-d27a2195068d"},
						map[string]any{"fixed": "8.0.0-20260217110922-b7d4a1f1f59b"},
					},
				}},
			},
		}
		vuln := osvmodel.Vulnerability{ID: "GO-2026-4916", Aliases: []string{"CVE-2026-26233"}, Affected: []osvmodel.Affected{affected}}

		got := govulndbAffectedPackages(vuln)
		want := []db.AffectedPackageHandle{{
			Package: &db.Package{Name: "github.com/mattermost/mattermost-server", Ecosystem: "go-module"},
			BlobValue: &db.PackageBlob{
				CVEs: []string{"CVE-2026-26233"},
				Ranges: []db.Range{
					// bounded standard window kept...
					{
						Version: db.Version{Type: "go", Constraint: ">=11.2.0-rc1+incompatible,<11.2.4+incompatible"},
						Fix:     &db.Fix{Version: "11.2.4+incompatible", State: db.FixedStatus},
					},
					// ...with the disjoint custom pseudo-version window appended
					{
						Version: db.Version{Type: "go", Constraint: ">=8.0.0-20260105080200-d27a2195068d,<8.0.0-20260217110922-b7d4a1f1f59b"},
						Fix:     &db.Fix{Version: "8.0.0-20260217110922-b7d4a1f1f59b", State: db.FixedStatus},
					},
				},
			},
		}}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("bounded keep + union:\n got: %+v\nwant: %+v", got, want)
		}
	})
}

// TestGoVulnDB_WithdrawnRecord pins that an OSV `withdrawn` timestamp surfaces as
// Status=Rejected with WithdrawnDate set — the gate the matcher's
// OnlyNonWithdrawnVulnerabilities filter keys off. GO-2022-0617 drove this:
// go.dev withdrew it but the strategy had been emitting it Active.
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

// TestGoVulnDB_MalformedCustomRangesKeepsStandard pins Wave-1.1: a custom_ranges
// value that fails to decode (here, introduced arrives as a number) must not
// erase the standard range. govulndbCustomRanges logs and returns nil, so the
// record falls back to standard-range-only matching.
func TestGoVulnDB_MalformedCustomRangesKeepsStandard(t *testing.T) {
	vuln := osvmodel.Vulnerability{
		ID:      "GO-0000-0001",
		Aliases: []string{"CVE-0000-0001"},
		Affected: []osvmodel.Affected{{
			Package: osvmodel.Package{Name: "github.com/example/mod", Ecosystem: "Go"},
			Ranges:  []osvmodel.Range{{Type: osvmodel.RangeSemVer, Events: []osvmodel.Event{{Introduced: "0"}, {Fixed: "1.2.0"}}}},
			EcosystemSpecific: map[string]any{"custom_ranges": []any{map[string]any{
				"type":   "ECOSYSTEM",
				"events": []any{map[string]any{"introduced": 5}}, // int, not string -> decode error
			}}},
		}},
	}
	got := govulndbAffectedPackages(vuln)
	want := []db.Range{{
		Version: db.Version{Type: "go", Constraint: "<1.2.0"},
		Fix:     &db.Fix{Version: "1.2.0", State: db.FixedStatus},
	}}
	if len(got) != 1 || !reflect.DeepEqual(got[0].BlobValue.Ranges, want) {
		t.Errorf("malformed custom_ranges should keep standard %v, got %+v", want, got)
	}
}

// TestGoVulnDB_WindowlessCustomKeepsStandard pins Wave-1.2: a custom_ranges that
// decodes fine but yields no version windows (an event with only `limit`) must
// not erase the standard range. Without the guard this emitted zero ranges,
// which grype reads as "vulnerable at every version" — a silent over-match.
func TestGoVulnDB_WindowlessCustomKeepsStandard(t *testing.T) {
	vuln := osvmodel.Vulnerability{
		ID: "GO-0000-0002",
		Affected: []osvmodel.Affected{{
			Package: osvmodel.Package{Name: "github.com/example/mod", Ecosystem: "Go"},
			// open-ended floor standard: ">= 5.0.0"
			Ranges: []osvmodel.Range{{Type: osvmodel.RangeSemVer, Events: []osvmodel.Event{{Introduced: "5.0.0"}}}},
			EcosystemSpecific: map[string]any{"custom_ranges": []any{map[string]any{
				"type":   "ECOSYSTEM",
				"events": []any{map[string]any{"limit": "9.9.9"}}, // no introduced/fixed -> no window
			}}},
		}},
	}
	got := govulndbAffectedPackages(vuln)
	want := []db.Range{{Version: db.Version{Type: "go", Constraint: ">=5.0.0"}}}
	if len(got) != 1 || !reflect.DeepEqual(got[0].BlobValue.Ranges, want) {
		t.Errorf("windowless custom_ranges should keep standard %v, got %+v", want, got)
	}
}
