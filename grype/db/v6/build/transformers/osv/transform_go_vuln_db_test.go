package osv

import (
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/anchore/grype/grype/db/internal/provider/unmarshal/osvmodel"
	db "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/build/transformers"
)

// TestGoVulnDBTransform exercises the govulndb strategy end-to-end against a real
// GO-* fixture. The transformer emits the stdlib pseudo-module and the
// golang.org/x/* extended standard libraries (see govulndbEmits); other
// third-party modules are dropped.
//
//   - GO-2022-0969: a MIXED record listing both "stdlib" and "golang.org/x/net".
//     Both survive the emit filter, so the want below contains BOTH handles
//     (golang.org/x/net sorts before stdlib). The stdlib range is multi-window
//     (< 1.18.6 || >= 1.19.0-0,< 1.19.1), exercising the comma-separated constraint
//     normalization the Go version comparator needs; the golang.org/x/net range is
//     a single pseudo-version window, exercising the golang.org/x/* emit path.
func TestGoVulnDBTransform(t *testing.T) {
	tests := []transformCase{
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
							Qualifiers: &db.PackageQualifiers{
								GoImports: []db.GoImport{{
									Path:    "golang.org/x/net/http2",
									Symbols: []string{"Server.ServeConn", "serverConn.goAway"},
								}},
							},
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
							Qualifiers: &db.PackageQualifiers{
								GoImports: []db.GoImport{{
									Path: "net/http",
									Symbols: []string{
										"ListenAndServe", "ListenAndServeTLS", "Serve", "ServeTLS",
										"Server.ListenAndServe", "Server.ListenAndServeTLS", "Server.Serve", "Server.ServeTLS",
										"http2Server.ServeConn", "http2serverConn.goAway",
									},
								}},
							},
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
				{Introduced: "0"},
				{Fixed: "1.18.6"},
				{Introduced: "1.19.0-0"},
				{Fixed: "1.19.1"},
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

// TestGoVulnDB_NonStdlibEmitsNothing guards the drop path for general third-party
// modules: an advisory whose only affected package is a non-emitted module (here
// github.com/gin-gonic/gin — not stdlib and not golang.org/x/*) must produce NO
// entries at all — not an orphaned vulnerability handle with zero affected
// packages. Transform returns early when every affected package is filtered out,
// so such a GO record never reaches the DB.
func TestGoVulnDB_NonStdlibEmitsNothing(t *testing.T) {
	vulns := loadFixture(t, "testdata/GO-2020-0001.json")
	if len(vulns) != 1 {
		t.Fatalf("expected 1 vuln in fixture, got %d", len(vulns))
	}
	entries, err := Transform(vulns[0], inputProviderState())
	if err != nil {
		t.Fatalf("transform: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("non-stdlib advisory must emit no entries (no orphaned vuln handle), got %d", len(entries))
	}
}

// TestGoVulnDB_WithdrawnStdlibIsRejected pins that a WITHDRAWN govulndb advisory
// survives the stdlib-only filter (it has a stdlib affected package) but is
// emitted with Status=Rejected + a WithdrawnDate, so the matcher's
// OnlyNonWithdrawnVulnerabilities filter drops it — a withdrawn stdlib advisory
// must NOT match. No real stdlib record is withdrawn today, so this builds one
// inline to exercise the withdrawn-marking path.
func TestGoVulnDB_WithdrawnStdlibIsRejected(t *testing.T) {
	withdrawn := time.Date(2024, time.August, 21, 16, 25, 56, 0, time.UTC)
	vuln := osvmodel.Vulnerability{
		ID:        "GO-0000-9999",
		Withdrawn: withdrawn,
		Affected: []osvmodel.Affected{{
			Package: osvmodel.Package{Name: "stdlib", Ecosystem: "Go"},
			Ranges:  []osvmodel.Range{{Type: osvmodel.RangeSemVer, Events: []osvmodel.Event{{Introduced: "0"}, {Fixed: "1.18.6"}}}},
		}},
	}
	entries, err := Transform(vuln, inputProviderState())
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
		t.Errorf("Status = %q, want %q (withdrawn must surface as rejected so the matcher drops it)", vh.Status, db.VulnerabilityRejected)
	}
	if vh.WithdrawnDate == nil || !vh.WithdrawnDate.Equal(withdrawn) {
		t.Errorf("WithdrawnDate = %v, want %s", vh.WithdrawnDate, withdrawn)
	}
}

// TestGoVulnDB_EmitsStdlibAndGolangOrgX pins the emit filter on a real MIXED
// advisory: GO-2022-0969 lists both "stdlib" and "golang.org/x/net". Both classes
// are emitted — stdlib because it is statically linked into every Go binary, and
// golang.org/x/net because the golang.org/x/* extended standard libraries are
// versioned by the Go team and absent from GHSA, so they don't carry the
// false-positive/duplicate baggage that motivates dropping general third-party
// modules. Per-package filtering is asserted on a single record.
func TestGoVulnDB_EmitsStdlibAndGolangOrgX(t *testing.T) {
	vulns := loadFixture(t, "testdata/GO-2022-0969.json")
	if len(vulns) != 1 {
		t.Fatalf("expected 1 vuln, got %d", len(vulns))
	}

	// sanity: the fixture really is mixed, otherwise this test proves nothing
	var fixtureNames []string
	for _, a := range vulns[0].Affected {
		fixtureNames = append(fixtureNames, a.Package.Name)
	}
	if len(fixtureNames) < 2 {
		t.Fatalf("fixture is not mixed (need stdlib + golang.org/x/*), got %v", fixtureNames)
	}

	got := map[string]bool{}
	for _, aph := range govulndbAffectedPackages(vulns[0]) {
		got[aph.Package.Name] = true
	}
	for _, want := range []string{"stdlib", "golang.org/x/net"} {
		if !got[want] {
			t.Errorf("expected %q to survive the emit filter, got %v (fixture had %v)", want, keys(got), fixtureNames)
		}
	}
	if len(got) != 2 {
		t.Errorf("expected exactly [stdlib golang.org/x/net] to survive, got %v (fixture had %v)", keys(got), fixtureNames)
	}
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
