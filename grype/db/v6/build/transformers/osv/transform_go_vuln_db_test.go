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
// GO-* fixture.
//
//   - GO-2022-0969: a MIXED record listing both "stdlib" and "golang.org/x/net",
//     so the want below contains BOTH handles
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
						Aliases:      []string{"CVE-2022-27664", "GHSA-69cg-p879-7622"},
						ReviewStatus: "REVIEWED",
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

// TestGoVulnDB_ThirdPartyEmitsAffectedPackage pins that general third-party
// modules (here github.com/gin-gonic/gin — not stdlib and not golang.org/x/*)
// are emitted with their imports qualifier and review status intact. The overlap
// with GHSA-sourced advisories for the same module is reconciled by the build
// writer (handleGoVulnDBEntry), not by dropping the package here.
func TestGoVulnDB_ThirdPartyEmitsAffectedPackage(t *testing.T) {
	vulns := loadFixture(t, "testdata/GO-2020-0001.json")
	if len(vulns) != 1 {
		t.Fatalf("expected 1 vuln in fixture, got %d", len(vulns))
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
	if re.VulnerabilityHandle == nil || re.VulnerabilityHandle.BlobValue == nil {
		t.Fatal("entry has no VulnerabilityHandle with a blob")
	}
	if got := re.VulnerabilityHandle.BlobValue.ReviewStatus; got != "REVIEWED" {
		t.Errorf("ReviewStatus = %q, want %q", got, "REVIEWED")
	}
	if len(re.Related) != 1 {
		t.Fatalf("expected 1 affected package, got %d", len(re.Related))
	}
	aph, ok := re.Related[0].(db.AffectedPackageHandle)
	if !ok {
		t.Fatalf("unexpected related entry type %T", re.Related[0])
	}
	if aph.Package == nil || aph.Package.Name != "github.com/gin-gonic/gin" {
		t.Errorf("expected affected package github.com/gin-gonic/gin, got %+v", aph.Package)
	}
	if aph.BlobValue == nil || aph.BlobValue.Qualifiers == nil || len(aph.BlobValue.Qualifiers.GoImports) != 1 {
		t.Fatalf("expected 1 go import on the qualifier, got %+v", aph.BlobValue)
	}
	if got := aph.BlobValue.Qualifiers.GoImports[0].Path; got != "github.com/gin-gonic/gin" {
		t.Errorf("import path = %q, want %q", got, "github.com/gin-gonic/gin")
	}
}

// TestGoVulnDB_WithdrawnStdlibIsRejected pins that a WITHDRAWN govulndb advisory
// is emitted with Status=Rejected + a WithdrawnDate, so the matcher's
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

// TestGoVulnDB_CustomRangesOnRealRecords guards the ecosystem_specific
// custom_ranges reconciliation against real vuln.go.dev records now that
// third-party modules are emitted. These are the shapes govulncheck gives up on
// ("bails and assumes vulnerable"); grype must emit the real windows instead:
//
//   - GO-2025-4004 (lxd): the standard range is a bare introduced:0 (says
//     nothing), so custom supersedes. The custom stream is messy — a dangling
//     introduced:4.0.0 immediately overwritten by a pseudo-version window — and
//     must still yield bounded windows, not all-versions-vulnerable. The /v6
//     major-version module carries its own clean custom window.
//   - GO-2024-2826 (vitess): bounded standard windows in module-version space
//     (0.17/0.18/0.19) plus bounded custom windows in upstream-tag space
//     (17/18/19; GHSA lists these under github.com/vitessio/vitess). Bounded +
//     bounded unions both sets: the tag-space windows cannot match a
//     module-versioned (0.x) package, so the union covers both version schemes
//     without widening either.
//   - GO-2026-4610 (docker): the +incompatible case — an open-ended custom floor
//     (>=19.03.0+incompatible) grafts onto the standard window's placeholder
//     introduced:0 rather than appending as a disjoint trailing window
//     (anchore/grype#3520). Sibling modules pass through untouched: a lone
//     introduced:0 yields no ranges (a real all-versions-vulnerable advisory for
//     deprecated compose v1) and an open-ended standard floor stays open-ended.
func TestGoVulnDB_CustomRangesOnRealRecords(t *testing.T) {
	tests := []struct {
		name        string
		fixturePath string
		want        map[string][]string // package name -> range constraints
	}{
		{
			name:        "GO-2025-4004 lxd: default-floor standard, messy custom windows",
			fixturePath: "testdata/GO-2025-4004.json",
			want: map[string][]string{
				"github.com/lxc/lxd": {
					"<5.21.4",
					">=0.0.0-20200331193331-03aab09f5b5c,<0.0.0-20250827065555-0494f5d47e41",
				},
				"github.com/lxc/lxd/v6": {
					">=6.0.0,<6.5.0",
				},
			},
		},
		{
			name:        "GO-2024-2826 vitess: bounded standard + bounded tag-space custom union",
			fixturePath: "testdata/GO-2024-2826.json",
			want: map[string][]string{
				"vitess.io/vitess": {
					"<0.17.7",
					">=0.18.0,<0.18.5",
					">=0.19.0,<0.19.4",
					"<17.0.7",
					">=18.0.0,<18.0.5",
					">=19.0.0,<19.0.4",
				},
			},
		},
		{
			name:        "GO-2026-4610 docker: +incompatible floor graft and pass-through siblings",
			fixturePath: "testdata/GO-2026-4610.json",
			want: map[string][]string{
				"github.com/docker/cli":        {">=19.03.0+incompatible,<29.2.0+incompatible"},
				"github.com/docker/compose":    nil, // lone introduced:0 -> all versions vulnerable
				"github.com/docker/compose/v2": {">=2.31.0"},
				"github.com/docker/compose/v5": {"<5.1.0"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vulns := loadFixture(t, tt.fixturePath)
			if len(vulns) != 1 {
				t.Fatalf("expected 1 vuln in fixture, got %d", len(vulns))
			}
			got := map[string][]string{}
			for _, aph := range govulndbAffectedPackages(vulns[0]) {
				var constraints []string
				for _, r := range aph.BlobValue.Ranges {
					constraints = append(constraints, r.Version.Constraint)
				}
				got[aph.Package.Name] = constraints
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ranges by package mismatch:\ngot:  %v\nwant: %v", got, tt.want)
			}
		})
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
