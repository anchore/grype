package osv

import (
	"reflect"
	"testing"
	"time"

	"github.com/anchore/grype/grype/db/internal/provider/unmarshal/osvmodel"
	db "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/build/transformers"
)

// TestBellsoftTransform exercises the bellsoft strategy end-to-end against a
// real BELL-* fixture.
//
//   - BELL-CVE-2025-59375: the CVE lives in `upstream` (aliases/related are
//     empty), and every affected package is an Alpaquita / BellSoft Hardened
//     Containers apk package described by an ECOSYSTEM range with apk-flavored
//     versions (e.g. 2.7.2-r0). Locks in that CVEs/Aliases come from
//     vuln.Upstream, that constraints are emitted in apk format, and that each
//     affected entry carries the OperatingSystem derived from its ecosystem
//     (numeric release → MajorVersion, "stream" → LabelVersion).
func TestBellsoftTransform(t *testing.T) {
	tests := []transformCase{
		{
			name:        "expat CVE-2025-59375",
			fixturePath: "testdata/BELL-CVE-2025-59375.json",
			want: []transformers.RelatedEntries{{
				VulnerabilityHandle: &db.VulnerabilityHandle{
					Name:          "BELL-CVE-2025-59375",
					Status:        db.VulnerabilityActive,
					ProviderID:    "osv",
					Provider:      expectedProvider(),
					ModifiedDate:  timeRef(time.Date(2025, time.December, 23, 13, 5, 51, 859654000, time.UTC)),
					PublishedDate: timeRef(time.Date(2025, time.September, 15, 11, 56, 23, 866967000, time.UTC)),
					BlobValue: &db.VulnerabilityBlob{
						ID: "BELL-CVE-2025-59375",
						References: []db.Reference{{
							URL:  "https://docs.bell-sw.com/security/cves/CVE-2025-59375",
							Tags: []string{"ADVISORY"},
						}, {
							URL:  "https://docs.bell-sw.com/security/advisories/BELL-SA-2025-13",
							Tags: []string{"ADVISORY"},
						}},
						Aliases: []string{"CVE-2025-59375"},
						Severities: []db.Severity{{
							Scheme: db.SeveritySchemeCVSS,
							Value: db.CVSSSeverity{
								Vector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
								Version: "3.1",
							},
						}},
					},
				},
				// ByAffectedPackage sorts on package + ranges (not OS), so the six
				// entries group by constraint: stream (2.4.9), 23 (2.5.0), 25 (2.7.1).
				Related: affectedPkgSlice(
					bellsoftAffected(bellsoftOS("alpaquita", "", "stream"), ">=2.4.9-r0,<2.7.2-r0"),
					bellsoftAffected(bellsoftOS("bellsoft-hardened-containers", "", "stream"), ">=2.4.9-r0,<2.7.2-r0"),
					bellsoftAffected(bellsoftOS("alpaquita", "23", ""), ">=2.5.0-r0,<2.7.2-r0"),
					bellsoftAffected(bellsoftOS("bellsoft-hardened-containers", "23", ""), ">=2.5.0-r0,<2.7.2-r0"),
					bellsoftAffected(bellsoftOS("alpaquita", "25", ""), ">=2.7.1-r0,<2.7.2-r0"),
					bellsoftAffected(bellsoftOS("bellsoft-hardened-containers", "25", ""), ">=2.7.1-r0,<2.7.2-r0"),
				),
			}},
		},
	}
	runTransformCases(t, tests)
}

func bellsoftOS(name, major, label string) *db.OperatingSystem {
	return &db.OperatingSystem{Name: name, MajorVersion: major, LabelVersion: label}
}

func bellsoftAffected(os *db.OperatingSystem, constraint string) db.AffectedPackageHandle {
	return db.AffectedPackageHandle{
		Package: &db.Package{
			Name:      "expat",
			Ecosystem: "apk",
		},
		OperatingSystem: os,
		BlobValue: &db.PackageBlob{
			CVEs: []string{"CVE-2025-59375"},
			Ranges: []db.Range{{
				Version: db.Version{
					Type:       "apk",
					Constraint: constraint,
				},
				Fix: &db.Fix{
					Version: "2.7.2-r0",
					State:   db.FixedStatus,
				},
			}},
		},
	}
}

// TestBellsoftRangeConversion exercises the bellsoft-flavored range-conversion
// path: bellsoftRangeType maps OSV's ECOSYSTEM/SEMVER to "apk", then
// getGrypeRangesFromRange builds the affected version constraints. The apk
// generic-constraint parser rejects space-separated conjunctions, so multi-
// window ranges must be comma-delimited.
func TestBellsoftRangeConversion(t *testing.T) {
	tests := []struct {
		name string
		rnge osvmodel.Range
		want []db.Range
	}{
		{
			name: "ecosystem introduced -> fixed apk range is comma-delimited",
			rnge: osvmodel.Range{
				Type: osvmodel.RangeEcosystem,
				Events: []osvmodel.Event{
					{Introduced: "2.5.0-r0"},
					{Fixed: "2.7.2-r0"},
				},
			},
			want: []db.Range{{
				Version: db.Version{Type: "apk", Constraint: ">=2.5.0-r0,<2.7.2-r0"},
				Fix:     &db.Fix{Version: "2.7.2-r0", State: db.FixedStatus},
			}},
		},
		{
			name: "semver introduced -> fixed apk range",
			rnge: osvmodel.Range{
				Type: osvmodel.RangeSemVer,
				Events: []osvmodel.Event{
					{Introduced: "1.0.0"},
					{Fixed: "1.2.0"},
				},
			},
			want: []db.Range{{
				Version: db.Version{Type: "apk", Constraint: ">=1.0.0,<1.2.0"},
				Fix:     &db.Fix{Version: "1.2.0", State: db.FixedStatus},
			}},
		},
		{
			name: "introduced with no upper bound stays open-ended",
			rnge: osvmodel.Range{
				Type: osvmodel.RangeEcosystem,
				Events: []osvmodel.Event{
					{Introduced: "2.4.9-r0"},
				},
			},
			want: []db.Range{{
				Version: db.Version{Type: "apk", Constraint: ">=2.4.9-r0"},
			}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getGrypeRangesFromRange(tt.rnge, bellsoftRangeType(tt.rnge.Type))
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}
