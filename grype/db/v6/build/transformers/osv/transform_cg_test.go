package osv

import (
	"reflect"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/db/internal/provider/unmarshal"
	"github.com/anchore/grype/grype/db/internal/provider/unmarshal/osvmodel"
	db "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/build/transformers"
)

// chainguardOS / wolfiOS are small constructors used by TestChainguardTransform
// to keep expected AffectedPackageHandle entries readable. Each ecosystem gets
// its own OSV OS row (Name == ReleaseID == lowercased ecosystem + "-osv") with a shared
// LabelVersion of "rolling" — both distros are rolling-release with no version
// number to attach, so the OS-specifier-override layer matches on Name/ReleaseID
// alone.
func chainguardOS() *db.OperatingSystem {
	return &db.OperatingSystem{
		Name:         "chainguard-osv",
		ReleaseID:    "chainguard-osv",
		LabelVersion: "rolling",
	}
}

func wolfiOS() *db.OperatingSystem {
	return &db.OperatingSystem{
		Name:         "wolfi-osv",
		ReleaseID:    "wolfi-osv",
		LabelVersion: "rolling",
	}
}

// TestChainguardStrategy_Matches covers ID-prefix dispatch. Only CGA-* records
// route to this strategy; everything else (other distro advisories, plain CVEs,
// GHSAs, the prior CG- prefix) must miss so dispatch falls through to the
// correct strategy or the "no strategy matched" log path.
func TestChainguardStrategy_Matches(t *testing.T) {
	tests := []struct {
		id   string
		want bool
	}{
		{"CGA-xcpc-gm23-prj9", true},
		{"CGA-22hv-wp9q-4779", true},
		{"CGA-fhcx-m79g-26vp", true},
		{"ALSA-2025:7467", false},
		{"BIT-apache-2020-11984", false},
		{"ROOT-OS-ALPINE-318-CVE-2000-0548", false},
		{"CVE-2025-68121", false},
		{"GHSA-qgxr-kfqx-v5q9", false},
		{"CG-foo", false}, // legacy prefix without the trailing "A" must not match
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			if got := (chainguardStrategy{}).Matches(tt.id); got != tt.want {
				t.Errorf("Matches(%q) = %v, want %v", tt.id, got, tt.want)
			}
		})
	}
}

// TestChainguardTransform exercises the cg strategy end-to-end against real
// CGA fixtures pulled from the vunnel test corpus. Each fixture targets a
// distinct shape:
//
//   - CGA-xcpc-gm23-prj9: multi-ecosystem (Chainguard + Wolfi) with per-row
//     arch qualifiers, a "fixed":"0" degenerate range (syncthing-compat —
//     advisory marks the package as not-applicable-to-this-ecosystem), and
//     a mixed ADVISORY + FIX reference set.
//   - CGA-22hv-wp9q-4779: cleanest shape — single ADVISORY reference,
//     standard ECOSYSTEM ranges across Chainguard + Wolfi. Locks in the
//     baseline behavior without the awkward edge cases.
//   - CGA-224q-ccj5-2p53: multiple ADVISORY references AND one affected
//     package whose PURL has no `arch=` qualifier (haproxy-3.1) — exercises
//     the nil-Qualifiers branch through the integration path. Without this
//     case the unit-level TestCgGetQualifiers would be the only signal that
//     missing-arch is handled correctly end-to-end.
//
// Sort order is by package name, then ecosystem, then version constraint
// (per internal.ByAffectedPackage). Expected outputs below are written in
// sorted order so the diff fails loudly if the sort drifts.
func TestChainguardTransform(t *testing.T) {
	tests := []transformCase{
		{
			name:        "multi-ecosystem with arch qualifiers, upstream aliases, and a fixed=0 degenerate range",
			fixturePath: "testdata/CGA-xcpc-gm23-prj9.json",
			want: []transformers.RelatedEntries{{
				MergeByName: true,
				VulnerabilityHandle: &db.VulnerabilityHandle{
					Name:          "CVE-2025-68121",
					Status:        db.VulnerabilityActive,
					ProviderID:    "osv",
					Provider:      expectedProvider(),
					ModifiedDate:  timeRef(time.Date(2026, time.February, 20, 0, 0, 0, 0, time.UTC)),
					PublishedDate: timeRef(time.Date(2026, time.February, 20, 0, 0, 0, 0, time.UTC)),
					BlobValue: &db.VulnerabilityBlob{
						ID: "CVE-2025-68121",
						// Description is empty: the fixture uses `summary`, not `details`.
						// The cg strategy reads vuln.Details so this round-trips to "".
						Description: "",
						References: []db.Reference{
							{
								URL:  "https://nvd.nist.gov/vuln/detail/CVE-2025-68121",
								Tags: []string{"ADVISORY"},
							},
							{
								URL:  "https://github.com/netty/netty/pull/12345",
								Tags: []string{"FIX"},
							},
						},
						Severities: []db.Severity{{
							Scheme: db.SeveritySchemeCVSS,
							Value: db.CVSSSeverity{
								Vector:  "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
								Version: "3.1",
							},
						}},
					},
				},
				Related: affectedPkgSlice(
					db.AffectedPackageHandle{
						OperatingSystem: chainguardOS(),
						Package: &db.Package{
							Name:      "syncthing",
							Ecosystem: "apk",
						},
						BlobValue: &db.PackageBlob{
							CVEs: []string{"CVE-2025-68121", "GHSA-qgxr-kfqx-v5q9", "CGA-xcpc-gm23-prj9"},
							Qualifiers: &db.PackageQualifiers{
								Architecture: stringRef("x86_64"),
							},
							Ranges: []db.Range{{
								Version: db.Version{
									Type:       "apk",
									Constraint: "< 2.0.14-r1",
								},
								Fix: &db.Fix{
									Version: "2.0.14-r1",
									State:   db.FixedStatus,
								},
							}},
						},
					},
					db.AffectedPackageHandle{
						OperatingSystem: wolfiOS(),
						Package: &db.Package{
							Name:      "syncthing",
							Ecosystem: "apk",
						},
						BlobValue: &db.PackageBlob{
							CVEs: []string{"CVE-2025-68121", "GHSA-qgxr-kfqx-v5q9", "CGA-xcpc-gm23-prj9"},
							Qualifiers: &db.PackageQualifiers{
								Architecture: stringRef("aarch64"),
							},
							Ranges: []db.Range{{
								Version: db.Version{
									Type:       "apk",
									Constraint: "< 2.0.14-r1",
								},
								Fix: &db.Fix{
									Version: "2.0.14-r1",
									State:   db.FixedStatus,
								},
							}},
						},
					},
					db.AffectedPackageHandle{
						OperatingSystem: chainguardOS(),
						Package: &db.Package{
							Name:      "syncthing-compat",
							Ecosystem: "apk",
						},
						BlobValue: &db.PackageBlob{
							CVEs: []string{"CVE-2025-68121", "GHSA-qgxr-kfqx-v5q9", "CGA-xcpc-gm23-prj9"},
							Qualifiers: &db.PackageQualifiers{
								Architecture: stringRef("x86_64"),
							},
							Ranges: []db.Range{{
								Version: db.Version{
									Type:       "apk",
									Constraint: "< 0",
								},
								Fix: &db.Fix{
									Version: "0",
									State:   db.FixedStatus,
								},
							}},
						},
					},
					db.AffectedPackageHandle{
						OperatingSystem: chainguardOS(),
						Package: &db.Package{
							Name:      "syncthing-fips",
							Ecosystem: "apk",
						},
						BlobValue: &db.PackageBlob{
							CVEs: []string{"CVE-2025-68121", "GHSA-qgxr-kfqx-v5q9", "CGA-xcpc-gm23-prj9"},
							Qualifiers: &db.PackageQualifiers{
								Architecture: stringRef("x86_64"),
							},
							Ranges: []db.Range{{
								Version: db.Version{
									Type:       "apk",
									Constraint: "< 2.0.14-r1",
								},
								Fix: &db.Fix{
									Version: "2.0.14-r1",
									State:   db.FixedStatus,
								},
							}},
						},
					},
				),
			}},
		},
		{
			name:        "single ADVISORY ref with multi-ecosystem packages",
			fixturePath: "testdata/CGA-22hv-wp9q-4779.json",
			want: []transformers.RelatedEntries{{
				MergeByName: true,
				VulnerabilityHandle: &db.VulnerabilityHandle{
					Name:          "CVE-2026-24398",
					Status:        db.VulnerabilityActive,
					ProviderID:    "osv",
					Provider:      expectedProvider(),
					ModifiedDate:  timeRef(time.Date(2026, time.February, 24, 13, 7, 8, 0, time.UTC)),
					PublishedDate: timeRef(time.Date(2026, time.February, 24, 13, 7, 8, 0, time.UTC)),
					BlobValue: &db.VulnerabilityBlob{
						ID:          "CVE-2026-24398",
						Description: "",
						References: []db.Reference{
							{
								URL:  "https://nvd.nist.gov/vuln/detail/CVE-2026-24398",
								Tags: []string{"ADVISORY"},
							},
						},
						Severities: []db.Severity{{
							Scheme: db.SeveritySchemeCVSS,
							Value: db.CVSSSeverity{
								Vector:  "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
								Version: "3.1",
							},
						}},
					},
				},
				Related: affectedPkgSlice(
					db.AffectedPackageHandle{
						OperatingSystem: chainguardOS(),
						Package: &db.Package{
							Name:      "langfuse-3-worker",
							Ecosystem: "apk",
						},
						BlobValue: &db.PackageBlob{
							CVEs: []string{"CVE-2026-24398", "GHSA-r354-f388-2fhh", "CGA-22hv-wp9q-4779"},
							Qualifiers: &db.PackageQualifiers{
								Architecture: stringRef("x86_64"),
							},
							Ranges: []db.Range{{
								Version: db.Version{
									Type:       "apk",
									Constraint: "< 3.153.0-r0",
								},
								Fix: &db.Fix{
									Version: "3.153.0-r0",
									State:   db.FixedStatus,
								},
							}},
						},
					},
					db.AffectedPackageHandle{
						OperatingSystem: wolfiOS(),
						Package: &db.Package{
							Name:      "langfuse-3-worker",
							Ecosystem: "apk",
						},
						BlobValue: &db.PackageBlob{
							CVEs: []string{"CVE-2026-24398", "GHSA-r354-f388-2fhh", "CGA-22hv-wp9q-4779"},
							Qualifiers: &db.PackageQualifiers{
								Architecture: stringRef("aarch64"),
							},
							Ranges: []db.Range{{
								Version: db.Version{
									Type:       "apk",
									Constraint: "< 3.153.0-r0",
								},
								Fix: &db.Fix{
									Version: "3.153.0-r0",
									State:   db.FixedStatus,
								},
							}},
						},
					},
					db.AffectedPackageHandle{
						OperatingSystem: chainguardOS(),
						Package: &db.Package{
							Name:      "langfuse-fips-3-worker",
							Ecosystem: "apk",
						},
						BlobValue: &db.PackageBlob{
							CVEs: []string{"CVE-2026-24398", "GHSA-r354-f388-2fhh", "CGA-22hv-wp9q-4779"},
							Qualifiers: &db.PackageQualifiers{
								Architecture: stringRef("x86_64"),
							},
							Ranges: []db.Range{{
								Version: db.Version{
									Type:       "apk",
									Constraint: "< 3.152.0-r0",
								},
								Fix: &db.Fix{
									Version: "3.152.0-r0",
									State:   db.FixedStatus,
								},
							}},
						},
					},
				),
			}},
		},
		{
			name:        "multiple ADVISORY refs and a PURL with no arch qualifier",
			fixturePath: "testdata/CGA-224q-ccj5-2p53.json",
			want: []transformers.RelatedEntries{{
				MergeByName: true,
				VulnerabilityHandle: &db.VulnerabilityHandle{
					Name:          "CVE-2025-32464",
					Status:        db.VulnerabilityActive,
					ProviderID:    "osv",
					Provider:      expectedProvider(),
					ModifiedDate:  timeRef(time.Date(2026, time.January, 7, 0, 0, 0, 0, time.UTC)),
					PublishedDate: timeRef(time.Date(2026, time.January, 7, 0, 0, 0, 0, time.UTC)),
					BlobValue: &db.VulnerabilityBlob{
						ID:          "CVE-2025-32464",
						Description: "",
						References: []db.Reference{
							{
								URL:  "https://nvd.nist.gov/vuln/detail/CVE-2025-32464",
								Tags: []string{"ADVISORY"},
							},
							{
								URL:  "https://github.com/advisories/GHSA-frg5-h47x-75j9",
								Tags: []string{"ADVISORY"},
							},
						},
						Severities: []db.Severity{{
							Scheme: db.SeveritySchemeCVSS,
							Value: db.CVSSSeverity{
								Vector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
								Version: "3.1",
							},
						}},
					},
				},
				Related: affectedPkgSlice(
					db.AffectedPackageHandle{
						OperatingSystem: chainguardOS(),
						Package: &db.Package{
							Name:      "haproxy-2.2",
							Ecosystem: "apk",
						},
						BlobValue: &db.PackageBlob{
							CVEs: []string{"CVE-2025-32464", "GHSA-frg5-h47x-75j9", "CGA-224q-ccj5-2p53"},
							Qualifiers: &db.PackageQualifiers{
								Architecture: stringRef("x86_64"),
							},
							Ranges: []db.Range{{
								Version: db.Version{
									Type:       "apk",
									Constraint: "< 2.2.34-r0",
								},
								Fix: &db.Fix{
									Version: "2.2.34-r0",
									State:   db.FixedStatus,
								},
							}},
						},
					},
					db.AffectedPackageHandle{
						OperatingSystem: chainguardOS(),
						Package: &db.Package{
							Name:      "haproxy-2.8",
							Ecosystem: "apk",
						},
						BlobValue: &db.PackageBlob{
							CVEs: []string{"CVE-2025-32464", "GHSA-frg5-h47x-75j9", "CGA-224q-ccj5-2p53"},
							Qualifiers: &db.PackageQualifiers{
								Architecture: stringRef("x86_64"),
							},
							Ranges: []db.Range{{
								Version: db.Version{
									Type:       "apk",
									Constraint: "< 2.8.18-r0",
								},
								Fix: &db.Fix{
									Version: "2.8.18-r0",
									State:   db.FixedStatus,
								},
							}},
						},
					},
					db.AffectedPackageHandle{
						OperatingSystem: wolfiOS(),
						Package: &db.Package{
							Name:      "haproxy-3.0",
							Ecosystem: "apk",
						},
						BlobValue: &db.PackageBlob{
							CVEs: []string{"CVE-2025-32464", "GHSA-frg5-h47x-75j9", "CGA-224q-ccj5-2p53"},
							Qualifiers: &db.PackageQualifiers{
								Architecture: stringRef("aarch64"),
							},
							Ranges: []db.Range{{
								Version: db.Version{
									Type:       "apk",
									Constraint: "< 3.0.10-r0",
								},
								Fix: &db.Fix{
									Version: "3.0.10-r0",
									State:   db.FixedStatus,
								},
							}},
						},
					},
					db.AffectedPackageHandle{
						OperatingSystem: wolfiOS(),
						Package: &db.Package{
							Name:      "haproxy-3.1",
							Ecosystem: "apk",
						},
						BlobValue: &db.PackageBlob{
							CVEs: []string{"CVE-2025-32464", "GHSA-frg5-h47x-75j9", "CGA-224q-ccj5-2p53"},
							// haproxy-3.1's PURL omits `?arch=...`, so the integration path
							// must produce nil Qualifiers here. Without this case the only
							// signal that "missing arch" round-trips correctly is the unit
							// TestCgGetQualifiers test.
							Qualifiers: nil,
							Ranges: []db.Range{{
								Version: db.Version{
									Type:       "apk",
									Constraint: "< 3.1.7-r0",
								},
								Fix: &db.Fix{
									Version: "3.1.7-r0",
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

// TestChainguardTransform_Identifiers covers where a record's identifiers land once the CGA
// stops being the name. Name and BlobValue.ID must move together, since blobs dedupe by
// digest and a stale CGA in the blob would defeat the merge. The CGA itself is kept on the
// package row, the granularity it actually describes.
func TestChainguardTransform_Identifiers(t *testing.T) {
	vuln := unmarshal.OSVVulnerability{
		Upstream: []string{"CVE-2026-99999", "GHSA-aaaa-bbbb-cccc"},
	}
	vuln.ID = "CGA-abcd-efgh-ijkl"
	vuln.Aliases = []string{"ALEX-1"} // pre-existing aliases must be preserved
	vuln.Related = []string{"CVE-2026-77777"}
	vuln.Affected = []osvmodel.Affected{
		{
			Package: osvmodel.Package{
				Ecosystem: "apk",
				Name:      "demo",
				Purl:      "pkg:apk/chainguard/demo?arch=x86_64",
			},
			Ranges: []osvmodel.Range{
				{
					Type: osvmodel.RangeEcosystem,
					Events: []osvmodel.Event{
						{Introduced: "0"},
						{Fixed: "1.0.0-r1"},
					},
				},
			},
		},
	}

	require.True(t, chainguardStrategy{}.Matches(vuln.ID))

	entries, err := Transform(vuln, inputProviderState())
	require.NoError(t, err)
	require.Len(t, entries, 1)

	rel, ok := entries[0].Data.(transformers.RelatedEntries)
	require.True(t, ok)
	require.True(t, rel.MergeByName,
		"cg entries must be marked for merging; without it every CGA stays its own handle")

	require.Equal(t, "CVE-2026-99999", rel.VulnerabilityHandle.Name,
		"the strict CVE in upstream wins the name over the CGA")
	require.Equal(t, "CVE-2026-99999", rel.VulnerabilityHandle.BlobValue.ID,
		"BlobValue.ID must track Name or blob digests stay per-record and nothing dedupes")

	require.Nil(t, rel.VulnerabilityHandle.BlobValue.Aliases,
		"the handle is shared by every CGA for the CVE, so a per-CGA id in its aliases would leak to other packages")

	require.Len(t, rel.Related, 1)
	aph, ok := rel.Related[0].(db.AffectedPackageHandle)
	require.True(t, ok, "cg emits AffectedPackageHandle (not Unaffected) — CGA records describe vulnerable version ranges, not NAKs")
	require.Equal(t,
		[]string{"ALEX-1", "CVE-2026-99999", "GHSA-aaaa-bbbb-cccc", "CGA-abcd-efgh-ijkl"},
		aph.BlobValue.CVEs,
		"PackageBlob.CVEs is aliases + upstream + the CGA in feed order; `related` means a different vulnerability, so it stays out")
}

// The tier order decides whether ~1M records collapse onto ~11.7k names, so each tier gets a
// case, as does every way the feed is known to break it.
func TestCgNames(t *testing.T) {
	tests := []struct {
		name     string
		id       string
		aliases  []string
		upstream []string
		want     []string
	}{
		{
			name:     "single CVE wins",
			id:       "CGA-abcd-efgh-ijkl",
			upstream: []string{"CVE-2026-99999", "GHSA-aaaa-bbbb-cccc", "GO-2026-1234"},
			want:     []string{"CVE-2026-99999"},
		},
		{
			name:     "two CVEs fan out, in feed order",
			id:       "CGA-abcd-efgh-ijkl",
			upstream: []string{"CVE-2026-99999", "CVE-2026-11111"},
			want:     []string{"CVE-2026-99999", "CVE-2026-11111"},
		},
		{
			// smallest rather than first, so CGAs listing the same GHSAs in another order share a handle
			name:     "no CVE falls to the smallest GHSA only",
			id:       "CGA-abcd-efgh-ijkl",
			upstream: []string{"GHSA-dddd-eeee-ffff", "GHSA-aaaa-bbbb-cccc", "GO-2026-1234"},
			want:     []string{"GHSA-aaaa-bbbb-cccc"},
		},
		{
			name:     "no CVE or GHSA falls to the smallest GO only",
			id:       "CGA-abcd-efgh-ijkl",
			upstream: []string{"GO-2026-5678", "GO-2026-1234"},
			want:     []string{"GO-2026-1234"},
		},
		{
			// naming reads upstream only
			name:     "a CVE only in aliases does not become the name",
			id:       "CGA-abcd-efgh-ijkl",
			aliases:  []string{"CVE-2026-99999"},
			upstream: nil,
			want:     []string{"CGA-abcd-efgh-ijkl"},
		},
		{
			name:     "empty upstream keeps the CGA",
			id:       "CGA-abcd-efgh-ijkl",
			upstream: nil,
			want:     []string{"CGA-abcd-efgh-ijkl"},
		},
		{
			// observed in the feed as "cve36", "cve31", "cve34"
			name:     "malformed CVE-ish id does not become a name",
			id:       "CGA-2fhp-4c5v-pg3h",
			upstream: []string{"cve36"},
			want:     []string{"CGA-2fhp-4c5v-pg3h"},
		},
		{
			// observed in the feed: U+2011 non-breaking hyphens
			name:     "CVE with non-breaking hyphens is rejected",
			id:       "CGA-pg93-fqx7-3jgq",
			upstream: []string{"CVE\u20112026\u201155200"},
			want:     []string{"CGA-pg93-fqx7-3jgq"},
		},
		{
			// observed in the feed: a record whose upstream points at another CGA
			name:     "CGA self-reference in upstream keeps the record's own CGA",
			id:       "CGA-3p77-w9cj-m77w",
			upstream: []string{"CGA-q7jg-8hpq-v668"},
			want:     []string{"CGA-3p77-w9cj-m77w"},
		},
		{
			name:     "short CVE sequence number is rejected",
			id:       "CGA-abcd-efgh-ijkl",
			upstream: []string{"CVE-2026-999"},
			want:     []string{"CGA-abcd-efgh-ijkl"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vuln := unmarshal.OSVVulnerability{Upstream: tt.upstream}
			vuln.ID = tt.id
			vuln.Aliases = tt.aliases
			require.Equal(t, tt.want, cgNames(vuln))
		})
	}
}

// Two entries, not one: NewEntries keeps only the last VulnerabilityHandle it is given, so
// emitting both in one call would silently drop a vulnerability.
func TestChainguardTransform_FansOutOnMultipleCVEs(t *testing.T) {
	vuln := unmarshal.OSVVulnerability{
		Upstream: []string{"CVE-2026-99999", "CVE-2026-11111"},
	}
	vuln.ID = "CGA-abcd-efgh-ijkl"
	vuln.Affected = []osvmodel.Affected{
		{
			Package: osvmodel.Package{Ecosystem: "Chainguard", Name: "demo", Purl: "pkg:apk/chainguard/demo?arch=x86_64"},
			Ranges: []osvmodel.Range{{
				Type:   osvmodel.RangeEcosystem,
				Events: []osvmodel.Event{{Introduced: "0"}, {Fixed: "1.0.0-r1"}},
			}},
		},
	}

	entries, err := Transform(vuln, inputProviderState())
	require.NoError(t, err)
	require.Len(t, entries, 2, "each CVE must get its own entry")

	var names []string
	for _, e := range entries {
		rel := e.Data.(transformers.RelatedEntries)
		names = append(names, rel.VulnerabilityHandle.Name)
		require.Equal(t, rel.VulnerabilityHandle.Name, rel.VulnerabilityHandle.BlobValue.ID)
		require.Len(t, rel.Related, 1, "both entries carry the record's package rows")
	}
	require.Equal(t, []string{"CVE-2026-99999", "CVE-2026-11111"}, names)

	// the sibling CVE is a fact about this CGA, so it rides on the package rows rather than in
	// handles other CGAs will share
	for _, e := range entries {
		rel := e.Data.(transformers.RelatedEntries)
		require.Nil(t, rel.VulnerabilityHandle.BlobValue.Aliases)
		aph := rel.Related[0].(db.AffectedPackageHandle)
		require.Equal(t, []string{"CVE-2026-99999", "CVE-2026-11111", "CGA-abcd-efgh-ijkl"}, aph.BlobValue.CVEs)
	}
}

// Reference IDs stay empty: stamping the CGA mislabeled third-party URLs (mostly Red Hat
// errata) and re-injected per-record entropy into the blob, defeating the merge.
func TestCgReferences(t *testing.T) {
	vuln := unmarshal.OSVVulnerability{}
	vuln.ID = "CGA-abcd-efgh-ijkl"
	vuln.References = []osvmodel.Reference{
		{Type: osvmodel.ReferenceAdvisory, URL: "https://access.redhat.com/errata/RHSA-2026:10125"},
		{Type: osvmodel.ReferenceType("FIX"), URL: "https://github.com/netty/netty/pull/12345"},
	}

	require.Equal(t, []db.Reference{
		{URL: "https://access.redhat.com/errata/RHSA-2026:10125", Tags: []string{"ADVISORY"}},
		{URL: "https://github.com/netty/netty/pull/12345", Tags: []string{"FIX"}},
	}, cgReferences(vuln))
}

// TestCgRangeType covers the OSV range-type → grype version-format mapping for
// CG records. CGA records observed in vunnel exclusively use ECOSYSTEM ranges
// (which describe APK versions), but the fallback to defaultRangeType keeps
// unexpected shapes visible rather than silently becoming "unknown".
func TestCgRangeType(t *testing.T) {
	tests := []struct {
		rangeType osvmodel.RangeType
		want      string
	}{
		{osvmodel.RangeEcosystem, "apk"},
		{osvmodel.RangeSemVer, "semver"},
		{osvmodel.RangeGit, "git"},
		{osvmodel.RangeType("UNRECOGNIZED"), "unknown"},
	}
	for _, tt := range tests {
		t.Run(string(tt.rangeType), func(t *testing.T) {
			if got := cgRangeType(tt.rangeType); got != tt.want {
				t.Errorf("cgRangeType(%q) = %q, want %q", tt.rangeType, got, tt.want)
			}
		})
	}
}

// TestCgGetQualifiers covers PURL qualifier extraction. CG advisories carry
// per-package arch in the PURL `?arch=<value>` qualifier; nothing else on the
// PURL is currently surfaced into PackageQualifiers. Cases below pin down both
// the happy path and the defensive "no qualifiers emitted" outcomes.
func TestCgGetQualifiers(t *testing.T) {
	archX86 := "x86_64"
	archArm := "aarch64"

	tests := []struct {
		name     string
		affected osvmodel.Affected
		want     *db.PackageQualifiers
	}{
		{
			name: "arch x86_64 extracted",
			affected: osvmodel.Affected{
				Package: osvmodel.Package{Purl: "pkg:apk/chainguard/syncthing?arch=x86_64"},
			},
			want: &db.PackageQualifiers{Architecture: &archX86},
		},
		{
			name: "arch aarch64 extracted",
			affected: osvmodel.Affected{
				Package: osvmodel.Package{Purl: "pkg:apk/wolfi/syncthing?arch=aarch64"},
			},
			want: &db.PackageQualifiers{Architecture: &archArm},
		},
		{
			name: "arch alongside other qualifiers — only arch is surfaced",
			affected: osvmodel.Affected{
				Package: osvmodel.Package{Purl: "pkg:apk/chainguard/demo?arch=x86_64&distro=chainguard"},
			},
			want: &db.PackageQualifiers{Architecture: &archX86},
		},
		{
			name: "PURL without arch qualifier returns nil",
			affected: osvmodel.Affected{
				Package: osvmodel.Package{Purl: "pkg:apk/chainguard/demo"},
			},
			want: nil,
		},
		{
			name: "empty PURL returns nil",
			affected: osvmodel.Affected{
				Package: osvmodel.Package{Purl: ""},
			},
			want: nil,
		},
		{
			name: "malformed PURL returns nil (does not panic)",
			affected: osvmodel.Affected{
				Package: osvmodel.Package{Purl: "not-a-purl"},
			},
			want: nil,
		},
		{
			name: "arch qualifier present but empty returns nil",
			affected: osvmodel.Affected{
				Package: osvmodel.Package{Purl: "pkg:apk/chainguard/demo?arch="},
			},
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cgGetQualifiers(tt.affected)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("cgGetQualifiers() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// TestCgOperatingSystem covers the ecosystem → OperatingSystem mapping. CGA
// records carry per-affected-row ecosystem strings ("Chainguard" / "Wolfi");
// each maps to its own OSV OS row (Name == ReleaseID == lowercased ecosystem
// plus "-osv", so released clients, which look the distro up by name or
// release ID, never see it) with
// a shared LabelVersion of "rolling" — both distros are rolling-release. Any
// other ecosystem (lowercased variants, unrecognized strings, empty) must
// return nil so the caller leaves OperatingSystem unset on the
// AffectedPackageHandle.
func TestCgOperatingSystem(t *testing.T) {
	tests := []struct {
		name      string
		ecosystem string
		want      *db.OperatingSystem
	}{
		{
			name:      "Chainguard maps to its OSV OS with rolling label",
			ecosystem: "Chainguard",
			want: &db.OperatingSystem{
				Name:         "chainguard-osv",
				ReleaseID:    "chainguard-osv",
				LabelVersion: "rolling",
			},
		},
		{
			name:      "Wolfi maps to its OSV OS with rolling label",
			ecosystem: "Wolfi",
			want: &db.OperatingSystem{
				Name:         "wolfi-osv",
				ReleaseID:    "wolfi-osv",
				LabelVersion: "rolling",
			},
		},
		{
			name:      "unrelated apk distro returns nil so caller skips OS attribution",
			ecosystem: "Alpine",
			want:      nil,
		},
		{
			name:      "empty ecosystem returns nil",
			ecosystem: "",
			want:      nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cgOperatingSystem(tt.ecosystem)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("cgOperatingSystem(%q) mismatch (-want +got):\n%s", tt.ecosystem, diff)
			}
		})
	}
}

// cgAffectedWithStatus builds an affected entry with the given verdicts and optional fix.
func cgAffectedWithStatus(fixedVersion string, statuses ...string) osvmodel.Affected {
	var components []any
	for _, s := range statuses {
		components = append(components, map[string]any{"latest_event_status": s})
	}
	a := osvmodel.Affected{
		Package:           osvmodel.Package{Ecosystem: "Chainguard", Name: "demo", Purl: "pkg:apk/chainguard/demo?arch=x86_64"},
		EcosystemSpecific: map[string]any{"components": components},
	}
	events := []osvmodel.Event{{Introduced: "0"}}
	if fixedVersion != "" {
		events = append(events, osvmodel.Event{Fixed: fixedVersion})
	}
	a.Ranges = []osvmodel.Range{{Type: osvmodel.RangeEcosystem, Events: events}}
	return a
}

// Chainguard states a verdict on every unfixed advisory and grype renders them all blank, so
// "will never fix" is indistinguishable from "fix pending". Each verdict gets a case.
func TestCgUnfixedFixStatus(t *testing.T) {
	tests := []struct {
		name     string
		statuses []string
		want     db.FixStatus
	}{
		{"fix_not_planned becomes wont-fix", []string{"fix_not_planned"}, db.WontFixStatus},
		{"pending_upstream_fix becomes not-fixed", []string{"pending_upstream_fix"}, db.NotFixedStatus},
		{"true_positive_determination becomes not-fixed", []string{"true_positive_determination"}, db.NotFixedStatus},
		{
			// not-fixed would assert more than Chainguard does
			name: "detection stays unknown", statuses: []string{"detection"}, want: db.UnknownFixStatus,
		},
		{"unrecognized verdict stays unknown", []string{"something_new"}, db.UnknownFixStatus},
		{"no verdict stays unknown", nil, db.UnknownFixStatus},
		{"agreeing components resolve", []string{"fix_not_planned", "fix_not_planned"}, db.WontFixStatus},
		{
			// zero entries in the feed disagree; refuse rather than guess if that changes
			name: "disagreeing components refuse to resolve", statuses: []string{"fix_not_planned", "pending_upstream_fix"}, want: db.UnknownFixStatus,
		},
		{
			// silence is not agreement, whichever side it is on
			name: "an empty verdict beside a real one refuses to resolve", statuses: []string{"fix_not_planned", ""}, want: db.UnknownFixStatus,
		},
		{"a real verdict after an empty one refuses to resolve", []string{"", "fix_not_planned"}, db.UnknownFixStatus},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, cgUnfixedFixStatus(cgAffectedWithStatus("", tt.statuses...)))
		})
	}
}

// A component with no latest_event_status key at all is silent too, so wont-fix (the state users
// most often filter out) must not be inferred from its sibling.
func TestCgUnfixedFixStatus_ComponentWithoutStatusIsNotAgreement(t *testing.T) {
	affected := cgAffectedWithStatus("", "fix_not_planned")
	components := affected.EcosystemSpecific["components"].([]any)
	affected.EcosystemSpecific["components"] = append(components, map[string]any{})

	require.Equal(t, db.UnknownFixStatus, cgUnfixedFixStatus(affected))
}

// The digging walks an untyped map, so it must not panic on anything the feed might hold.
func TestCgLatestEventStatus_MalformedShapes(t *testing.T) {
	cases := map[string]osvmodel.Affected{
		"nil ecosystem_specific":  {},
		"no components key":       {EcosystemSpecific: map[string]any{"other": 1}},
		"components not a list":   {EcosystemSpecific: map[string]any{"components": "nope"}},
		"component not an object": {EcosystemSpecific: map[string]any{"components": []any{"nope"}}},
		"status not a string":     {EcosystemSpecific: map[string]any{"components": []any{map[string]any{"latest_event_status": 7}}}},
		"status empty string":     {EcosystemSpecific: map[string]any{"components": []any{map[string]any{"latest_event_status": ""}}}},
	}
	for name, affected := range cases {
		t.Run(name, func(t *testing.T) {
			require.Equal(t, "", cgLatestEventStatus(affected))
		})
	}
}

// TestCgWithUnfixedState_OnlyWhenThereIsNoFix asserts the synthesized range appears only for
// entries that produced none, so an advisory carrying a real fix is never overwritten.
func TestCgWithUnfixedState_OnlyWhenThereIsNoFix(t *testing.T) {
	t.Run("no ranges gains an inert range carrying the state", func(t *testing.T) {
		got := cgAffectedPackages(cgVulnWith(cgAffectedWithStatus("", "fix_not_planned")), []string{"CVE-2026-1"})
		require.Len(t, got, 1)
		require.Equal(t, []db.Range{{Fix: &db.Fix{State: db.WontFixStatus}}}, got[0].BlobValue.Ranges)

		// the synthesized range must carry no version opinion: getVersionConstraint only
		// reads Type when Constraint is non-empty, so both being zero is what keeps the
		// match behavior identical to emitting no range at all
		require.Equal(t, db.Version{}, got[0].BlobValue.Ranges[0].Version)
		require.Empty(t, got[0].BlobValue.Ranges[0].Fix.Version)
	})

	t.Run("a real fix is left alone", func(t *testing.T) {
		got := cgAffectedPackages(cgVulnWith(cgAffectedWithStatus("1.2.3-r0", "fix_not_planned")), []string{"CVE-2026-1"})
		require.Len(t, got, 1)
		require.Len(t, got[0].BlobValue.Ranges, 1)
		require.Equal(t, "< 1.2.3-r0", got[0].BlobValue.Ranges[0].Version.Constraint)
		require.Equal(t, db.FixedStatus, got[0].BlobValue.Ranges[0].Fix.State)
	})

	t.Run("detection leaves the entry rangeless, exactly as today", func(t *testing.T) {
		got := cgAffectedPackages(cgVulnWith(cgAffectedWithStatus("", "detection")), []string{"CVE-2026-1"})
		require.Len(t, got, 1)
		require.Empty(t, got[0].BlobValue.Ranges)
	})
}

func cgVulnWith(affected ...osvmodel.Affected) unmarshal.OSVVulnerability {
	v := unmarshal.OSVVulnerability{}
	v.ID = "CGA-abcd-efgh-ijkl"
	v.Affected = affected
	return v
}
