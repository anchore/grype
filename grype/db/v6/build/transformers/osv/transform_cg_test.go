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
// its own OS row (Name == ReleaseID == lowercased ecosystem) with a shared
// LabelVersion of "rolling" — both distros are rolling-release with no version
// number to attach, so the OS-specifier-override layer matches on Name/ReleaseID
// alone.
func chainguardOS() *db.OperatingSystem {
	return &db.OperatingSystem{
		Name:         "chainguard",
		ReleaseID:    "chainguard",
		LabelVersion: "rolling",
	}
}

func wolfiOS() *db.OperatingSystem {
	return &db.OperatingSystem{
		Name:         "wolfi",
		ReleaseID:    "wolfi",
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
				VulnerabilityHandle: &db.VulnerabilityHandle{
					Name:          "CGA-xcpc-gm23-prj9",
					Status:        db.VulnerabilityActive,
					ProviderID:    "osv",
					Provider:      expectedProvider(),
					ModifiedDate:  timeRef(time.Date(2026, time.February, 20, 0, 0, 0, 0, time.UTC)),
					PublishedDate: timeRef(time.Date(2026, time.February, 20, 0, 0, 0, 0, time.UTC)),
					BlobValue: &db.VulnerabilityBlob{
						ID: "CGA-xcpc-gm23-prj9",
						// Description is empty: the fixture uses `summary`, not `details`.
						// The cg strategy reads vuln.Details so this round-trips to "".
						Description: "",
						References: []db.Reference{
							{
								ID:   "CGA-xcpc-gm23-prj9",
								URL:  "https://nvd.nist.gov/vuln/detail/CVE-2025-68121",
								Tags: []string{"ADVISORY"},
							},
							{
								URL:  "https://github.com/netty/netty/pull/12345",
								Tags: []string{"FIX"},
							},
						},
						// Aliases are populated solely from the `upstream` field
						// (this fixture has no top-level `aliases`).
						Aliases: []string{"CVE-2025-68121", "GHSA-qgxr-kfqx-v5q9"},
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
							Ecosystem: "Chainguard",
						},
						BlobValue: &db.PackageBlob{
							CVEs: []string{"CVE-2025-68121", "GHSA-qgxr-kfqx-v5q9"},
							Qualifiers: &db.PackageQualifiers{
								Architecture: stringRef("x86_64"),
							},
							Ranges: []db.Range{{
								Version: db.Version{
									Type:       "apk",
									Constraint: "<2.0.14-r1",
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
							Ecosystem: "Wolfi",
						},
						BlobValue: &db.PackageBlob{
							CVEs: []string{"CVE-2025-68121", "GHSA-qgxr-kfqx-v5q9"},
							Qualifiers: &db.PackageQualifiers{
								Architecture: stringRef("aarch64"),
							},
							Ranges: []db.Range{{
								Version: db.Version{
									Type:       "apk",
									Constraint: "<2.0.14-r1",
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
							Ecosystem: "Chainguard",
						},
						BlobValue: &db.PackageBlob{
							CVEs: []string{"CVE-2025-68121", "GHSA-qgxr-kfqx-v5q9"},
							Qualifiers: &db.PackageQualifiers{
								Architecture: stringRef("x86_64"),
							},
							Ranges: []db.Range{{
								Version: db.Version{
									Type:       "apk",
									Constraint: "<0",
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
							Ecosystem: "Chainguard",
						},
						BlobValue: &db.PackageBlob{
							CVEs: []string{"CVE-2025-68121", "GHSA-qgxr-kfqx-v5q9"},
							Qualifiers: &db.PackageQualifiers{
								Architecture: stringRef("x86_64"),
							},
							Ranges: []db.Range{{
								Version: db.Version{
									Type:       "apk",
									Constraint: "<2.0.14-r1",
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
				VulnerabilityHandle: &db.VulnerabilityHandle{
					Name:          "CGA-22hv-wp9q-4779",
					Status:        db.VulnerabilityActive,
					ProviderID:    "osv",
					Provider:      expectedProvider(),
					ModifiedDate:  timeRef(time.Date(2026, time.February, 24, 13, 7, 8, 0, time.UTC)),
					PublishedDate: timeRef(time.Date(2026, time.February, 24, 13, 7, 8, 0, time.UTC)),
					BlobValue: &db.VulnerabilityBlob{
						ID:          "CGA-22hv-wp9q-4779",
						Description: "",
						References: []db.Reference{
							{
								ID:   "CGA-22hv-wp9q-4779",
								URL:  "https://nvd.nist.gov/vuln/detail/CVE-2026-24398",
								Tags: []string{"ADVISORY"},
							},
						},
						Aliases: []string{"CVE-2026-24398", "GHSA-r354-f388-2fhh"},
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
							Ecosystem: "Chainguard",
						},
						BlobValue: &db.PackageBlob{
							CVEs: []string{"CVE-2026-24398", "GHSA-r354-f388-2fhh"},
							Qualifiers: &db.PackageQualifiers{
								Architecture: stringRef("x86_64"),
							},
							Ranges: []db.Range{{
								Version: db.Version{
									Type:       "apk",
									Constraint: "<3.153.0-r0",
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
							Ecosystem: "Wolfi",
						},
						BlobValue: &db.PackageBlob{
							CVEs: []string{"CVE-2026-24398", "GHSA-r354-f388-2fhh"},
							Qualifiers: &db.PackageQualifiers{
								Architecture: stringRef("aarch64"),
							},
							Ranges: []db.Range{{
								Version: db.Version{
									Type:       "apk",
									Constraint: "<3.153.0-r0",
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
							Ecosystem: "Chainguard",
						},
						BlobValue: &db.PackageBlob{
							CVEs: []string{"CVE-2026-24398", "GHSA-r354-f388-2fhh"},
							Qualifiers: &db.PackageQualifiers{
								Architecture: stringRef("x86_64"),
							},
							Ranges: []db.Range{{
								Version: db.Version{
									Type:       "apk",
									Constraint: "<3.152.0-r0",
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
				VulnerabilityHandle: &db.VulnerabilityHandle{
					Name:          "CGA-224q-ccj5-2p53",
					Status:        db.VulnerabilityActive,
					ProviderID:    "osv",
					Provider:      expectedProvider(),
					ModifiedDate:  timeRef(time.Date(2026, time.January, 7, 0, 0, 0, 0, time.UTC)),
					PublishedDate: timeRef(time.Date(2026, time.January, 7, 0, 0, 0, 0, time.UTC)),
					BlobValue: &db.VulnerabilityBlob{
						ID:          "CGA-224q-ccj5-2p53",
						Description: "",
						References: []db.Reference{
							{
								ID:   "CGA-224q-ccj5-2p53",
								URL:  "https://nvd.nist.gov/vuln/detail/CVE-2025-32464",
								Tags: []string{"ADVISORY"},
							},
							{
								ID:   "CGA-224q-ccj5-2p53",
								URL:  "https://github.com/advisories/GHSA-frg5-h47x-75j9",
								Tags: []string{"ADVISORY"},
							},
						},
						Aliases: []string{"CVE-2025-32464", "GHSA-frg5-h47x-75j9"},
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
							Ecosystem: "Chainguard",
						},
						BlobValue: &db.PackageBlob{
							CVEs: []string{"CVE-2025-32464", "GHSA-frg5-h47x-75j9"},
							Qualifiers: &db.PackageQualifiers{
								Architecture: stringRef("x86_64"),
							},
							Ranges: []db.Range{{
								Version: db.Version{
									Type:       "apk",
									Constraint: "<2.2.34-r0",
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
							Ecosystem: "Chainguard",
						},
						BlobValue: &db.PackageBlob{
							CVEs: []string{"CVE-2025-32464", "GHSA-frg5-h47x-75j9"},
							Qualifiers: &db.PackageQualifiers{
								Architecture: stringRef("x86_64"),
							},
							Ranges: []db.Range{{
								Version: db.Version{
									Type:       "apk",
									Constraint: "<2.8.18-r0",
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
							Ecosystem: "Wolfi",
						},
						BlobValue: &db.PackageBlob{
							CVEs: []string{"CVE-2025-32464", "GHSA-frg5-h47x-75j9"},
							Qualifiers: &db.PackageQualifiers{
								Architecture: stringRef("aarch64"),
							},
							Ranges: []db.Range{{
								Version: db.Version{
									Type:       "apk",
									Constraint: "<3.0.10-r0",
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
							Ecosystem: "Wolfi",
						},
						BlobValue: &db.PackageBlob{
							CVEs: []string{"CVE-2025-32464", "GHSA-frg5-h47x-75j9"},
							// haproxy-3.1's PURL omits `?arch=...`, so the integration path
							// must produce nil Qualifiers here. Without this case the only
							// signal that "missing arch" round-trips correctly is the unit
							// TestCgGetQualifiers test.
							Qualifiers: nil,
							Ranges: []db.Range{{
								Version: db.Version{
									Type:       "apk",
									Constraint: "<3.1.7-r0",
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

// TestChainguardTransform_UpstreamToAliases is the focused unit covering the
// `upstream` → aliases augmentation in isolation. The integration case above
// covers the same path through a real fixture; this case lets us assert the
// behavior without dragging in the whole record shape, so a regression in the
// alias-merging line is obvious in test output.
func TestChainguardTransform_UpstreamToAliases(t *testing.T) {
	vuln := unmarshal.OSVVulnerability{
		Upstream: []string{"CVE-2026-99999", "GHSA-aaaa-bbbb-cccc"},
	}
	vuln.ID = "CGA-abcd-efgh-ijkl"
	vuln.Aliases = []string{"ALEX-1"} // pre-existing aliases must be preserved
	vuln.Affected = []osvmodel.Affected{
		{
			Package: osvmodel.Package{
				Ecosystem: "Chainguard",
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

	require.Equal(t,
		[]string{"ALEX-1", "CVE-2026-99999", "GHSA-aaaa-bbbb-cccc"},
		rel.VulnerabilityHandle.BlobValue.Aliases,
		"VulnerabilityBlob.Aliases must be the union of aliases + upstream, in that order")

	require.Len(t, rel.Related, 1)
	aph, ok := rel.Related[0].(db.AffectedPackageHandle)
	require.True(t, ok, "cg emits AffectedPackageHandle (not Unaffected) — CGA records describe vulnerable version ranges, not NAKs")
	require.Equal(t,
		[]string{"ALEX-1", "CVE-2026-99999", "GHSA-aaaa-bbbb-cccc"},
		aph.BlobValue.CVEs,
		"PackageBlob.CVEs must also be the augmented set so downstream consumers see upstream CVEs at the per-package level")
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
// each maps to its own OS row (Name == ReleaseID == lowercased ecosystem) with
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
			name:      "Chainguard maps to lowercase OS with rolling label",
			ecosystem: "Chainguard",
			want: &db.OperatingSystem{
				Name:         "chainguard",
				ReleaseID:    "chainguard",
				LabelVersion: "rolling",
			},
		},
		{
			name:      "Wolfi maps to lowercase OS with rolling label",
			ecosystem: "Wolfi",
			want: &db.OperatingSystem{
				Name:         "wolfi",
				ReleaseID:    "wolfi",
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
