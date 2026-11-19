package osv

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/db/internal/provider/unmarshal"
	"github.com/anchore/grype/grype/db/internal/provider/unmarshal/osvmodel"
	db "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/build/transformers"
	"github.com/anchore/grype/grype/version"
)

// TestOCamlTransform exercises the ocaml strategy end-to-end against real
// OSEC-* records (as written by the vunnel ocamlsec provider, including the
// database_specific.anchore.fixes it patches in).
//
//   - OSEC-2017-01: a single introduced/fixed window in the opam ECOSYSTEM range,
//     plus an affected entry without a package holding only GIT ranges, which is
//     dropped.
func TestOCamlTransform(t *testing.T) {
	tests := []transformCase{
		{
			name:        "OSEC-2017-01",
			fixturePath: "testdata/OSEC-2017-01.json",
			want: []transformers.RelatedEntries{{
				VulnerabilityHandle: &db.VulnerabilityHandle{
					Name:          "OSEC-2017-01",
					Status:        db.VulnerabilityActive,
					ProviderID:    "osv",
					Provider:      expectedProvider(),
					ModifiedDate:  timeRef(time.Date(2025, time.December, 16, 12, 0, 0, 0, time.UTC)),
					PublishedDate: timeRef(time.Date(2017, time.June, 23, 15, 19, 47, 0, time.UTC)),
					BlobValue: &db.VulnerabilityBlob{
						ID:          "OSEC-2017-01",
						Description: "## Description\n\nInsufficient sanitisation in the OCaml compiler versions 4.04.0 and 4.04.1 allows external code to be executed with raised privilege in binaries marked as setuid, by setting the CAML_CPLUGINS, CAML_NATIVE_CPLUGINS, or CAML_BYTE_CPLUGINS environment variable.",
						References: []db.Reference{{
							URL:  "https://github.com/ocaml/ocaml/issues/7557",
							Tags: []string{"REPORT"},
						}},
						Aliases: []string{"CVE-2017-9772"},
						Severities: []db.Severity{{
							Scheme: db.SeveritySchemeCVSS,
							Value: db.CVSSSeverity{
								Vector:  "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
								Version: "3.0",
							},
						}},
					},
				},
				Related: affectedPkgSlice(
					db.AffectedPackageHandle{
						Package: &db.Package{
							Name:      "ocaml",
							Ecosystem: "opam",
						},
						BlobValue: &db.PackageBlob{
							CVEs: []string{"CVE-2017-9772"},
							Ranges: []db.Range{{
								Version: db.Version{
									Type:       "opam",
									Constraint: ">=4.04.0,<4.04.2",
								},
								Fix: &db.Fix{
									Version: "4.04.2",
									State:   db.FixedStatus,
									Detail: &db.FixDetail{
										Available: &db.FixAvailability{
											Date: timeRef(time.Date(2017, time.June, 23, 0, 0, 0, 0, time.UTC)),
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
			// two ECOSYSTEM ranges from the opam constraint {< "4.14.3" | >= "5" & < "5.4.1"}
			name:        "OSEC-2026-01",
			fixturePath: "testdata/OSEC-2026-01.json",
			want: []transformers.RelatedEntries{{
				VulnerabilityHandle: &db.VulnerabilityHandle{
					Name:          "OSEC-2026-01",
					Status:        db.VulnerabilityActive,
					ProviderID:    "osv",
					Provider:      expectedProvider(),
					ModifiedDate:  timeRef(time.Date(2026, time.February, 27, 9, 30, 0, 0, time.UTC)),
					PublishedDate: timeRef(time.Date(2026, time.February, 17, 13, 30, 0, 0, time.UTC)),
					BlobValue: &db.VulnerabilityBlob{
						ID:          "OSEC-2026-01",
						Description: "## Summary\n\nA critical buffer over-read vulnerability in OCaml's Marshal deserialization (runtime/intern.c) enables remote code execution through a multi-phase attack chain. The vulnerability stems from missing bounds validation in the readblock() function, which performs unbounded memcpy() operations using attacker-controlled lengths from malicious Marshal data.\n\nPlease note that Marshal is not type safe, and you have to be careful if you use the deserialization on untrusted input (due to type confusion, and remote code execution by design - you can use Marshal for code).\n\nAffected functions: `Marshal.from_channel`, `Marshal.from_bytes`, `Marshal.from_string`, `Stdlib.input_value`, `Pervasives.input_value` when reading data from an untrusted source.\n\n## Vulnerability Attack Vector\n\nCorrupted or malicious marshaled data that causes undefined behaviour in the runtime system when unmarshaled.\n`input_value` should either fail cleanly or produce a well-formed OCaml object, without corrupting the runtime system.\n\nConsequently, this excludes:\n\n* well-formed marshaled data that produces an OCaml object that is not of the type expected by the OCaml code and causes the Ocaml code to crash or misbehave\n\n* misuses of the OCaml runtime system by the program performing input_value, such as setting `Debugger.function_placeholder` to the wrong function.\n\nThe former issue may be addressed at some point by validating the unmarshaled OCaml value against the expected type, using the functions from module `Obj` and some kind of run-time type description.\n\nThe latter issue is a bug in the program that unmarshals the data.\n\n## Fix\n\n### OCaml runtime\n\nThe OCaml runtime has been hardened with additional bounds checks. An exception is raised on bad input.\n\n### Third party libraries\n\nThird party libraries that want to harden their custom Marshal deserialization code can follow the example fix for bigarrays from the standard library.\nThere are new macros in `custom.h` called `Wsize_custom_data` and `Bsize_custom_data` that return the size in words or bytes of the allocated custom destination block. The deserializer needs to ensure it only writes data within those bounds.\n\nThis only needs to be done if the library defines a custom type in a C binding, and `struct custom_operations`'s `deserialize` field is not set to `NULL` or `custom_deserialize_default`, and `struct custom_operations`'s `fixed_length` field is set to `NULL` or `custom_fixed_length_default`\n\nSince `Marshal.from*` and `input_value` remain unsafe to use, the fix for the OCaml runtime is released, and we wouldn't attempt to coordinate updating all deserialization functions in the ecosystem.\n\n## Timeline\n\n- Nov 4th 2025: Discovery Date: Discovered first in OxCaml\n- Nov 5th 2025: First Disclosure Date (Jane Street Team): Emailed top maintainers, no response.\n- Nov 9th 2025: Second Disclosure Date (OCaml Team): Submitted to OCaml/ocaml GitHub Repo as a Security Advisory.\n- Nov 11th 2025: Emailed OCaml Security Mail List: Submitted to OCaml over email, responded asking for details.\n- Nov 11th 2025: Third Disclosure (OCaml Security Response Team): Submitted to ocaml/security-advisories GitHub Repo as a Security Advisory.\n- Dec 16th 2025: Initial patch is developed\n- Dec 17th 2025: Fuzz testing found further issues\n- Dec 24th 2025: Final patch for OCaml is developed\n- Dec 25th 2025: Fuzz testing couldn't find any further issues\n- Jan 2nd 2026: Patch got reviewed by OCaml maintainers\n- Jan 4th 2026: Benchmarking of the patch with good results\n- Jan 6th 2026: Reporter got contacted to confirm\n- Jan 25th 2026: Further related issues discovered by fuzzing\n- Feb 17th 2026: fixed OCaml releases are published, security advisory is published",
						References: []db.Reference{{
							URL:  "https://github.com/ocaml/security-advisories/security/advisories/GHSA-j26j-m5xr-g23c",
							Tags: []string{"REPORT"},
						}},
						Aliases: []string{"CVE-2026-28364", "GHSA-j26j-m5xr-g23c", "GHSA-m34r-cgq7-jhfm"},
						Severities: []db.Severity{{
							Scheme: db.SeveritySchemeCVSS,
							Value: db.CVSSSeverity{
								Vector:  "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
								Version: "3.1",
							},
						}},
					},
				},
				Related: affectedPkgSlice(
					db.AffectedPackageHandle{
						Package: &db.Package{
							Name:      "ocaml",
							Ecosystem: "opam",
						},
						BlobValue: &db.PackageBlob{
							CVEs: []string{"CVE-2026-28364", "GHSA-j26j-m5xr-g23c", "GHSA-m34r-cgq7-jhfm"},
							Ranges: []db.Range{{
								Version: db.Version{Type: "opam", Constraint: "<4.14.3"},
								Fix:     ocamlFix("4.14.3", time.Date(2026, time.February, 17, 0, 0, 0, 0, time.UTC)),
							}, {
								Version: db.Version{Type: "opam", Constraint: ">=5.0.0,<5.4.1"},
								Fix:     ocamlFix("5.4.1", time.Date(2026, time.February, 17, 0, 0, 0, 0, time.UTC)),
							}},
						},
					},
				),
			}},
		},
		{
			// only an affected entry without a package holding GIT ranges: nothing to match
			name:        "OSEC-2026-28 without an opam package",
			fixturePath: "testdata/OSEC-2026-28.json",
			want:        nil,
		},
	}

	runTransformCases(t, tests)
}

// TestOCamlRangesUseOpamOrdering checks that the stored ranges of OSEC-2026-01
// (< 4.14.3 and [5.0.0, 5.4.1)) are evaluated with the opam version ordering.
func TestOCamlRangesUseOpamOrdering(t *testing.T) {
	vulns := loadFixture(t, "testdata/OSEC-2026-01.json")
	require.Len(t, vulns, 1)
	aphs := ocamlAffectedPackages(vulns[0])
	require.Len(t, aphs, 1)

	for _, tt := range []struct {
		version  string
		affected bool
	}{
		{version: "4.14.2", affected: true},
		{version: "4.14.3~rc1", affected: true},
		{version: "4.14.3", affected: false},
		{version: "5.0.0~alpha1", affected: false}, // pre-release before the first affected release 5.0.0
		{version: "5.0.0", affected: true},
		{version: "5.4.0", affected: true},
		{version: "5.4.1", affected: false},
	} {
		affected := false
		for _, r := range aphs[0].BlobValue.Ranges {
			c, err := version.GetConstraint(r.Version.Constraint, version.ParseFormat(r.Version.Type))
			require.NoError(t, err)
			satisfied, err := c.Satisfied(version.New(tt.version, version.OpamFormat))
			require.NoError(t, err)
			affected = affected || satisfied
		}
		assert.Equal(t, tt.affected, affected, "version %s", tt.version)
	}
}

// TestOCamlTransformRangeShapes covers OSV shapes the current advisories don't
// use (yet), starting from OSEC-2017-01.
func TestOCamlTransformRangeShapes(t *testing.T) {
	fixDate := time.Date(2017, time.June, 23, 0, 0, 0, 0, time.UTC)
	ecosystemRange := func(events ...osvmodel.Event) []osvmodel.Range {
		return []osvmodel.Range{{Type: osvmodel.RangeEcosystem, Events: events}}
	}
	tests := []struct {
		name     string
		modify   func(v *unmarshal.OSVVulnerability)
		packages []db.AffectedPackageHandle
	}{
		{
			name: "last_affected",
			modify: func(v *unmarshal.OSVVulnerability) {
				v.Affected[0].Ranges = ecosystemRange(osvmodel.Event{Introduced: "4.04.0"}, osvmodel.Event{LastAffected: "4.04.1"})
			},
			packages: []db.AffectedPackageHandle{ocamlPackage("ocaml", db.Range{
				Version: db.Version{Type: "opam", Constraint: ">=4.04.0,<=4.04.1"},
			})},
		},
		{
			name: "open-ended range",
			modify: func(v *unmarshal.OSVVulnerability) {
				v.Affected[0].Ranges = ecosystemRange(osvmodel.Event{Introduced: "4.04.0"})
			},
			packages: []db.AffectedPackageHandle{ocamlPackage("ocaml", db.Range{
				Version: db.Version{Type: "opam", Constraint: ">=4.04.0"},
			})},
		},
		{
			name: "multiple opam packages",
			modify: func(v *unmarshal.OSVVulnerability) {
				other := v.Affected[0]
				other.Package.Name = "ocaml-base-compiler"
				other.Package.Purl = "pkg:opam/ocaml-base-compiler"
				v.Affected = append(v.Affected, other)
			},
			packages: []db.AffectedPackageHandle{
				ocamlPackage("ocaml", db.Range{
					Version: db.Version{Type: "opam", Constraint: ">=4.04.0,<4.04.2"},
					Fix:     ocamlFix("4.04.2", fixDate),
				}),
				ocamlPackage("ocaml-base-compiler", db.Range{
					Version: db.Version{Type: "opam", Constraint: ">=4.04.0,<4.04.2"},
					Fix:     ocamlFix("4.04.2", fixDate),
				}),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vulns := loadFixture(t, "testdata/OSEC-2017-01.json")
			require.Len(t, vulns, 1)
			tt.modify(&vulns[0])
			assert.Equal(t, tt.packages, ocamlAffectedPackages(vulns[0]))
		})
	}
}

func TestOCamlTransformWithoutReferences(t *testing.T) {
	vulns := loadFixture(t, "testdata/OSEC-2017-01.json")
	require.Len(t, vulns, 1)
	vulns[0].References = nil

	entries, err := Transform(vulns[0], inputProviderState())
	require.NoError(t, err)
	require.Len(t, entries, 1)
	related, ok := entries[0].Data.(transformers.RelatedEntries)
	require.True(t, ok)
	assert.Empty(t, related.VulnerabilityHandle.BlobValue.References)
	assert.Len(t, related.Related, 1)
}

func ocamlPackage(name string, ranges ...db.Range) db.AffectedPackageHandle {
	return db.AffectedPackageHandle{
		Package:   &db.Package{Name: name, Ecosystem: "opam"},
		BlobValue: &db.PackageBlob{CVEs: []string{"CVE-2017-9772"}, Ranges: ranges},
	}
}

func ocamlFix(version string, date time.Time) *db.Fix {
	return &db.Fix{
		Version: version,
		State:   db.FixedStatus,
		Detail: &db.FixDetail{
			Available: &db.FixAvailability{Date: &date, Kind: "advisory"},
		},
	}
}

func TestOCamlTransformWithdrawn(t *testing.T) {
	vulns := loadFixture(t, "testdata/OSEC-2017-01.json")
	require.Len(t, vulns, 1)
	withdrawn := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	vulns[0].Withdrawn = withdrawn

	entries, err := Transform(vulns[0], inputProviderState())
	require.NoError(t, err)
	require.Len(t, entries, 1)
	related, ok := entries[0].Data.(transformers.RelatedEntries)
	require.True(t, ok)
	assert.Equal(t, db.VulnerabilityRejected, related.VulnerabilityHandle.Status)
	assert.Equal(t, &withdrawn, related.VulnerabilityHandle.WithdrawnDate)
}

func TestOCamlStrategyMatches(t *testing.T) {
	s := ocamlStrategy{}
	assert.True(t, s.Matches("OSEC-2026-01"))
	assert.False(t, s.Matches("GHSA-j26j-m5xr-g23c"))
	assert.False(t, s.Matches("CVE-2026-28364"))
}

// opam versions are not necessarily semver, e.g. menhir uses dates ("20260209")
// and Jane Street packages use a "v" prefix ("v0.16.0"); the constraint
// normalization must keep them intact.
func TestOCamlNonSemverRanges(t *testing.T) {
	tests := []struct {
		name       string
		introduced string
		fixed      string
		constraint string
		affected   []string
		unaffected []string
	}{
		{
			name:       "dates",
			introduced: "20220210",
			fixed:      "20260209",
			constraint: ">=20220210,<20260209",
			affected:   []string{"20220210", "20230415", "20260209~rc1"},
			unaffected: []string{"20211230", "20260209", "20260209.1"},
		},
		{
			name:       "v prefix",
			introduced: "v0.15.0",
			fixed:      "v0.16.0",
			constraint: ">=v0.15.0,<v0.16.0",
			affected:   []string{"v0.15.0", "v0.15.1", "v0.16.0~preview.129.00+243"},
			unaffected: []string{"v0.14.3", "v0.16.0", "v0.17.0"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ranges := eventsToRanges([]osvmodel.Event{{Introduced: tt.introduced}, {Fixed: tt.fixed}}, nil, "opam")
			require.Len(t, ranges, 1)
			assert.Equal(t, tt.constraint, ranges[0].Version.Constraint)
			require.NotNil(t, ranges[0].Fix)
			assert.Equal(t, tt.fixed, ranges[0].Fix.Version)

			c, err := version.GetConstraint(ranges[0].Version.Constraint, version.ParseFormat(ranges[0].Version.Type))
			require.NoError(t, err)
			for _, v := range tt.affected {
				satisfied, err := c.Satisfied(version.New(v, version.OpamFormat))
				require.NoError(t, err)
				assert.True(t, satisfied, "%s should be affected", v)
			}
			for _, v := range tt.unaffected {
				satisfied, err := c.Satisfied(version.New(v, version.OpamFormat))
				require.NoError(t, err)
				assert.False(t, satisfied, "%s should not be affected", v)
			}
		})
	}
}

// TestOCamlTransformUnfixed covers an advisory without a fix yet: like for
// govulndb, an ECOSYSTEM range with a lone introduced:0 yields no ranges, which
// grype treats as every version being vulnerable.
func TestOCamlTransformUnfixed(t *testing.T) {
	vulns := loadFixture(t, "testdata/OSEC-2017-01.json")
	require.Len(t, vulns, 1)
	vulns[0].Affected[0].Ranges = []osvmodel.Range{{
		Type:   osvmodel.RangeEcosystem,
		Events: []osvmodel.Event{{Introduced: "0"}},
	}}

	entries, err := Transform(vulns[0], inputProviderState())
	require.NoError(t, err)
	require.Len(t, entries, 1)
	related, ok := entries[0].Data.(transformers.RelatedEntries)
	require.True(t, ok)
	require.Len(t, related.Related, 1)
	aph, ok := related.Related[0].(db.AffectedPackageHandle)
	require.True(t, ok)
	assert.Equal(t, &db.Package{Name: "ocaml", Ecosystem: "opam"}, aph.Package)
	assert.Empty(t, aph.BlobValue.Ranges)
}

// TestOCamlTransformWithoutEcosystemRange checks that an opam entry without an
// ECOSYSTEM range is dropped instead of being stored without ranges, which would
// match every version.
func TestOCamlTransformWithoutEcosystemRange(t *testing.T) {
	vulns := loadFixture(t, "testdata/OSEC-2017-01.json")
	require.Len(t, vulns, 1)
	vulns[0].Affected[0].Ranges = []osvmodel.Range{{
		Type:   osvmodel.RangeSemVer,
		Events: []osvmodel.Event{{Introduced: "0"}, {Fixed: "4.04.2"}},
	}}

	entries, err := Transform(vulns[0], inputProviderState())
	require.NoError(t, err)
	assert.Empty(t, entries)
}
