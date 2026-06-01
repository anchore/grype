package osv

import (
	"reflect"
	"testing"
	"time"

	"github.com/anchore/grype/grype/db/internal/provider/unmarshal/osvmodel"
	db "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/build/transformers"
)

// TestAlmaTransform exercises the alma strategy end-to-end against real ALSA
// fixtures pulled from the on-disk vunnel cache.
//
// Each fixture targets a distinct shape:
//
//   - ALSA-2020-1636: the dominant alma shape — aliases:null, related populated.
//     Regression net for the related → aliases augmentation that the strategy
//     does on the vulnerability blob.
//   - ALSA-2021-4156: carries ecosystem_specific.rpm_modularity (~63% of alma 8
//     records are modular). Regression net for the modularity qualifier
//     round-trip through the advisory path.
//   - ALSA-2025-7467: the exceptional shape — aliases populated, related null,
//     multiple affected packages on the same advisory. Also covers the
//     ADVISORY-typed reference with refID injection.
func TestAlmaTransform(t *testing.T) {
	tests := []transformCase{
		{
			name:        "AlmaLinux Advisory with related-only aliases",
			fixturePath: "testdata/ALSA-2020-1636.json",
			want: []transformers.RelatedEntries{{
				VulnerabilityHandle: &db.VulnerabilityHandle{
					Name:          "ALSA-2020:1636",
					Status:        db.VulnerabilityActive,
					ProviderID:    "osv",
					Provider:      expectedProvider(),
					ModifiedDate:  timeRef(time.Date(2021, time.August, 11, 8, 54, 0, 0, time.UTC)),
					PublishedDate: timeRef(time.Date(2020, time.April, 28, 8, 59, 15, 0, time.UTC)),
					BlobValue: &db.VulnerabilityBlob{
						ID:          "ALSA-2020:1636",
						Description: "libsndfile is a C library for reading and writing files containing sampled sound, such as AIFF, AU, or WAV. \n\nSecurity Fix(es):\n\n* libsndfile: stack-based buffer overflow in sndfile-deinterleave utility (CVE-2018-13139)\n\n* libsndfile: buffer over-read in the function i2alaw_array in alaw.c (CVE-2018-19662)\n\nFor more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and other related information, refer to the CVE page(s) listed in the References section.\n\nAdditional Changes:\n\nFor detailed information on changes in this release, see the AlmaLinux Release Notes linked from the References section.",
						References: []db.Reference{
							{URL: "https://vulners.com/cve/CVE-2018-13139", Tags: []string{"REPORT"}},
							{URL: "https://vulners.com/cve/CVE-2018-19662", Tags: []string{"REPORT"}},
						},
						Aliases:    []string{"CVE-2018-13139", "CVE-2018-19662"},
						Severities: nil,
					},
				},
				Related: unaffectedPkgSlice(
					db.UnaffectedPackageHandle{
						Package: &db.Package{
							Name:      "libsndfile-devel",
							Ecosystem: "rpm",
						},
						OperatingSystem: &db.OperatingSystem{
							Name:         "almalinux",
							MajorVersion: "8",
						},
						BlobValue: &db.PackageBlob{
							// PackageBlob.CVEs is currently built from the un-augmented
							// vuln.Aliases (nil for this record), so the package-level CVE
							// list is empty even though VulnerabilityBlob.Aliases above
							// correctly carries CVE-2018-13139 + CVE-2018-19662. Whether to
							// populate this from the augmented list is a per-strategy
							// decision; this assertion locks down current behavior.
							// Functionally low-impact: the only runtime read site
							// (vulnerability.go::getRelatedVulnerabilities) already sees the
							// same CVEs via vuln.BlobValue.Aliases and dedups.
							CVEs: nil,
							Ranges: []db.Range{{
								Version: db.Version{
									Type:       "rpm",
									Constraint: ">= 1.0.28-10.el8",
								},
								Fix: &db.Fix{
									Version: "1.0.28-10.el8",
									State:   db.FixedStatus,
								},
							}},
						},
					},
				),
			}},
		},
		{
			name:        "AlmaLinux Advisory with rpm_modularity",
			fixturePath: "testdata/ALSA-2021-4156.json",
			want: []transformers.RelatedEntries{{
				VulnerabilityHandle: &db.VulnerabilityHandle{
					Name:          "ALSA-2021:4156",
					Status:        db.VulnerabilityActive,
					ProviderID:    "osv",
					Provider:      expectedProvider(),
					ModifiedDate:  timeRef(time.Date(2021, time.December, 16, 11, 29, 11, 0, time.UTC)),
					PublishedDate: timeRef(time.Date(2021, time.November, 9, 8, 25, 49, 0, time.UTC)),
					BlobValue: &db.VulnerabilityBlob{
						ID:          "ALSA-2021:4156",
						Description: "Go Toolset provides the Go programming language tools and libraries. Go is alternatively known as golang. \n\nThe following packages have been upgraded to a later upstream version: golang (1.16.7). (BZ#1938071)\n\nSecurity Fix(es):\n\n* golang: net: lookup functions may return invalid host names (CVE-2021-33195)\n\n* golang: net/http/httputil: ReverseProxy forwards connection headers if first one is empty (CVE-2021-33197)\n\n* golang: math/big.Rat: may cause a panic or an unrecoverable fatal error if passed inputs with very large exponents (CVE-2021-33198)\n\n* golang: net/http/httputil: panic due to racy read of persistConn after handler panic (CVE-2021-36221)\n\nFor more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and other related information, refer to the CVE page(s) listed in the References section.\n\nAdditional Changes:\n\nFor detailed information on changes in this release, see the AlmaLinux Release Notes linked from the References section.",
						References: []db.Reference{
							{URL: "https://vulners.com/cve/CVE-2021-33195", Tags: []string{"REPORT"}},
							{URL: "https://vulners.com/cve/CVE-2021-33197", Tags: []string{"REPORT"}},
							{URL: "https://vulners.com/cve/CVE-2021-33198", Tags: []string{"REPORT"}},
							{URL: "https://vulners.com/cve/CVE-2021-36221", Tags: []string{"REPORT"}},
						},
						Aliases:    []string{"CVE-2021-33195", "CVE-2021-33197", "CVE-2021-33198", "CVE-2021-36221"},
						Severities: nil,
					},
				},
				Related: unaffectedPkgSlice(
					db.UnaffectedPackageHandle{
						Package: &db.Package{
							Name:      "delve",
							Ecosystem: "rpm",
						},
						OperatingSystem: &db.OperatingSystem{
							Name:         "almalinux",
							MajorVersion: "8",
						},
						BlobValue: &db.PackageBlob{
							// Same per-strategy-decision call-out as ALSA-2020:1636 above.
							CVEs: nil,
							Qualifiers: &db.PackageQualifiers{
								RpmModularity: stringRef("go-toolset:rhel8"),
							},
							Ranges: []db.Range{{
								Version: db.Version{
									Type:       "rpm",
									Constraint: ">= 1.6.0-1.module_el8.5.0+2604+960c7771",
								},
								Fix: &db.Fix{
									Version: "1.6.0-1.module_el8.5.0+2604+960c7771",
									State:   db.FixedStatus,
								},
							}},
						},
					},
				),
			}},
		},
		{
			name:        "AlmaLinux Advisory with aliases populated and ADVISORY ref",
			fixturePath: "testdata/ALSA-2025-7467.json",
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
							MajorVersion: "10",
						},
						BlobValue: &db.PackageBlob{
							CVEs: []string{"CVE-2025-27144"},
							Ranges: []db.Range{{
								Version: db.Version{
									Type:       "rpm",
									Constraint: ">= 2:1.18.1-1.el10_0",
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
							MajorVersion: "10",
						},
						BlobValue: &db.PackageBlob{
							CVEs: []string{"CVE-2025-27144"},
							Ranges: []db.Range{{
								Version: db.Version{
									Type:       "rpm",
									Constraint: ">= 2:1.18.1-1.el10_0",
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
	}
	runTransformCases(t, tests)
}

// TestAlmaRangeConversion exercises the alma-flavored range-conversion path:
// almaRangeType maps OSV's ECOSYSTEM to "rpm", then
// getGrypeUnaffectedRangesFromRange inverts the event list into the
// >= fix constraints that advisory records need.
//
// Inputs use realistic alma shapes (ECOSYSTEM, real RPM version strings); the
// old test_getGrypeRangesFromRange used SEMVER + "npm" which never reflected
// any provider's actual records.
func TestAlmaRangeConversion(t *testing.T) {
	tests := []struct {
		name string
		rnge osvmodel.Range
		want []db.Range
	}{
		{
			name: "ECOSYSTEM range with introduced=0 and fixed produces inverted unaffected range",
			rnge: osvmodel.Range{
				Type: osvmodel.RangeEcosystem,
				Events: []osvmodel.Event{
					{Introduced: "0"},
					{Fixed: "1.0.28-10.el8"},
				},
			},
			want: []db.Range{{
				Version: db.Version{Type: "rpm", Constraint: ">= 1.0.28-10.el8"},
				Fix:     &db.Fix{Version: "1.0.28-10.el8", State: db.FixedStatus},
			}},
		},
		{
			name: "ECOSYSTEM range with modular RPM fix version",
			rnge: osvmodel.Range{
				Type: osvmodel.RangeEcosystem,
				Events: []osvmodel.Event{
					{Introduced: "0"},
					{Fixed: "1.6.0-1.module_el8.5.0+2604+960c7771"},
				},
			},
			want: []db.Range{{
				Version: db.Version{Type: "rpm", Constraint: ">= 1.6.0-1.module_el8.5.0+2604+960c7771"},
				Fix:     &db.Fix{Version: "1.6.0-1.module_el8.5.0+2604+960c7771", State: db.FixedStatus},
			}},
		},
		{
			name: "ECOSYSTEM range with epoch-prefixed RPM version",
			rnge: osvmodel.Range{
				Type: osvmodel.RangeEcosystem,
				Events: []osvmodel.Event{
					{Introduced: "0"},
					{Fixed: "2:1.18.1-1.el10_0"},
				},
			},
			want: []db.Range{{
				Version: db.Version{Type: "rpm", Constraint: ">= 2:1.18.1-1.el10_0"},
				Fix:     &db.Fix{Version: "2:1.18.1-1.el10_0", State: db.FixedStatus},
			}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getGrypeUnaffectedRangesFromRange(tt.rnge, almaRangeType(tt.rnge.Type))
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

// Test_almaEcoExt covers the alma-only ecosystem_specific reader. Kept as a
// unit test (not just integration coverage) because the input-type branches
// (nil map, missing key, non-string value) are real defensive paths that
// wouldn't reliably show up in production records — the typed accessor
// silently coerces a non-string rpm_modularity to "" via JSON unmarshal
// failure, which is the behavior the caller depends on.
func Test_almaEcoExt(t *testing.T) {
	tests := []struct {
		name     string
		affected osvmodel.Affected
		want     string
	}{
		{
			name: "with rpm_modularity",
			affected: osvmodel.Affected{
				EcosystemSpecific: map[string]any{
					"rpm_modularity": "mariadb:10.3",
				},
			},
			want: "mariadb:10.3",
		},
		{
			name:     "no ecosystem_specific",
			affected: osvmodel.Affected{EcosystemSpecific: nil},
			want:     "",
		},
		{
			name: "no rpm_modularity key",
			affected: osvmodel.Affected{
				EcosystemSpecific: map[string]any{"other_key": "some_value"},
			},
			want: "",
		},
		{
			name: "rpm_modularity not string",
			affected: osvmodel.Affected{
				EcosystemSpecific: map[string]any{"rpm_modularity": 123},
			},
			want: "",
		},
		{
			name: "nodejs modularity",
			affected: osvmodel.Affected{
				EcosystemSpecific: map[string]any{"rpm_modularity": "nodejs:16"},
			},
			want: "nodejs:16",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := almaEcoExt(tt.affected).RpmModularity; got != tt.want {
				t.Errorf("almaEcoExt(...).RpmModularity = %v, want %v", got, tt.want)
			}
		})
	}
}
