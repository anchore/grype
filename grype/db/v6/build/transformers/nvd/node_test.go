package nvd

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/cpe"
)

func TestDeduplicateCandidates(t *testing.T) {
	aVendorProduct1 := cpe.Attributes{
		Part:    "a",
		Vendor:  "vendor1",
		Product: "product1",
	}

	aVendorProduct2 := cpe.Attributes{
		Part:    "a",
		Vendor:  "vendor2",
		Product: "product2",
	}

	osProduct1 := cpe.Attributes{
		Part:    "o",
		Vendor:  "os1",
		Product: "os1product",
	}

	osProduct2 := cpe.Attributes{

		Part:    "o",
		Vendor:  "os2",
		Product: "os2product",
	}

	tests := []struct {
		name     string
		input    []affectedPackageCandidate
		expected []affectedPackageCandidate
	}{
		{
			name:     "empty input",
			input:    []affectedPackageCandidate{},
			expected: nil,
		},
		{
			name: "go case",
			input: []affectedPackageCandidate{
				{
					VulnerableCPE: aVendorProduct1,
					Ranges: newAffectedRanges(affectedCPERange{
						ExactVersion: "1.0",
					}),
				},
			},
			expected: []affectedPackageCandidate{
				{
					VulnerableCPE: aVendorProduct1,
					Ranges: newAffectedRanges(affectedCPERange{
						ExactVersion: "1.0",
					}),
				},
			},
		},
		{
			name: "deduplicate identical candidates",
			input: []affectedPackageCandidate{
				{
					VulnerableCPE: aVendorProduct1,
					Ranges: newAffectedRanges(affectedCPERange{
						ExactVersion: "1.0",
					}),
				},
				{
					VulnerableCPE: aVendorProduct1,
					Ranges: newAffectedRanges(affectedCPERange{
						ExactVersion: "1.0",
					}),
				},
			},
			expected: []affectedPackageCandidate{
				{
					VulnerableCPE: aVendorProduct1,
					Ranges: newAffectedRanges(affectedCPERange{
						ExactVersion: "1.0",
					}),
				},
			},
		},
		{
			name: "merge ranges for same CPE",
			input: []affectedPackageCandidate{
				{
					VulnerableCPE: aVendorProduct1,
					Ranges: newAffectedRanges(affectedCPERange{
						ExactVersion: "1.0",
					}),
				},
				{
					VulnerableCPE: aVendorProduct1,
					Ranges: newAffectedRanges(affectedCPERange{
						ExactVersion: "2.0",
					}),
				},
			},
			expected: []affectedPackageCandidate{
				{
					VulnerableCPE: aVendorProduct1,
					Ranges: newAffectedRanges(
						affectedCPERange{ExactVersion: "1.0"},
						affectedCPERange{ExactVersion: "2.0"},
					),
				},
			},
		},
		{
			name: "merge platform CPEs for same vulnerable CPE",
			input: []affectedPackageCandidate{
				{
					VulnerableCPE: aVendorProduct1,
					PlatformCPEs: []cpe.Attributes{
						osProduct1,
					},
					Ranges: newAffectedRanges(affectedCPERange{
						ExactVersion: "1.0",
					}),
				},
				{
					VulnerableCPE: aVendorProduct1,
					PlatformCPEs: []cpe.Attributes{
						osProduct2,
					},
					Ranges: newAffectedRanges(affectedCPERange{
						ExactVersion: "1.0",
					}),
				},
			},
			expected: []affectedPackageCandidate{
				{
					VulnerableCPE: aVendorProduct1,
					PlatformCPEs: []cpe.Attributes{
						osProduct1,
						osProduct2,
					},
					Ranges: newAffectedRanges(affectedCPERange{
						ExactVersion: "1.0",
					}),
				},
			},
		},
		{
			name: "different CPEs not deduplicated",
			input: []affectedPackageCandidate{
				{
					VulnerableCPE: aVendorProduct1,
					Ranges: newAffectedRanges(affectedCPERange{
						ExactVersion: "1.0",
					}),
				},
				{
					VulnerableCPE: aVendorProduct2,
					Ranges: newAffectedRanges(affectedCPERange{
						ExactVersion: "2.0",
					}),
				},
			},
			expected: []affectedPackageCandidate{
				{
					VulnerableCPE: aVendorProduct1,
					Ranges: newAffectedRanges(affectedCPERange{
						ExactVersion: "1.0",
					}),
				},
				{
					VulnerableCPE: aVendorProduct2,
					Ranges: newAffectedRanges(affectedCPERange{
						ExactVersion: "2.0",
					}),
				},
			},
		},
		{
			name: "deduplicate based on target software",
			input: []affectedPackageCandidate{
				{
					VulnerableCPE: cpe.Attributes{
						Part:     "a",
						Vendor:   "vendor",
						Product:  "product",
						TargetSW: "target1",
					},
					Ranges: newAffectedRanges(affectedCPERange{
						ExactVersion: "1.0",
					}),
				},
				{
					VulnerableCPE: cpe.Attributes{
						Part:     "a",
						Vendor:   "vendor",
						Product:  "product",
						TargetSW: "target2",
					},
					Ranges: newAffectedRanges(affectedCPERange{
						ExactVersion: "1.0",
					}),
				},
			},
			expected: []affectedPackageCandidate{
				{
					VulnerableCPE: cpe.Attributes{
						Part:     "a",
						Vendor:   "vendor",
						Product:  "product",
						TargetSW: "target1",
					},
					Ranges: newAffectedRanges(affectedCPERange{
						ExactVersion: "1.0",
					}),
				},
				{
					VulnerableCPE: cpe.Attributes{
						Part:     "a",
						Vendor:   "vendor",
						Product:  "product",
						TargetSW: "target2",
					},
					Ranges: newAffectedRanges(affectedCPERange{
						ExactVersion: "1.0",
					}),
				},
			},
		},
		{
			name: "derive ranges when none specified",
			input: []affectedPackageCandidate{
				{
					VulnerableCPE: cpe.Attributes{
						Part:    "a",
						Vendor:  "vendor",
						Product: "product",
						Version: "3.0",
						Update:  "p2",
					},
					Ranges: newAffectedRanges(),
				},
			},
			expected: []affectedPackageCandidate{
				{
					VulnerableCPE: cpe.Attributes{
						Part:    "a",
						Vendor:  "vendor",
						Product: "product",
						Version: "3.0",
						Update:  "p2",
					},
					Ranges: newAffectedRanges(affectedCPERange{
						ExactVersion: "3.0",
						ExactUpdate:  "p2",
					}),
				},
			},
		},
		{
			name: "derive ranges for one candidate but not others",
			input: []affectedPackageCandidate{
				{
					VulnerableCPE: cpe.Attributes{
						Part:    "a",
						Vendor:  "vendor",
						Product: "product1",
						Version: "3.0",
					},
					Ranges: newAffectedRanges(),
				},
				{
					VulnerableCPE: cpe.Attributes{
						Part:    "a",
						Vendor:  "vendor",
						Product: "product2",
					},
					Ranges: newAffectedRanges(affectedCPERange{
						ExactVersion: "1.0",
					}),
				},
			},
			expected: []affectedPackageCandidate{
				{
					VulnerableCPE: cpe.Attributes{
						Part:    "a",
						Vendor:  "vendor",
						Product: "product1",
						Version: "3.0",
					},
					Ranges: newAffectedRanges(affectedCPERange{
						ExactVersion: "3.0",
					}),
				},
				{
					VulnerableCPE: cpe.Attributes{
						Part:    "a",
						Vendor:  "vendor",
						Product: "product2",
					},
					Ranges: newAffectedRanges(affectedCPERange{
						ExactVersion: "1.0",
					}),
				},
			},
		},
		{
			name: "complex case with mixed input",
			input: []affectedPackageCandidate{
				{
					VulnerableCPE: cpe.Attributes{
						Part:      "a",
						Vendor:    "vendor",
						Product:   "product",
						Version:   "1.0",
						SWEdition: "enterprise",
					},
					PlatformCPEs: []cpe.Attributes{
						osProduct1,
					},
					Ranges: newAffectedRanges(affectedCPERange{
						ExactVersion: "1.0",
					}),
				},
				{
					VulnerableCPE: cpe.Attributes{
						Part:      "a",
						Vendor:    "vendor",
						Product:   "product",
						Version:   "1.0",
						SWEdition: "enterprise",
					},
					PlatformCPEs: []cpe.Attributes{
						osProduct2,
					},
					Ranges: newAffectedRanges(affectedCPERange{
						VersionStartIncluding: "1.0",
						VersionEndExcluding:   "2.0",
					}),
				},
				{
					VulnerableCPE: cpe.Attributes{
						Part:      "a",
						Vendor:    "vendor",
						Product:   "product",
						Version:   "1.0",
						SWEdition: "community",
					},
					Ranges: newAffectedRanges(affectedCPERange{
						ExactVersion: "1.0",
					}),
				},
			},
			expected: []affectedPackageCandidate{
				{
					VulnerableCPE: cpe.Attributes{
						Part:      "a",
						Vendor:    "vendor",
						Product:   "product",
						Version:   "1.0",
						SWEdition: "community",
					},
					Ranges: newAffectedRanges(affectedCPERange{
						ExactVersion: "1.0",
					}),
				},
				{
					VulnerableCPE: cpe.Attributes{
						Part:      "a",
						Vendor:    "vendor",
						Product:   "product",
						Version:   "1.0",
						SWEdition: "enterprise",
					},
					PlatformCPEs: []cpe.Attributes{
						osProduct1,
						osProduct2,
					},
					Ranges: newAffectedRanges(
						affectedCPERange{
							ExactVersion: "1.0",
						},
						affectedCPERange{
							VersionStartIncluding: "1.0",
							VersionEndExcluding:   "2.0",
						},
					),
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := deduplicateCandidates(tt.input)

			if diff := cmp.Diff(tt.expected, actual); diff != "" {
				t.Errorf("deduplicateCandidates() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestDeduplicateCandidates_SensitiveToAllCPEFields(t *testing.T) {
	base := cpe.Attributes{
		Part:      "a",
		Vendor:    "vendor",
		Product:   "product",
		Version:   "1.0",
		Update:    "update",
		Edition:   "edition",
		SWEdition: "sw-edition",
		TargetSW:  "target-sw",
		TargetHW:  "target-hw",
		Language:  "lang",
		Other:     "other",
	}

	// note: we do not care about version and update fields for this part of the test...
	for field, mutate := range map[string]func(cpe.Attributes) cpe.Attributes{
		"Part":      func(c cpe.Attributes) cpe.Attributes { c.Part = "h"; return c },
		"Vendor":    func(c cpe.Attributes) cpe.Attributes { c.Vendor = "other-vendor"; return c },
		"Product":   func(c cpe.Attributes) cpe.Attributes { c.Product = "other-product"; return c },
		"Edition":   func(c cpe.Attributes) cpe.Attributes { c.Edition = "other-edition"; return c },
		"SWEdition": func(c cpe.Attributes) cpe.Attributes { c.SWEdition = "other-sw-edition"; return c },
		"TargetSW":  func(c cpe.Attributes) cpe.Attributes { c.TargetSW = "other-target-sw"; return c },
		"TargetHW":  func(c cpe.Attributes) cpe.Attributes { c.TargetHW = "other-target-hw"; return c },
		"Language":  func(c cpe.Attributes) cpe.Attributes { c.Language = "other-lang"; return c },
		"Other":     func(c cpe.Attributes) cpe.Attributes { c.Other = "other-other"; return c },
	} {
		t.Run("field="+field, func(t *testing.T) {
			a := affectedPackageCandidate{VulnerableCPE: base, Ranges: newAffectedRanges()}
			b := affectedPackageCandidate{VulnerableCPE: mutate(base), Ranges: newAffectedRanges()}
			result := deduplicateCandidates([]affectedPackageCandidate{a, b})
			require.Len(t, result, 2, "field %s should cause deduplication to treat entries as separate", field)
		})
	}

	// now that all other fields have been tested, prove that we do not care about version and update fields...
	t.Run("Version and Update do not matter", func(t *testing.T) {
		c1 := base
		c1.Version = "1.0"
		c1.Update = "u1"

		c2 := base
		c2.Version = "2.0"
		c2.Update = "u2"

		a := affectedPackageCandidate{VulnerableCPE: c1, Ranges: newAffectedRanges(affectedCPERange{ExactVersion: "1.0"})}
		b := affectedPackageCandidate{VulnerableCPE: c2, Ranges: newAffectedRanges(affectedCPERange{ExactVersion: "2.0"})}

		result := deduplicateCandidates([]affectedPackageCandidate{a, b})
		require.Len(t, result, 1)
		require.Len(t, result[0].Ranges, 2)
	})
}
