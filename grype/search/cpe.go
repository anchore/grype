package search

import (
	"strings"

	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/cpe"
)

// ByCPE returns criteria which will search based on any of the provided CPEs
func ByCPE(c cpe.CPE) vulnerability.Criteria {
	return &CPECriteria{
		CPE: c,
	}
}

type CPECriteria struct {
	CPE cpe.CPE
}

func (v *CPECriteria) MatchesVulnerability(vuln vulnerability.Vulnerability) (bool, error) {
	if containsCPE(vuln.CPEs, v.CPE) {
		return true, nil
	}
	return false, nil
}

var _ interface {
	vulnerability.Criteria
} = (*CPECriteria)(nil)

// containsCPE returns true if the provided slice contains a matching CPE based on attributes matching
func containsCPE(cpes []cpe.CPE, cpe cpe.CPE) bool {
	for _, c := range cpes {
		if matchesAttributes(cpe.Attributes, c.Attributes) {
			return true
		}
	}
	return false
}

func matchesAttributes(a1 cpe.Attributes, a2 cpe.Attributes) bool {
	if !matchesAttribute(a1.Product, a2.Product) ||
		!matchesAttribute(a1.Vendor, a2.Vendor) ||
		!matchesAttribute(a1.Part, a2.Part) ||
		!matchesAttribute(a1.Language, a2.Language) ||
		!matchesAttribute(a1.SWEdition, a2.SWEdition) ||
		!matchesAttribute(a1.TargetSW, a2.TargetSW) ||
		!matchesAttribute(a1.TargetHW, a2.TargetHW) ||
		!matchesAttribute(a1.Other, a2.Other) ||
		!matchesAttribute(a1.Edition, a2.Edition) {
		return false
	}
	return true
}

func matchesAttribute(a1, a2 string) bool {
	return a1 == "" || a2 == "" || strings.EqualFold(a1, a2)
}
