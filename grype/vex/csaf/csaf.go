package csaf

import (
	"slices"

	"github.com/csaf-poc/csaf_distribution/v3/csaf"
)

// advisoryMatch captures the criteria that caused a vulnerability to match a CSAF advisory
type advisoryMatch struct {
	Vulnerability *csaf.Vulnerability
	Status        status
	ProductID     csaf.ProductID
}

// cve returns the CVE of the vulnerability that matched
func (m *advisoryMatch) cve() string {
	if m == nil || m.Vulnerability == nil || m.Vulnerability.CVE == nil {
		return ""
	}

	return string(*m.Vulnerability.CVE)
}

// statement returns the statement of the vulnerability that matched
func (m *advisoryMatch) statement() string {
	if m == nil || m.Vulnerability == nil {
		return ""
	}

	// an impact statement SHALL exist as machine readable flag in /vulnerabilities[]/flags (...)
	for _, flag := range m.Vulnerability.Flags {
		if flag == nil || flag.ProductIds == nil || flag.Label == nil {
			continue
		}
		for _, pID := range *flag.ProductIds {
			if pID == nil {
				continue
			}
			if *pID == m.ProductID {
				return string(*flag.Label)
			}
		}
	}
	// (...) or as human readable justification in /vulnerabilities[]/threats
	for _, th := range m.Vulnerability.Threats {
		if th == nil || th.Category == nil || th.Details == nil {
			continue
		}
		if *th.Category == csaf.CSAFThreatCategoryImpact {
			return string(*th.Details)
		}
	}

	return ""
}

type advisories []*csaf.Advisory

// Matches returns the first CSAF advisory to match for a given vulnerability ID and package URL
func (advisories advisories) matches(vulnID, purl string) *advisoryMatch {
	for _, adv := range advisories {
		if adv == nil || adv.Vulnerabilities == nil {
			continue
		}

		// Auxiliary function to find in the advisory the 1st product ID that matches a given pURL
		findProductID := func(products csaf.Products, purl string) csaf.ProductID {
			for _, p := range products {
				if p == nil {
					continue
				}
				if slices.Contains(purlsFromProductIdentificationHelpers(adv.ProductTree.CollectProductIdentificationHelpers(*p)), purl) {
					return *p
				}
			}
			return ""
		}

		for _, vuln := range adv.Vulnerabilities {
			if vuln == nil || vuln.CVE == nil || string(*vuln.CVE) != vulnID {
				continue
			}

			productsByStatus := map[status]*csaf.Products{
				firstAffected:      vuln.ProductStatus.FirstAffected,
				firstFixed:         vuln.ProductStatus.FirstFixed,
				fixed:              vuln.ProductStatus.Fixed,
				knownAffected:      vuln.ProductStatus.KnownAffected,
				knownNotAffected:   vuln.ProductStatus.KnownNotAffected,
				lastAffected:       vuln.ProductStatus.LastAffected,
				recommended:        vuln.ProductStatus.Recommended,
				underInvestigation: vuln.ProductStatus.UnderInvestigation,
			}
			for status, products := range productsByStatus {
				if products == nil {
					continue
				}
				if productID := findProductID(*products, purl); productID != "" {
					return &advisoryMatch{vuln, status, productID}
				}
			}
		}
	}

	return nil
}

// purlsFromProductIdentificationHelpers returns a slice of PackageURLs (string format) given a slice of ProductIdentificationHelpers.
func purlsFromProductIdentificationHelpers(helpers []*csaf.ProductIdentificationHelper) []string {
	var purls []string
	for _, helper := range helpers {
		if helper == nil || helper.PURL == nil {
			continue
		}
		purls = append(purls, string(*helper.PURL))
	}
	return purls
}
