package v5

import (
	"github.com/anchore/grype/grype/vulnerability"
)

func NewCvss(m []Cvss) []vulnerability.Cvss {
	//nolint:prealloc
	var cvss []vulnerability.Cvss
	for _, score := range m {
		cvss = append(cvss, vulnerability.Cvss{
			Source:  score.Source,
			Type:    score.Type,
			Version: score.Version,
			Vector:  score.Vector,
			Metrics: vulnerability.CvssMetrics{
				BaseScore:           score.Metrics.BaseScore,
				ExploitabilityScore: score.Metrics.ExploitabilityScore,
				ImpactScore:         score.Metrics.ImpactScore,
			},
			VendorMetadata: score.VendorMetadata,
		})
	}
	return cvss
}
