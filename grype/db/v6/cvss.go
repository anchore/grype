package v6

import (
	"github.com/anchore/grype/grype/vulnerability"
)

func NewCvss(severities ...Severity) []vulnerability.Cvss {
	//nolint:prealloc
	var out []vulnerability.Cvss
	for _, sev := range severities {
		switch sev.Scheme {
		case SeveritySchemeCVSS:
		default:
			// not a CVSS score
			continue
		}
		score, ok := sev.Value.(CVSSSeverity)
		if !ok {
			// not a CVSS score
			continue
		}
		out = append(out, vulnerability.Cvss{
			Source:  sev.Source,
			Type:    string(sev.Scheme),
			Version: score.Version,
			Vector:  score.Vector,
			Metrics: vulnerability.CvssMetrics{
				// FIXME: where do these metrics come from?
				//BaseScore:           score.Metrics.BaseScore,
				//ExploitabilityScore: score.Metrics.ExploitabilityScore,
				//ImpactScore:         score.Metrics.ImpactScore,
			},
			//VendorMetadata: score.VendorMetadata,
		})
	}
	return out
}
