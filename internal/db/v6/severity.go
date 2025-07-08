package v6

import (
	"fmt"

	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/cvss"
	"github.com/anchore/grype/internal/log"
)

func extractSeverities(vuln *VulnerabilityHandle) (vulnerability.Severity, []vulnerability.Cvss, error) {
	if vuln.BlobValue == nil {
		return vulnerability.UnknownSeverity, nil, nil
	}
	sev := vulnerability.UnknownSeverity
	if len(vuln.BlobValue.Severities) > 0 {
		var err error
		// grype DB v6+ will order the set of severities by rank, so we can just take the first one
		sev, err = extractSeverity(vuln.BlobValue.Severities[0].Value)
		if err != nil {
			return vulnerability.UnknownSeverity, nil, fmt.Errorf("unable to extract severity: %w", err)
		}
	}
	return sev, toCvss(vuln.BlobValue.Severities...), nil
}

func extractSeverity(severity any) (vulnerability.Severity, error) {
	switch sev := severity.(type) {
	case string:
		return vulnerability.ParseSeverity(sev), nil
	case CVSSSeverity:
		metrics, err := cvss.ParseMetricsFromVector(sev.Vector)
		if err != nil {
			return vulnerability.UnknownSeverity, fmt.Errorf("unable to parse CVSS vector: %w", err)
		}
		if metrics == nil {
			return vulnerability.UnknownSeverity, nil
		}
		return interpretCVSS(metrics.BaseScore, sev.Version), nil
	default:
		return vulnerability.UnknownSeverity, nil
	}
}

func interpretCVSS(score float64, version string) vulnerability.Severity {
	switch version {
	case "2.0":
		return interpretCVSSv2(score)
	case "3.0", "3.1", "4.0":
		return interpretCVSSv3Plus(score)
	default:
		return vulnerability.UnknownSeverity
	}
}

func interpretCVSSv2(score float64) vulnerability.Severity {
	if score < 0 {
		return vulnerability.UnknownSeverity
	}
	if score == 0 {
		return vulnerability.NegligibleSeverity
	}
	if score < 4.0 {
		return vulnerability.LowSeverity
	}
	if score < 7.0 {
		return vulnerability.MediumSeverity
	}
	if score <= 10.0 {
		return vulnerability.HighSeverity
	}
	return vulnerability.UnknownSeverity
}

func interpretCVSSv3Plus(score float64) vulnerability.Severity {
	if score < 0 {
		return vulnerability.UnknownSeverity
	}
	if score == 0 {
		return vulnerability.NegligibleSeverity
	}
	if score < 4.0 {
		return vulnerability.LowSeverity
	}
	if score < 7.0 {
		return vulnerability.MediumSeverity
	}
	if score < 9.0 {
		return vulnerability.HighSeverity
	}
	if score <= 10.0 {
		return vulnerability.CriticalSeverity
	}
	return vulnerability.UnknownSeverity
}

func toCvss(severities ...Severity) []vulnerability.Cvss {
	//nolint:prealloc
	var out []vulnerability.Cvss
	for _, sev := range severities {
		switch sev.Scheme {
		case SeveritySchemeCVSS:
		default:
			// not a CVSS score
			continue
		}
		cvssSev, ok := sev.Value.(CVSSSeverity)
		if !ok {
			// not a CVSS score
			continue
		}
		var usedMetrics vulnerability.CvssMetrics
		// though the DB has the base score, we parse the vector for all metrics
		metrics, err := cvss.ParseMetricsFromVector(cvssSev.Vector)
		if err != nil {
			log.WithFields("vector", cvssSev.Vector, "error", err).Warn("unable to parse CVSS vector")
			continue
		}
		if metrics != nil {
			usedMetrics = *metrics
		}

		out = append(out, vulnerability.Cvss{
			Source:  sev.Source,
			Type:    legacyCVSSType(sev.Rank),
			Version: cvssSev.Version,
			Vector:  cvssSev.Vector,
			Metrics: usedMetrics,
		})
	}
	return out
}

func legacyCVSSType(rank int) string {
	if rank == 1 {
		return "Primary"
	}
	return "Secondary"
}
