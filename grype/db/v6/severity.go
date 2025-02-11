package v6

import (
	"fmt"
	"math"
	"strings"

	gocvss20 "github.com/pandatix/go-cvss/20"
	gocvss30 "github.com/pandatix/go-cvss/30"
	gocvss31 "github.com/pandatix/go-cvss/31"
	gocvss40 "github.com/pandatix/go-cvss/40"

	"github.com/anchore/grype/grype/vulnerability"
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
		metrics, err := parseCVSS(sev.Vector)
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

func parseCVSS(vector string) (*vulnerability.CvssMetrics, error) {
	switch {
	case strings.HasPrefix(vector, "CVSS:3.0"):
		cvss, err := gocvss30.ParseVector(vector)
		if err != nil {
			return nil, fmt.Errorf("unable to parse CVSS v3 vector: %w", err)
		}
		ex := roundScore(cvss.Exploitability())
		im := roundScore(cvss.Impact())
		return &vulnerability.CvssMetrics{
			BaseScore:           roundScore(cvss.BaseScore()),
			ExploitabilityScore: &ex,
			ImpactScore:         &im,
		}, nil
	case strings.HasPrefix(vector, "CVSS:3.1"):
		cvss, err := gocvss31.ParseVector(vector)
		if err != nil {
			return nil, fmt.Errorf("unable to parse CVSS v3.1 vector: %w", err)
		}
		ex := roundScore(cvss.Exploitability())
		im := roundScore(cvss.Impact())
		return &vulnerability.CvssMetrics{
			BaseScore:           roundScore(cvss.BaseScore()),
			ExploitabilityScore: &ex,
			ImpactScore:         &im,
		}, nil
	case strings.HasPrefix(vector, "CVSS:4.0"):
		cvss, err := gocvss40.ParseVector(vector)
		if err != nil {
			return nil, fmt.Errorf("unable to parse CVSS v4.0 vector: %w", err)
		}
		// there are no exploitability and impact scores in CVSS v4.0
		return &vulnerability.CvssMetrics{
			BaseScore: roundScore(cvss.Score()),
		}, nil
	default:
		// should be CVSS v2.0 or is invalid
		cvss, err := gocvss20.ParseVector(vector)
		if err != nil {
			return nil, fmt.Errorf("unable to parse CVSS v2 vector: %w", err)
		}
		ex := roundScore(cvss.Exploitability())
		im := roundScore(cvss.Impact())
		return &vulnerability.CvssMetrics{
			BaseScore:           roundScore(cvss.BaseScore()),
			ExploitabilityScore: &ex,
			ImpactScore:         &im,
		}, nil
	}
}

// roundScore rounds the score to the nearest tenth based on first.org rounding rules
// see https://www.first.org/cvss/v3.1/specification-document#Appendix-A---Floating-Point-Rounding
func roundScore(score float64) float64 {
	intInput := int(math.Round(score * 100000))
	if intInput%10000 == 0 {
		return float64(intInput) / 100000.0
	}
	return (math.Floor(float64(intInput)/10000.0) + 1) / 10.0
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
		metrics, err := parseCVSS(cvssSev.Vector)
		if err != nil {
			log.WithFields("vector", cvssSev.Vector, "error", err).Warn("unable to parse CVSS vector")
			continue
		}
		if metrics != nil {
			usedMetrics = *metrics
		}

		out = append(out, vulnerability.Cvss{
			Source:  sev.Source,
			Type:    string(sev.Scheme),
			Version: cvssSev.Version,
			Vector:  cvssSev.Vector,
			Metrics: usedMetrics,
		})
	}
	return out
}
