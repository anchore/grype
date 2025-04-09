package cvss

import (
	"fmt"
	"math"
	"strings"

	gocvss20 "github.com/pandatix/go-cvss/20"
	gocvss30 "github.com/pandatix/go-cvss/30"
	gocvss31 "github.com/pandatix/go-cvss/31"
	gocvss40 "github.com/pandatix/go-cvss/40"

	"github.com/anchore/grype/grype/vulnerability"
)

func ParseMetricsFromVector(vector string) (*vulnerability.CvssMetrics, error) {
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

func SeverityFromBaseScore(bs float64) vulnerability.Severity {
	switch {
	case bs >= 10.0:
		return vulnerability.UnknownSeverity
	case bs >= 9.0:
		return vulnerability.CriticalSeverity
	case bs >= 7.0:
		return vulnerability.HighSeverity
	case bs >= 4.0:
		return vulnerability.MediumSeverity
	case bs >= 0.1:
		return vulnerability.LowSeverity
	case bs > 0:
		return vulnerability.NegligibleSeverity
	}
	return vulnerability.UnknownSeverity
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
