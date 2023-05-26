package models

import "github.com/nextlinux/griffon/griffon/vulnerability"

type Cvss struct {
	Version        string      `json:"version"`
	Vector         string      `json:"vector"`
	Metrics        CvssMetrics `json:"metrics"`
	VendorMetadata interface{} `json:"vendorMetadata"`
}

type CvssMetrics struct {
	BaseScore           float64  `json:"baseScore"`
	ExploitabilityScore *float64 `json:"exploitabilityScore,omitempty"`
	ImpactScore         *float64 `json:"impactScore,omitempty"`
}

func NewCVSS(metadata *vulnerability.Metadata) []Cvss {
	cvss := make([]Cvss, 0)
	for _, score := range metadata.Cvss {
		vendorMetadata := score.VendorMetadata
		if vendorMetadata == nil {
			vendorMetadata = make(map[string]interface{})
		}
		cvss = append(cvss, Cvss{
			Version: score.Version,
			Vector:  score.Vector,
			Metrics: CvssMetrics{
				BaseScore:           score.Metrics.BaseScore,
				ExploitabilityScore: score.Metrics.ExploitabilityScore,
				ImpactScore:         score.Metrics.ImpactScore,
			},
			VendorMetadata: vendorMetadata,
		})
	}
	return cvss
}
