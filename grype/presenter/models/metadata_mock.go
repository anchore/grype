package models

import (
	"github.com/anchore/grype/grype/vulnerability"
)

var _ vulnerability.MetadataProvider = (*MetadataMock)(nil)

// MetadataMock provides the behavior required for a vulnerability.Provider for the purpose of testing.
type MetadataMock struct {
	store map[string]map[string]vulnerability.Metadata
}

type MockVendorMetadata struct {
	BaseSeverity string
	Status       string
}

// NewMetadataMock returns a new instance of MetadataMock.
func NewMetadataMock() *MetadataMock {
	return &MetadataMock{
		store: map[string]map[string]vulnerability.Metadata{
			"CVE-1999-0001": {
				"source-1": {
					Description: "1999-01 description",
					Severity:    "Low",
					Cvss: []vulnerability.Cvss{
						{
							Metrics: vulnerability.CvssMetrics{
								BaseScore: 4,
							},
							Vector:  "another vector",
							Version: "3.0",
						},
					},
				},
			},
			"CVE-1999-0002": {
				"source-2": {
					Description: "1999-02 description",
					Severity:    "Critical",
					Cvss: []vulnerability.Cvss{
						{
							Metrics: vulnerability.CvssMetrics{
								BaseScore:           1,
								ExploitabilityScore: ptr(2.0),
								ImpactScore:         ptr(3.0),
							},
							Vector:  "vector",
							Version: "2.0",
							VendorMetadata: MockVendorMetadata{
								BaseSeverity: "Low",
								Status:       "verified",
							},
						},
					},
				},
			},
			"CVE-1999-0003": {
				"source-1": {
					Description: "1999-03 description",
					Severity:    "High",
				},
			},
			"CVE-1999-0004": {
				"source-2": {
					Description: "1999-04 description",
					Severity:    "Critical",
					Cvss: []vulnerability.Cvss{
						{
							Metrics: vulnerability.CvssMetrics{
								BaseScore:           1,
								ExploitabilityScore: ptr(2.0),
								ImpactScore:         ptr(3.0),
							},
							Vector:  "vector",
							Version: "2.0",
							VendorMetadata: MockVendorMetadata{
								BaseSeverity: "Low",
								Status:       "verified",
							},
						},
					},
				},
			},
		},
	}
}

func ptr[T any](t T) *T {
	return &t
}

// VulnerabilityMetadata returns vulnerability metadata for a given id and recordSource.
func (m *MetadataMock) VulnerabilityMetadata(vuln vulnerability.Reference) (*vulnerability.Metadata, error) {
	value := m.store[vuln.ID][vuln.Namespace]
	value.ID = vuln.ID
	value.Namespace = vuln.Namespace
	return &value, nil
}
