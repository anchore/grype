package models

import "github.com/anchore/grype/grype/vulnerability"

var _ vulnerability.MetadataProvider = (*MetadataMock)(nil)

// MetadataMock provides the behavior required for a vulnerability.MetadataProvider for the purpose of testing.
type MetadataMock struct {
	store map[string]map[string]vulnerability.Metadata
}

// NewMetadataMock returns a new instance of MetadataMock.
func NewMetadataMock() *MetadataMock {
	return &MetadataMock{
		store: map[string]map[string]vulnerability.Metadata{
			"CVE-1999-0001": {
				"source-1": {
					Description: "1999-01 description",
					Severity:    "Low",
					CvssV3: &vulnerability.Cvss{
						BaseScore: 4,
						Vector:    "another vector",
					},
				},
			},
			"CVE-1999-0002": {
				"source-2": {
					Description: "1999-02 description",
					Severity:    "Critical",
					CvssV2: &vulnerability.Cvss{
						BaseScore:           1,
						ExploitabilityScore: 2,
						ImpactScore:         3,
						Vector:              "vector",
					},
				},
			},
			"CVE-1999-0003": {
				"source-1": {
					Description: "1999-03 description",
					Severity:    "High",
				},
			},
		},
	}
}

// GetMetadata returns vulnerability metadata for a given id and recordSource.
func (m *MetadataMock) GetMetadata(id, recordSource string) (*vulnerability.Metadata, error) {
	value := m.store[id][recordSource]
	return &value, nil
}
