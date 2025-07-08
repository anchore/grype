package data

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/grype/grype/vulnerability"
	v6 "github.com/anchore/grype/internal/db/v5"
)

var _ v6.VulnerabilityMetadataStoreReader = (*mockReader)(nil)

type mockReader struct {
	metadata *v6.VulnerabilityMetadata
	err      error
}

func newMockReader(sev string) *mockReader {
	return &mockReader{
		metadata: &v6.VulnerabilityMetadata{
			Severity:  sev,
			Namespace: "nvd",
		},
	}
}

func newDeadMockReader() *mockReader {
	return &mockReader{
		err: errors.New("dead"),
	}
}

func (m mockReader) GetVulnerabilityMetadata(_, _ string) (*v6.VulnerabilityMetadata, error) {
	return m.metadata, m.err
}

func (m mockReader) GetAllVulnerabilityMetadata() (*[]v6.VulnerabilityMetadata, error) {
	panic("implement me")
}

func Test_normalizeSeverity(t *testing.T) {

	tests := []struct {
		name            string
		initialSeverity string
		namespace       string
		cveID           string
		reader          v6.VulnerabilityMetadataStoreReader
		expected        vulnerability.Severity
	}{
		{
			name:            "missing severity set to Unknown",
			initialSeverity: "",
			namespace:       "test",
			reader:          &mockReader{},
			expected:        vulnerability.UnknownSeverity,
		},
		{
			name:            "non-cve records metadata missing severity set to Unknown",
			cveID:           "GHSA-1234-1234-1234",
			initialSeverity: "",
			namespace:       "test",
			reader:          newDeadMockReader(), // should not be used
			expected:        vulnerability.UnknownSeverity,
		},
		{
			name:            "non-cve records metadata with severity set should not be overriden",
			cveID:           "GHSA-1234-1234-1234",
			initialSeverity: "high",
			namespace:       "test",
			reader:          newMockReader("critical"), // should not be used
			expected:        vulnerability.HighSeverity,
		},
		{
			name:            "override empty severity from NVD",
			initialSeverity: "",
			namespace:       "test",
			reader:          newMockReader("low"),
			expected:        vulnerability.LowSeverity,
		},
		{
			name:            "override unknown severity from NVD",
			initialSeverity: "unknown",
			namespace:       "test",
			reader:          newMockReader("low"),
			expected:        vulnerability.LowSeverity,
		},
		{
			name:            "ignore record with severity already set",
			initialSeverity: "Low",
			namespace:       "test",
			reader:          newMockReader("critical"), // should not be used
			expected:        vulnerability.LowSeverity,
		},
		{
			name:            "ignore nvd records",
			initialSeverity: "Low",
			namespace:       "nvdv2:cves",
			reader:          newDeadMockReader(), // should not be used
			expected:        vulnerability.LowSeverity,
		},
		{
			name:            "db errors should not fail or modify the record other than normalizing unset value",
			initialSeverity: "",
			namespace:       "test",
			reader:          newDeadMockReader(),
			expected:        vulnerability.UnknownSeverity,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			record := &v6.VulnerabilityMetadata{
				ID:        "cve-2020-0000",
				Severity:  tt.initialSeverity,
				Namespace: tt.namespace,
			}
			if tt.cveID != "" {
				record.ID = tt.cveID
			}
			normalizeSeverity(record, tt.reader)
			assert.Equal(t, tt.expected.String(), record.Severity)
		})
	}
}
