package v6

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/vulnerability"
)

func TestExtractSeverity(t *testing.T) {
	tests := []struct {
		name        string
		input       any
		expected    vulnerability.Severity
		expectedErr require.ErrorAssertionFunc
	}{
		{
			name:        "string low severity",
			input:       "low",
			expected:    vulnerability.LowSeverity,
			expectedErr: require.NoError,
		},
		{
			name:        "string high severity",
			input:       "high",
			expected:    vulnerability.HighSeverity,
			expectedErr: require.NoError,
		},
		{
			name:        "string critical severity",
			input:       "critical",
			expected:    vulnerability.CriticalSeverity,
			expectedErr: require.NoError,
		},
		{
			name:        "string unknown severity",
			input:       "invalid",
			expected:    vulnerability.UnknownSeverity,
			expectedErr: require.NoError,
		},
		{
			name: "CVSS v2 low severity",
			input: CVSSSeverity{
				Version: "2.0",
				Vector:  "AV:L/AC:L/Au:N/C:N/I:P/A:N",
			},
			expected:    vulnerability.LowSeverity,
			expectedErr: require.NoError,
		},
		{
			name: "CVSS v2 medium severity",
			input: CVSSSeverity{
				Version: "2.0",
				Vector:  "AV:N/AC:L/Au:N/C:P/I:P/A:N",
			},
			expected:    vulnerability.MediumSeverity,
			expectedErr: require.NoError,
		},
		{
			name: "CVSS v2 high severity",
			input: CVSSSeverity{
				Version: "2.0",
				Vector:  "AV:N/AC:L/Au:N/C:P/I:P/A:P",
			},
			expected:    vulnerability.HighSeverity,
			expectedErr: require.NoError,
		},
		{
			name: "CVSS v3 negligible severity",
			input: CVSSSeverity{
				Version: "3.1",
				Vector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
			},
			expected:    vulnerability.NegligibleSeverity,
			expectedErr: require.NoError,
		},
		{
			name: "CVSS v3 critical severity",
			input: CVSSSeverity{
				Version: "3.1",
				Vector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
			},
			expected:    vulnerability.CriticalSeverity,
			expectedErr: require.NoError,
		},
		{
			name: "CVSS v4 critical severity",
			input: CVSSSeverity{
				Version: "4.0",
				Vector:  "CVSS:4.0/AV:N/AC:H/AT:P/PR:L/UI:N/VC:N/VI:H/VA:L/SC:L/SI:H/SA:L/MAC:L/MAT:P/MPR:N/S:N/R:A/RE:L/U:Clear",
			},
			expected:    vulnerability.CriticalSeverity,
			expectedErr: require.NoError,
		},
		{
			name: "invalid CVSS vector",
			input: CVSSSeverity{
				Version: "3.1",
				Vector:  "INVALID",
			},
			expected:    vulnerability.UnknownSeverity,
			expectedErr: require.Error,
		},
		{
			name:        "invalid type",
			input:       123,
			expected:    vulnerability.UnknownSeverity,
			expectedErr: require.NoError,
		},
		{
			name:        "nil input",
			input:       nil,
			expected:    vulnerability.UnknownSeverity,
			expectedErr: require.NoError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := extractSeverity(tt.input)
			tt.expectedErr(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestParseCVSS(t *testing.T) {
	tests := []struct {
		name            string
		vector          string
		expectedMetrics *vulnerability.CvssMetrics
		wantErr         require.ErrorAssertionFunc
	}{
		{
			name:   "valid CVSS 2.0",
			vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P",
			expectedMetrics: &vulnerability.CvssMetrics{
				BaseScore:           7.5,
				ExploitabilityScore: ptr(10.0),
				ImpactScore:         ptr(6.5),
			},
		},
		{
			name:   "valid CVSS 3.0",
			vector: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			expectedMetrics: &vulnerability.CvssMetrics{
				BaseScore:           9.8,
				ExploitabilityScore: ptr(3.9),
				ImpactScore:         ptr(5.9),
			},
		},
		{
			name:   "valid CVSS 3.1",
			vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			expectedMetrics: &vulnerability.CvssMetrics{
				BaseScore:           9.8,
				ExploitabilityScore: ptr(3.9),
				ImpactScore:         ptr(5.9),
			},
		},
		{
			name:   "valid CVSS 4.0",
			vector: "CVSS:4.0/AV:N/AC:H/AT:P/PR:L/UI:N/VC:N/VI:H/VA:L/SC:L/SI:H/SA:L/MAC:L/MAT:P/MPR:N/S:N/R:A/RE:L/U:Clear",
			expectedMetrics: &vulnerability.CvssMetrics{
				BaseScore: 9.1,
			},
		},
		{
			name:    "invalid CVSS 2.0",
			vector:  "AV:N/AC:INVALID",
			wantErr: require.Error,
		},
		{
			name:    "invalid CVSS 3.0",
			vector:  "CVSS:3.0/AV:INVALID",
			wantErr: require.Error,
		},
		{
			name:    "invalid CVSS 3.1",
			vector:  "CVSS:3.1/AV:INVALID",
			wantErr: require.Error,
		},
		{
			name:    "invalid CVSS 4.0",
			vector:  "CVSS:4.0/AV:INVALID",
			wantErr: require.Error,
		},
		{
			name:    "empty vector",
			vector:  "",
			wantErr: require.Error,
		},
		{
			name:    "malformed vector",
			vector:  "INVALID:VECTOR",
			wantErr: require.Error,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr == nil {
				tt.wantErr = require.NoError
			}
			result, err := parseCVSS(tt.vector)
			tt.wantErr(t, err)
			if err != nil {
				assert.Nil(t, result)
				return
			}

			require.NotNil(t, result)
			assert.Equal(t, tt.expectedMetrics.BaseScore, result.BaseScore, "given vector: %s", tt.vector)

			if tt.expectedMetrics.ExploitabilityScore != nil {
				require.NotNil(t, result.ExploitabilityScore)
				assert.Equal(t, *tt.expectedMetrics.ExploitabilityScore, *result.ExploitabilityScore, "given vector: %s", tt.vector)
			}

			if tt.expectedMetrics.ImpactScore != nil {
				require.NotNil(t, result.ImpactScore)
				assert.Equal(t, *tt.expectedMetrics.ImpactScore, *result.ImpactScore, "given vector: %s", tt.vector)
			}
		})
	}
}

func TestExtractSeverities(t *testing.T) {
	tests := []struct {
		name          string
		input         *VulnerabilityHandle
		expectedSev   vulnerability.Severity
		expectedCVSS  []vulnerability.Cvss
		expectedError require.ErrorAssertionFunc
	}{
		{
			name:          "nil blob",
			input:         &VulnerabilityHandle{BlobValue: nil},
			expectedSev:   vulnerability.UnknownSeverity,
			expectedCVSS:  nil,
			expectedError: require.NoError,
		},
		{
			name: "empty severities",
			input: &VulnerabilityHandle{
				BlobValue: &VulnerabilityBlob{
					Severities: []Severity{},
				},
			},
			expectedSev:   vulnerability.UnknownSeverity,
			expectedCVSS:  nil,
			expectedError: require.NoError,
		},
		{
			name: "valid CVSS severity",
			input: &VulnerabilityHandle{
				BlobValue: &VulnerabilityBlob{
					Severities: []Severity{
						{
							Scheme: SeveritySchemeCVSS,
							Source: "NVD",
							Value: CVSSSeverity{
								Version: "3.1",
								Vector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
							},
						},
					},
				},
			},
			expectedSev: vulnerability.CriticalSeverity,
			expectedCVSS: []vulnerability.Cvss{
				{
					Source:  "NVD",
					Type:    "CVSS",
					Version: "3.1",
					Vector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
					Metrics: vulnerability.CvssMetrics{
						BaseScore:           9.8,
						ExploitabilityScore: ptr(3.9),
						ImpactScore:         ptr(5.9),
					},
				},
			},
			expectedError: require.NoError,
		},
		{
			name: "invalid CVSS vector",
			input: &VulnerabilityHandle{
				BlobValue: &VulnerabilityBlob{
					Severities: []Severity{
						{
							Scheme: SeveritySchemeCVSS,
							Value: CVSSSeverity{
								Version: "3.1",
								Vector:  "INVALID",
							},
						},
					},
				},
			},
			expectedSev:   vulnerability.UnknownSeverity,
			expectedCVSS:  nil,
			expectedError: require.Error,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.expectedError == nil {
				tt.expectedError = require.NoError
			}
			sev, cvss, err := extractSeverities(tt.input)
			tt.expectedError(t, err)
			assert.Equal(t, tt.expectedSev, sev)
			assert.Equal(t, tt.expectedCVSS, cvss)
		})
	}
}
