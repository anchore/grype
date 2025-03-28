package cvss

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/vulnerability"
)

func TestParseMetricsFromVector(t *testing.T) {
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
			result, err := ParseMetricsFromVector(tt.vector)
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

func ptr(f float64) *float64 {
	return &f
}
