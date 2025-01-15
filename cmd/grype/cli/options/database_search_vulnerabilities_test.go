package options

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	v6 "github.com/anchore/grype/grype/db/v6"
)

func TestDBSearchVulnerabilitiesPostLoad(t *testing.T) {
	testCases := []struct {
		name           string
		input          DBSearchVulnerabilities
		expectedSpecs  v6.VulnerabilitySpecifiers
		expectedErrMsg string
	}{
		{
			name: "single vulnerability ID",
			input: DBSearchVulnerabilities{
				VulnerabilityIDs: []string{"CVE-2023-0001"},
			},
			expectedSpecs: v6.VulnerabilitySpecifiers{
				{Name: "CVE-2023-0001"},
			},
		},
		{
			name: "multiple vulnerability IDs",
			input: DBSearchVulnerabilities{
				VulnerabilityIDs: []string{"CVE-2023-0001", "GHSA-1234"},
			},
			expectedSpecs: v6.VulnerabilitySpecifiers{
				{Name: "CVE-2023-0001"},
				{Name: "GHSA-1234"},
			},
		},
		{
			name: "published-after set",
			input: DBSearchVulnerabilities{
				PublishedAfter: "2023-01-01",
			},
			expectedSpecs: v6.VulnerabilitySpecifiers{
				{PublishedAfter: parseTime("2023-01-01")},
			},
		},
		{
			name: "modified-after set",
			input: DBSearchVulnerabilities{
				ModifiedAfter: "2023-02-01",
			},
			expectedSpecs: v6.VulnerabilitySpecifiers{
				{ModifiedAfter: parseTime("2023-02-01")},
			},
		},
		{
			name: "both published-after and modified-after set",
			input: DBSearchVulnerabilities{
				PublishedAfter: "2023-01-01",
				ModifiedAfter:  "2023-02-01",
			},
			expectedErrMsg: "only one of --published-after or --modified-after can be set",
		},
		{
			name: "invalid date for published-after",
			input: DBSearchVulnerabilities{
				PublishedAfter: "invalid-date",
			},
			expectedErrMsg: "invalid date format for published-after",
		},
		{
			name: "invalid date for modified-after",
			input: DBSearchVulnerabilities{
				ModifiedAfter: "invalid-date",
			},
			expectedErrMsg: "invalid date format for modified-after",
		},
		{
			name: "vulnerability ID with providers",
			input: DBSearchVulnerabilities{
				VulnerabilityIDs: []string{"CVE-2023-0001"},
				Providers:        []string{"provider1"},
			},
			expectedSpecs: v6.VulnerabilitySpecifiers{
				{Name: "CVE-2023-0001", Providers: []string{"provider1"}},
			},
		},
		{
			name: "providers without vulnerability IDs",
			input: DBSearchVulnerabilities{
				Providers: []string{"provider1", "provider2"},
			},
			expectedSpecs: v6.VulnerabilitySpecifiers{
				{Providers: []string{"provider1", "provider2"}},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.input.PostLoad()

			if tc.expectedErrMsg != "" {
				require.Error(t, err)
				require.ErrorContains(t, err, tc.expectedErrMsg)
				return
			}
			require.NoError(t, err)
			if d := cmp.Diff(tc.expectedSpecs, tc.input.Specs); d != "" {
				t.Errorf("unexpected vulnerability specifiers (-want +got):\n%s", d)
			}
		})
	}
}

func parseTime(value string) *time.Time {
	t, _ := time.Parse("2006-01-02", value)
	return &t
}
