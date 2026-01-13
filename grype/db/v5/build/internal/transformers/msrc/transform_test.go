package msrc

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/db/internal/provider/unmarshal"
	testUtils "github.com/anchore/grype/grype/db/internal/tests"
	grypeDB "github.com/anchore/grype/grype/db/v5"
)

func TestUnmarshalMsrcVulnerabilities(t *testing.T) {
	f, err := os.Open("test-fixtures/microsoft-msrc-0.json")
	require.NoError(t, err)
	defer testUtils.CloseFile(f)

	entries, err := unmarshal.MSRCVulnerabilityEntries(f)
	require.NoError(t, err)

	assert.Equal(t, len(entries), 2)
}

func TestParseMSRCEntry(t *testing.T) {
	expectedVulns := []struct {
		vulnerability grypeDB.Vulnerability
		metadata      grypeDB.VulnerabilityMetadata
	}{
		{
			vulnerability: grypeDB.Vulnerability{
				ID:                "CVE-2019-0671",
				VersionConstraint: `4480961 || 4483229 || 4487026 || 4489882 || base`,
				VersionFormat:     "kb",
				PackageName:       "10852",
				Namespace:         "msrc:distro:windows:10852",
				Fix: grypeDB.Fix{
					Versions: []string{"4516044"},
					State:    grypeDB.FixedState,
				},
			},
			metadata: grypeDB.VulnerabilityMetadata{
				ID:           "CVE-2019-0671",
				Severity:     "High",
				DataSource:   "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-0671",
				URLs:         []string{"https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-0671"},
				Description:  "",
				RecordSource: "microsoft:msrc:10852",
				Namespace:    "msrc:distro:windows:10852",
				Cvss: []grypeDB.Cvss{
					{
						Metrics: grypeDB.CvssMetrics{
							BaseScore:   7.8,
							ImpactScore: nil,
						},
						Vector: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H/E:P/RL:O/RC:C",
					},
				},
			},
		},
		{
			vulnerability: grypeDB.Vulnerability{
				ID:                "CVE-2018-8116",
				VersionConstraint: `3213986 || 4013429 || 4015217 || 4019472 || 4022715 || 4025339 || 4034658 || 4038782 || 4041691 || 4048953 || 4053579 || 4056890 || 4074590 || 4088787 || base`,
				VersionFormat:     "kb",
				PackageName:       "10852",
				Namespace:         "msrc:distro:windows:10852",
				Fix: grypeDB.Fix{
					Versions: []string{"4345418"},
					State:    grypeDB.FixedState,
				},
			},
			metadata: grypeDB.VulnerabilityMetadata{
				ID:           "CVE-2018-8116",
				Namespace:    "msrc:distro:windows:10852",
				DataSource:   "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-8116",
				RecordSource: "microsoft:msrc:10852",
				Severity:     "Medium",
				URLs:         []string{"https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-8116"},
				Description:  "",
				Cvss: []grypeDB.Cvss{
					{
						Metrics: grypeDB.CvssMetrics{
							BaseScore:   4.4,
							ImpactScore: nil,
						},
						Vector: "CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:U/C:N/I:N/A:H/E:P/RL:O/RC:C",
					},
				},
			},
		},
	}

	f, err := os.Open("test-fixtures/microsoft-msrc-0.json")
	require.NoError(t, err)
	defer testUtils.CloseFile(f)

	entries, err := unmarshal.MSRCVulnerabilityEntries(f)
	require.NoError(t, err)

	assert.Equal(t, len(entries), 2)

	for idx, entry := range entries {
		dataEntries, err := Transform(entry)
		assert.NoError(t, err)
		assert.Len(t, dataEntries, 2)
		expected := expectedVulns[idx]
		for _, entry := range dataEntries {
			switch vuln := entry.Data.(type) {
			case grypeDB.Vulnerability:
				assert.Equal(t, expected.vulnerability, vuln)
			case grypeDB.VulnerabilityMetadata:
				assert.Equal(t, expected.metadata, vuln)
			default:
				t.Fatalf("unexpected condition: data entry does not have a vulnerability or a metadata")
			}
		}
	}
}
