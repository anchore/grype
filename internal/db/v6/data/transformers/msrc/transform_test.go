package msrc

import (
	"os"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/db/data"
	"github.com/anchore/grype/grype/db/data/provider"
	"github.com/anchore/grype/internal/db/data/unmarshal"
	v6 "github.com/anchore/grype/internal/db/v6"
	"github.com/anchore/grype/internal/db/v6/data/transformers"
)

func TestUnmarshalMsrcVulnerabilities(t *testing.T) {
	f, err := os.Open("test-fixtures/microsoft-msrc-0.json")
	require.NoError(t, err)
	defer func() {
		require.NoError(t, f.Close())
	}()

	entries, err := unmarshal.MSRCVulnerabilityEntries(f)
	require.NoError(t, err)

	assert.Equal(t, len(entries), 2)
}

func TestParseMSRCEntry(t *testing.T) {
	x := time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)

	providerState := provider.State{
		Provider:            "msrc",
		Version:             1,
		DistributionVersion: 0,
		Processor:           "",
		Schema:              provider.Schema{},
		URLs:                nil,
		Timestamp:           x,
		Listing:             nil,
		Store:               "",
		Stale:               false,
	}

	expectedVulns := []data.Entry{
		{
			DBSchemaVersion: v6.ModelVersion,
			Data: transformers.RelatedEntries{
				VulnerabilityHandle: &v6.VulnerabilityHandle{
					Name:       "CVE-2019-0671",
					ProviderID: "msrc",
					Provider: &v6.Provider{
						ID:           "msrc",
						Version:      "1",
						DateCaptured: &x,
					},
					Status: v6.VulnerabilityActive,
					BlobValue: &v6.VulnerabilityBlob{
						ID:          "CVE-2019-0671",
						Description: "Microsoft Office Access Connectivity Engine Remote Code Execution Vulnerability",
						References: []v6.Reference{
							{
								URL: "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-0671",
							},
						},
						Severities: []v6.Severity{
							{
								Scheme: v6.SeveritySchemeCHML,
								Value:  "high",
							},
							{
								Scheme: v6.SeveritySchemeCVSS,
								Value: v6.CVSSSeverity{
									Vector:  "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H/E:P/RL:O/RC:C",
									Version: "3.0",
								},
							},
						},
					},
				},
				Related: []any{
					v6.AffectedPackageHandle{
						Package: &v6.Package{
							Name:      "10852",
							Ecosystem: "msrc-kb",
						},
						BlobValue: &v6.AffectedPackageBlob{
							Ranges: []v6.AffectedRange{
								{
									Version: v6.AffectedVersion{
										Type:       "kb",
										Constraint: `4480961 || 4483229 || 4487026 || 4489882 || base`,
									},
									Fix: &v6.Fix{
										Version: "4516044",
										State:   v6.FixedStatus,
									},
								},
							},
						},
					},
				},
			},
		},
		{
			DBSchemaVersion: v6.ModelVersion,
			Data: transformers.RelatedEntries{
				VulnerabilityHandle: &v6.VulnerabilityHandle{
					Name:       "CVE-2018-8116",
					ProviderID: "msrc",
					Provider: &v6.Provider{
						ID:           "msrc",
						Version:      "1",
						DateCaptured: &x,
					},
					Status: v6.VulnerabilityActive,
					BlobValue: &v6.VulnerabilityBlob{
						ID:          "CVE-2018-8116",
						Description: "Microsoft Graphics Component Denial of Service Vulnerability",
						References: []v6.Reference{
							{
								URL: "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-8116",
							},
						},
						Severities: []v6.Severity{
							{
								Scheme: v6.SeveritySchemeCHML,
								Value:  "medium",
							},
							{
								Scheme: v6.SeveritySchemeCVSS,
								Value: v6.CVSSSeverity{
									Vector:  "CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:U/C:N/I:N/A:H/E:P/RL:O/RC:C",
									Version: "3.0",
								},
							},
						},
					},
				},
				Related: []any{
					v6.AffectedPackageHandle{
						Package: &v6.Package{
							Name:      "10852",
							Ecosystem: "msrc-kb",
						},
						BlobValue: &v6.AffectedPackageBlob{
							Ranges: []v6.AffectedRange{
								{
									Version: v6.AffectedVersion{
										Type:       "kb",
										Constraint: `3213986 || 4013429 || 4015217 || 4019472 || 4022715 || 4025339 || 4034658 || 4038782 || 4041691 || 4048953 || 4053579 || 4056890 || 4074590 || 4088787 || base`,
									},
									Fix: &v6.Fix{
										Version: "4345418",
										State:   v6.FixedStatus,
									},
								},
							},
						},
					},
				},
			},
		},
	}

	f, err := os.Open("test-fixtures/microsoft-msrc-0.json")
	require.NoError(t, err)
	defer func() {
		require.NoError(t, f.Close())
	}()

	entries, err := unmarshal.MSRCVulnerabilityEntries(f)
	require.NoError(t, err)
	require.Equal(t, len(entries), 2)

	for idx, entry := range entries {
		dataEntries, err := Transform(entry, providerState)
		require.NoError(t, err)
		require.Len(t, dataEntries, 1, "expected a single data entry to be returned")

		if diff := cmp.Diff(expectedVulns[idx], dataEntries[0]); diff != "" {
			t.Errorf("data entry mismatch (-expected +actual):\n%s", diff)
		}
	}
}
