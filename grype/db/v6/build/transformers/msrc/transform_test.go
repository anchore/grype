package msrc

import (
	"os"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/db/data"
	testUtils "github.com/anchore/grype/grype/db/internal/tests"
	"github.com/anchore/grype/grype/db/provider"
	"github.com/anchore/grype/grype/db/provider/unmarshal"
	grypeDB "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/build/transformers"
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
			DBSchemaVersion: grypeDB.ModelVersion,
			Data: transformers.RelatedEntries{
				VulnerabilityHandle: &grypeDB.VulnerabilityHandle{
					Name:       "CVE-2019-0671",
					ProviderID: "msrc",
					Provider: &grypeDB.Provider{
						ID:           "msrc",
						Version:      "1",
						DateCaptured: &x,
					},
					Status: grypeDB.VulnerabilityActive,
					BlobValue: &grypeDB.VulnerabilityBlob{
						ID:          "CVE-2019-0671",
						Description: "Microsoft Office Access Connectivity Engine Remote Code Execution Vulnerability",
						References: []grypeDB.Reference{
							{
								URL: "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-0671",
							},
						},
						Severities: []grypeDB.Severity{
							{
								Scheme: grypeDB.SeveritySchemeCHML,
								Value:  "high",
							},
							{
								Scheme: grypeDB.SeveritySchemeCVSS,
								Value: grypeDB.CVSSSeverity{
									Vector:  "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H/E:P/RL:O/RC:C",
									Version: "3.0",
								},
							},
						},
					},
				},
				Related: []any{
					grypeDB.AffectedPackageHandle{
						Package: &grypeDB.Package{
							Name:      "10852",
							Ecosystem: "msrc-kb",
						},
						BlobValue: &grypeDB.PackageBlob{
							Ranges: []grypeDB.Range{
								{
									Version: grypeDB.Version{
										Type:       "kb",
										Constraint: `4480961 || 4483229 || 4487026 || 4489882 || base`,
									},
									Fix: &grypeDB.Fix{
										Version: "4516044",
										State:   grypeDB.FixedStatus,
										Detail: &grypeDB.FixDetail{
											Available: &grypeDB.FixAvailability{
												Date: timePtr(time.Date(2019, 11, 12, 0, 0, 0, 0, time.UTC)),
												Kind: "advisory",
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			DBSchemaVersion: grypeDB.ModelVersion,
			Data: transformers.RelatedEntries{
				VulnerabilityHandle: &grypeDB.VulnerabilityHandle{
					Name:       "CVE-2018-8116",
					ProviderID: "msrc",
					Provider: &grypeDB.Provider{
						ID:           "msrc",
						Version:      "1",
						DateCaptured: &x,
					},
					Status: grypeDB.VulnerabilityActive,
					BlobValue: &grypeDB.VulnerabilityBlob{
						ID:          "CVE-2018-8116",
						Description: "Microsoft Graphics Component Denial of Service Vulnerability",
						References: []grypeDB.Reference{
							{
								URL: "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-8116",
							},
						},
						Severities: []grypeDB.Severity{
							{
								Scheme: grypeDB.SeveritySchemeCHML,
								Value:  "medium",
							},
							{
								Scheme: grypeDB.SeveritySchemeCVSS,
								Value: grypeDB.CVSSSeverity{
									Vector:  "CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:U/C:N/I:N/A:H/E:P/RL:O/RC:C",
									Version: "3.0",
								},
							},
						},
					},
				},
				Related: []any{
					grypeDB.AffectedPackageHandle{
						Package: &grypeDB.Package{
							Name:      "10852",
							Ecosystem: "msrc-kb",
						},
						BlobValue: &grypeDB.PackageBlob{
							Ranges: []grypeDB.Range{
								{
									Version: grypeDB.Version{
										Type:       "kb",
										Constraint: `3213986 || 4013429 || 4015217 || 4019472 || 4022715 || 4025339 || 4034658 || 4038782 || 4041691 || 4048953 || 4053579 || 4056890 || 4074590 || 4088787 || base`,
									},
									Fix: &grypeDB.Fix{
										Version: "4345418",
										State:   grypeDB.FixedStatus,
										Detail: &grypeDB.FixDetail{
											Available: &grypeDB.FixAvailability{
												Date: timePtr(time.Date(2019, 11, 12, 0, 0, 0, 0, time.UTC)),
												Kind: "advisory",
											},
										},
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
	defer testUtils.CloseFile(f)

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

func timePtr(t time.Time) *time.Time {
	return &t
}
