package msrc

import (
	"os"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/db/data"
	"github.com/anchore/grype/grype/db/internal/provider/unmarshal"
	"github.com/anchore/grype/grype/db/internal/testutil"
	"github.com/anchore/grype/grype/db/provider"
	db "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/build/internal/transformers"
)

func TestUnmarshalMsrcVulnerabilities(t *testing.T) {
	f, err := os.Open("test-fixtures/microsoft-msrc-0.json")
	require.NoError(t, err)
	defer testutil.CloseFile(f)

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
			DBSchemaVersion: db.ModelVersion,
			Data: transformers.RelatedEntries{
				VulnerabilityHandle: &db.VulnerabilityHandle{
					Name:       "CVE-2019-0671",
					ProviderID: "msrc",
					Provider: &db.Provider{
						ID:           "msrc",
						Version:      "1",
						DateCaptured: &x,
					},
					Status: db.VulnerabilityActive,
					BlobValue: &db.VulnerabilityBlob{
						ID:          "CVE-2019-0671",
						Description: "Microsoft Office Access Connectivity Engine Remote Code Execution Vulnerability",
						References: []db.Reference{
							{
								URL: "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-0671",
							},
						},
						Severities: []db.Severity{
							{
								Scheme: db.SeveritySchemeCHML,
								Value:  "high",
							},
							{
								Scheme: db.SeveritySchemeCVSS,
								Value: db.CVSSSeverity{
									Vector:  "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H/E:P/RL:O/RC:C",
									Version: "3.0",
								},
							},
						},
					},
				},
				Related: []any{
					db.AffectedPackageHandle{
						Package: &db.Package{
							Name:      "10852",
							Ecosystem: "msrc-kb",
						},
						BlobValue: &db.PackageBlob{
							Ranges: []db.Range{
								{
									Version: db.Version{
										Type:       "kb",
										Constraint: `4480961 || 4483229 || 4487026 || 4489882 || base`,
									},
									Fix: &db.Fix{
										Version: "4516044",
										State:   db.FixedStatus,
										Detail: &db.FixDetail{
											Available: &db.FixAvailability{
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
			DBSchemaVersion: db.ModelVersion,
			Data: transformers.RelatedEntries{
				VulnerabilityHandle: &db.VulnerabilityHandle{
					Name:       "CVE-2018-8116",
					ProviderID: "msrc",
					Provider: &db.Provider{
						ID:           "msrc",
						Version:      "1",
						DateCaptured: &x,
					},
					Status: db.VulnerabilityActive,
					BlobValue: &db.VulnerabilityBlob{
						ID:          "CVE-2018-8116",
						Description: "Microsoft Graphics Component Denial of Service Vulnerability",
						References: []db.Reference{
							{
								URL: "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-8116",
							},
						},
						Severities: []db.Severity{
							{
								Scheme: db.SeveritySchemeCHML,
								Value:  "medium",
							},
							{
								Scheme: db.SeveritySchemeCVSS,
								Value: db.CVSSSeverity{
									Vector:  "CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:U/C:N/I:N/A:H/E:P/RL:O/RC:C",
									Version: "3.0",
								},
							},
						},
					},
				},
				Related: []any{
					db.AffectedPackageHandle{
						Package: &db.Package{
							Name:      "10852",
							Ecosystem: "msrc-kb",
						},
						BlobValue: &db.PackageBlob{
							Ranges: []db.Range{
								{
									Version: db.Version{
										Type:       "kb",
										Constraint: `3213986 || 4013429 || 4015217 || 4019472 || 4022715 || 4025339 || 4034658 || 4038782 || 4041691 || 4048953 || 4053579 || 4056890 || 4074590 || 4088787 || base`,
									},
									Fix: &db.Fix{
										Version: "4345418",
										State:   db.FixedStatus,
										Detail: &db.FixDetail{
											Available: &db.FixAvailability{
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
	defer testutil.CloseFile(f)

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
