package kev

import (
	"os"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/db/internal/provider/unmarshal"
	"github.com/anchore/grype/grype/db/provider"
	grypeDB "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/build/internal/tests"
	"github.com/anchore/grype/grype/db/v6/build/internal/transformers"
	"github.com/anchore/grype/grype/db/v6/build/internal/transformers/internal"
)

func TestTransform(t *testing.T) {

	var timeVal = time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)
	var listing = provider.File{
		Path:      "some",
		Digest:    "123456",
		Algorithm: "sha256",
	}

	tests := []struct {
		name string
		want []transformers.RelatedEntries
	}{
		{
			name: "test-fixtures/go-case.json",
			want: []transformers.RelatedEntries{
				{
					Provider: &grypeDB.Provider{
						ID:           "kev",
						Version:      "12",
						Processor:    "vunnel@1.2.3",
						DateCaptured: &timeVal,
						InputDigest:  "sha256:123456",
					},
					Related: kevSlice(
						grypeDB.KnownExploitedVulnerabilityHandle{
							Cve: "CVE-2025-0108",
							BlobValue: &grypeDB.KnownExploitedVulnerabilityBlob{
								Cve:                        "CVE-2025-0108",
								VendorProject:              "Palo Alto Networks",
								Product:                    "PAN-OS",
								DateAdded:                  internal.ParseTime("2025-02-18"),
								RequiredAction:             "Apply mitigations per vendor instructions [https://www.vendor.com/instructions] or discontinue use of the product if mitigations are unavailable [https://www.vendor.com/something-else].",
								DueDate:                    internal.ParseTime("2025-03-11"),
								KnownRansomwareCampaignUse: "unknown",
								Notes:                      "remaining information",
								URLs: []string{
									"https://security.paloaltonetworks.com/CVE-2025-0108",
									"https://nvd.nist.gov/vuln/detail/CVE-2025-0108",
									"https://www.vendor.com/instructions",
									"https://www.vendor.com/something-else",
								},
								CWEs: []string{"CWE-306"},
							},
						},
					),
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			entries := loadFixture(t, test.name)

			var actual []transformers.RelatedEntries
			for _, vuln := range entries {
				entries, err := Transform(vuln, provider.State{
					Provider:  "kev",
					Version:   12,
					Processor: "vunnel@1.2.3",
					Timestamp: timeVal,
					Listing:   &listing,
				})
				require.NoError(t, err)
				for _, entry := range entries {
					e, ok := entry.Data.(transformers.RelatedEntries)
					require.True(t, ok)
					actual = append(actual, e)
				}
			}

			if diff := cmp.Diff(test.want, actual); diff != "" {
				t.Errorf("data entries mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func kevSlice(a ...grypeDB.KnownExploitedVulnerabilityHandle) []any {
	var r []any
	for _, v := range a {
		r = append(r, v)
	}
	return r
}

func loadFixture(t *testing.T, fixturePath string) []unmarshal.KnownExploitedVulnerability {
	t.Helper()

	f, err := os.Open(fixturePath)
	require.NoError(t, err)
	defer tests.CloseFile(f)

	entries, err := unmarshal.KnownExploitedVulnerabilityEntries(f)
	require.NoError(t, err)
	return entries
}
