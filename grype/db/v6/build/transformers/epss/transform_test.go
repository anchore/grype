package epss

import (
	"os"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/db/internal/tests"
	"github.com/anchore/grype/grype/db/provider"
	"github.com/anchore/grype/grype/db/provider/unmarshal"
	grypeDB "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/build/transformers"
	"github.com/anchore/grype/grype/db/v6/build/transformers/internal"
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
						ID:           "epss",
						Version:      "12",
						Processor:    "vunnel@1.2.3",
						DateCaptured: &timeVal,
						InputDigest:  "sha256:123456",
					},
					Related: epssSlice(
						grypeDB.EpssHandle{
							Cve:        "CVE-2025-0108",
							Epss:       0.328,
							Percentile: 0.9929,
							Date:       *internal.ParseTime("2025-02-18"),
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
					Provider:  "epss",
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

func epssSlice(a ...grypeDB.EpssHandle) []any {
	var r []any
	for _, v := range a {
		r = append(r, v)
	}
	return r
}

func loadFixture(t *testing.T, fixturePath string) []unmarshal.EPSS {
	t.Helper()

	f, err := os.Open(fixturePath)
	require.NoError(t, err)
	defer tests.CloseFile(f)

	entries, err := unmarshal.EPSSEntries(f)
	require.NoError(t, err)
	return entries
}
