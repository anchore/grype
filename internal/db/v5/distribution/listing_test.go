package distribution

import (
	"net/url"
	"testing"
	"time"

	"github.com/go-test/deep"
	"github.com/spf13/afero"
)

func mustUrl(u *url.URL, err error) *url.URL {
	if err != nil {
		panic(err)
	}
	return u
}

func TestNewListingFromPath(t *testing.T) {
	tests := []struct {
		fixture  string
		expected Listing
		err      bool
	}{
		{
			fixture: "test-fixtures/listing.json",
			expected: Listing{
				Available: map[int][]ListingEntry{
					1: {
						{
							Built:    time.Date(2020, 06, 12, 16, 12, 12, 0, time.UTC),
							URL:      mustUrl(url.Parse("http://localhost:5000/vulnerability-db-v0.2.0+2020-6-12.tar.gz")),
							Version:  1,
							Checksum: "sha256:e20c251202948df7f853ddc812f64826bdcd6a285c839a7c65939e68609dfc6e",
						},
					},
					2: {
						{
							Built:    time.Date(2020, 06, 13, 17, 13, 13, 0, time.UTC),
							URL:      mustUrl(url.Parse("http://localhost:5000/vulnerability-db-v1.1.0+2020-6-13.tar.gz")),
							Version:  2,
							Checksum: "sha256:dcd6a285c839a7c65939e20c251202912f64826be68609dfc6e48df7f853ddc8",
						},
					},
				},
			},
		},
		{
			fixture: "test-fixtures/listing-sorted.json",
			expected: Listing{
				Available: map[int][]ListingEntry{
					1: {
						{
							Built:    time.Date(2020, 06, 13, 17, 13, 13, 0, time.UTC),
							URL:      mustUrl(url.Parse("http://localhost:5000/vulnerability-db_v1_2020-6-13.tar.gz")),
							Version:  1,
							Checksum: "sha256:dcd6a285c839a7c65939e20c251202912f64826be68609dfc6e48df7f853ddc8",
						},
						{
							Built:    time.Date(2020, 06, 12, 16, 12, 12, 0, time.UTC),
							URL:      mustUrl(url.Parse("http://localhost:5000/vulnerability-db_v1_2020-6-12.tar.gz")),
							Version:  1,
							Checksum: "sha256:e20c251202948df7f853ddc812f64826bdcd6a285c839a7c65939e68609dfc6e",
						},
					},
				},
			},
		},
		{
			fixture: "test-fixtures/listing-unsorted.json",
			expected: Listing{
				Available: map[int][]ListingEntry{
					1: {
						{
							Built:    time.Date(2020, 06, 13, 17, 13, 13, 0, time.UTC),
							URL:      mustUrl(url.Parse("http://localhost:5000/vulnerability-db_v1_2020-6-13.tar.gz")),
							Version:  1,
							Checksum: "sha256:dcd6a285c839a7c65939e20c251202912f64826be68609dfc6e48df7f853ddc8",
						},
						{
							Built:    time.Date(2020, 06, 12, 16, 12, 12, 0, time.UTC),
							URL:      mustUrl(url.Parse("http://localhost:5000/vulnerability-db_v1_2020-6-12.tar.gz")),
							Version:  1,
							Checksum: "sha256:e20c251202948df7f853ddc812f64826bdcd6a285c839a7c65939e68609dfc6e",
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.fixture, func(t *testing.T) {
			listing, err := NewListingFromFile(afero.NewOsFs(), test.fixture)
			if err != nil && !test.err {
				t.Fatalf("failed to get metadata: %+v", err)
			} else if err == nil && test.err {
				t.Fatalf("expected errer but got none")
			}

			for _, diff := range deep.Equal(listing, test.expected) {
				t.Errorf("listing difference: %s", diff)
			}
		})
	}
}

func TestListingBestUpdate(t *testing.T) {
	tests := []struct {
		fixture    string
		constraint int
		expected   *ListingEntry
	}{
		{
			fixture:    "test-fixtures/listing.json",
			constraint: 2,
			expected: &ListingEntry{
				Built:    time.Date(2020, 06, 13, 17, 13, 13, 0, time.UTC),
				URL:      mustUrl(url.Parse("http://localhost:5000/vulnerability-db-v1.1.0+2020-6-13.tar.gz")),
				Version:  2,
				Checksum: "sha256:dcd6a285c839a7c65939e20c251202912f64826be68609dfc6e48df7f853ddc8",
			},
		},
		{
			fixture:    "test-fixtures/listing.json",
			constraint: 1,
			expected: &ListingEntry{
				Built:    time.Date(2020, 06, 12, 16, 12, 12, 0, time.UTC),
				URL:      mustUrl(url.Parse("http://localhost:5000/vulnerability-db-v0.2.0+2020-6-12.tar.gz")),
				Version:  1,
				Checksum: "sha256:e20c251202948df7f853ddc812f64826bdcd6a285c839a7c65939e68609dfc6e",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.fixture, func(t *testing.T) {
			listing, err := NewListingFromFile(afero.NewOsFs(), test.fixture)
			if err != nil {
				t.Fatalf("failed to get metadata: %+v", err)
			}

			actual := listing.BestUpdate(test.constraint)
			if actual == nil && test.expected != nil || actual != nil && test.expected == nil {
				t.Fatalf("mismatched best candidate expectations")
			}

			for _, diff := range deep.Equal(actual, test.expected) {
				t.Errorf("listing entry difference: %s", diff)
			}
		})
	}
}
