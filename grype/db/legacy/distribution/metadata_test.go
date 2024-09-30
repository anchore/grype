package distribution

import (
	"testing"
	"time"

	"github.com/go-test/deep"
	"github.com/spf13/afero"
)

func TestMetadataParse(t *testing.T) {
	tests := []struct {
		fixture  string
		expected *Metadata
		err      bool
	}{
		{
			fixture: "test-fixtures/metadata-gocase",
			expected: &Metadata{
				Built:    time.Date(2020, 06, 15, 14, 02, 36, 0, time.UTC),
				Version:  2,
				Checksum: "sha256:dcd6a285c839a7c65939e20c251202912f64826be68609dfc6e48df7f853ddc8",
			},
		},
		{
			fixture: "test-fixtures/metadata-edt-timezone",
			expected: &Metadata{
				Built:    time.Date(2020, 06, 15, 18, 02, 36, 0, time.UTC),
				Version:  2,
				Checksum: "sha256:dcd6a285c839a7c65939e20c251202912f64826be68609dfc6e48df7f853ddc8",
			},
		},
		{
			fixture: "/dev/null/impossible",
			err:     true,
		},
	}

	for _, test := range tests {
		t.Run(test.fixture, func(t *testing.T) {
			metadata, err := NewMetadataFromDir(afero.NewOsFs(), test.fixture)
			if err != nil && !test.err {
				t.Fatalf("failed to get metadata: %+v", err)
			} else if err == nil && test.err {
				t.Fatalf("expected error but got none")
			} else if metadata == nil && test.expected != nil {
				t.Fatalf("metadata not found: %+v", test.fixture)
			}

			if metadata != nil && test.expected != nil {
				for _, diff := range deep.Equal(*metadata, *test.expected) {
					t.Errorf("metadata difference: %s", diff)
				}
			}
		})
	}
}

func TestMetadataIsSupercededBy(t *testing.T) {
	tests := []struct {
		name                string
		current             *Metadata
		update              *ListingEntry
		expectedToSupercede bool
	}{
		{
			name:                "prefer updated versions over later dates",
			expectedToSupercede: true,
			current: &Metadata{
				Built:   time.Date(2020, 06, 15, 14, 02, 36, 0, time.UTC),
				Version: 2,
			},
			update: &ListingEntry{
				Built:   time.Date(2020, 06, 13, 17, 13, 13, 0, time.UTC),
				Version: 3,
			},
		},
		{
			name:                "prefer later dates when version is the same",
			expectedToSupercede: false,
			current: &Metadata{
				Built:   time.Date(2020, 06, 15, 14, 02, 36, 0, time.UTC),
				Version: 1,
			},
			update: &ListingEntry{
				Built:   time.Date(2020, 06, 13, 17, 13, 13, 0, time.UTC),
				Version: 1,
			},
		},
		{
			name:                "prefer something over nothing",
			expectedToSupercede: true,
			current:             nil,
			update: &ListingEntry{
				Built:   time.Date(2020, 06, 13, 17, 13, 13, 0, time.UTC),
				Version: 1,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := test.current.IsSupersededBy(test.update)

			if test.expectedToSupercede != actual {
				t.Errorf("failed supercede assertion: got %+v", actual)
			}
		})
	}
}
