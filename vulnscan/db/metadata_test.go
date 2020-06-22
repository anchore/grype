package db

import (
	"testing"
	"time"

	"github.com/go-test/deep"
	"github.com/hashicorp/go-version"
	"github.com/spf13/afero"
)

func TestMetadataParse(t *testing.T) {
	tests := []struct {
		fixture  string
		expected Metadata
		err      bool
	}{
		{
			fixture: "test-fixtures/metadata-gocase",
			expected: Metadata{
				Built:    time.Date(2020, 06, 15, 14, 02, 36, 0, time.UTC),
				Version:  version.Must(version.NewVersion("0.2.0")),
				Checksum: "sha256:dcd6a285c839a7c65939e20c251202912f64826be68609dfc6e48df7f853ddc8",
			},
		},
		{
			fixture: "test-fixtures/metadata-edt-timezone",
			expected: Metadata{
				Built:    time.Date(2020, 06, 15, 18, 02, 36, 0, time.UTC),
				Version:  version.Must(version.NewVersion("0.2.0")),
				Checksum: "sha256:dcd6a285c839a7c65939e20c251202912f64826be68609dfc6e48df7f853ddc8",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.fixture, func(t *testing.T) {
			metadata, err := newMetadataFromDir(afero.NewOsFs(), test.fixture)
			if err != nil && !test.err {
				t.Fatalf("failed to get metadata: %+v", err)
			} else if err == nil && test.err {
				t.Fatalf("expected errer but got none")
			}

			if metadata == nil {
				t.Fatalf("metadata not found: %+v", test.fixture)
			}

			for _, diff := range deep.Equal(*metadata, test.expected) {
				t.Errorf("metadata difference: %s", diff)
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
				Version: version.Must(version.NewVersion("0.2.0")),
			},
			update: &ListingEntry{
				Built:   time.Date(2020, 06, 13, 17, 13, 13, 0, time.UTC),
				Version: version.Must(version.NewVersion("0.3.0")),
			},
		},
		{
			name:                "prefer later dates when version is the same",
			expectedToSupercede: false,
			current: &Metadata{
				Built:   time.Date(2020, 06, 15, 14, 02, 36, 0, time.UTC),
				Version: version.Must(version.NewVersion("1.1.0")),
			},
			update: &ListingEntry{
				Built:   time.Date(2020, 06, 13, 17, 13, 13, 0, time.UTC),
				Version: version.Must(version.NewVersion("1.1.0")),
			},
		},
		{
			name:                "prefer something over nothing",
			expectedToSupercede: true,
			current:             nil,
			update: &ListingEntry{
				Built:   time.Date(2020, 06, 13, 17, 13, 13, 0, time.UTC),
				Version: version.Must(version.NewVersion("1.1.0")),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := test.current.isSupercededBy(test.update)

			if test.expectedToSupercede != actual {
				t.Errorf("failed supercede assertion: got %+v", actual)
			}
		})
	}
}
