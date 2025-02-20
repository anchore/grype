package v6

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/internal/schemaver"
)

func TestReadImportMetadata(t *testing.T) {
	tests := []struct {
		name           string
		fileContent    string
		emptyFile      bool
		expectedErr    string
		expectedResult *ImportMetadata
	}{
		{
			name:        "file does not exist",
			fileContent: "",
		},
		{
			name:      "empty file",
			emptyFile: true,
		},
		{
			name:        "invalid json",
			fileContent: "invalid json",
			expectedErr: "failed to unmarshal import metadata",
		},
		{
			name:        "missing checksum prefix",
			fileContent: `{"digest": "invalid", "client_version": "1.0.0"}`,
			expectedErr: "import metadata digest is not in the expected format",
		},
		{
			name:        "valid metadata",
			fileContent: `{"digest": "xxh64:testdigest", "client_version": "1.0.0"}`,
			expectedResult: &ImportMetadata{
				Digest:        "xxh64:testdigest",
				ClientVersion: "1.0.0",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			filePath := filepath.Join(dir, ImportMetadataFileName)

			if tt.fileContent != "" {
				err := os.WriteFile(filePath, []byte(tt.fileContent), 0644)
				require.NoError(t, err)
			} else if tt.emptyFile {
				_, err := os.Create(filePath)
				require.NoError(t, err)
			}

			result, err := ReadImportMetadata(afero.NewOsFs(), dir)

			if tt.expectedErr != "" {
				require.ErrorContains(t, err, tt.expectedErr)
				require.Nil(t, result)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.expectedResult, result)
			}
		})
	}
}

func TestWriteImportMetadata(t *testing.T) {
	cases := []struct {
		name            string
		checksum        string
		expectedVersion string
		wantErr         require.ErrorAssertionFunc
	}{
		{
			name:            "valid checksum",
			checksum:        "xxh64:testdigest",
			expectedVersion: schemaver.New(ModelVersion, Revision, Addition).String(),
			wantErr:         require.NoError,
		},
		{
			name:     "empty checksum",
			checksum: "",
			wantErr:  require.Error,
		},
		{
			name:     "missing prefix",
			checksum: "testdigest",
			wantErr:  require.Error,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			claim, err := writeImportMetadata(&buf, tc.checksum)
			tc.wantErr(t, err)

			if err == nil {
				result := buf.String()

				var doc ImportMetadata
				err := json.Unmarshal([]byte(result), &doc)
				require.NoError(t, err)

				assert.Equal(t, tc.checksum, doc.Digest)
				assert.Equal(t, tc.checksum, claim.Digest)
				assert.Equal(t, tc.expectedVersion, doc.ClientVersion)
				assert.Equal(t, tc.expectedVersion, claim.ClientVersion)
			}
		})
	}
}

func TestCalculateDBDigest(t *testing.T) {
	tests := []struct {
		name           string
		fileContent    string
		expectedErr    string
		expectedDigest string
	}{
		{
			name:        "file does not exist",
			fileContent: "",
			expectedErr: "failed to digest DB file",
		},
		{
			name:           "valid file",
			fileContent:    "testcontent",
			expectedDigest: "xxh64:d37ed71e4fee2ebd",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			filePath := filepath.Join(dir, VulnerabilityDBFileName)

			if tt.fileContent != "" {
				err := os.WriteFile(filePath, []byte(tt.fileContent), 0644)
				require.NoError(t, err)
			}

			digest, err := CalculateDBDigest(afero.NewOsFs(), filePath)

			if tt.expectedErr != "" {
				require.ErrorContains(t, err, tt.expectedErr)
				require.Empty(t, digest)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.expectedDigest, digest)
			}
		})
	}
}
