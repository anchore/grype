package commands

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/vulnerability"
)

func TestPresentDBStatus(t *testing.T) {
	validStatus := vulnerability.ProviderStatus{
		Path:          "/Users/test/Library/Caches/grype/db/6/vulnerability.db",
		From:          "https://grype.anchore.io/databases/v6/vulnerability-db_v6.0.2_2025-03-14T01:31:06Z_1741925227.tar.zst?checksum=sha256%3Ad4654e3b212f1d8a1aaab979599691099af541568d687c4a7c4e7c1da079b9b8",
		SchemaVersion: "6.0.0",
		Built:         time.Date(2024, 11, 27, 14, 43, 17, 0, time.UTC),
		Error:         nil,
	}

	invalidStatus := vulnerability.ProviderStatus{
		Path:          "/Users/test/Library/Caches/grype/db/6/vulnerability.db",
		From:          "https://grype.anchore.io/databases/v6/vulnerability-db_v6.0.2_2025-03-14T01:31:06Z_1741925227.tar.zst?checksum=sha256%3Ad4654e3b212f1d8a1aaab979599691099af541568d687c4a7c4e7c1da079b9b8",
		SchemaVersion: "6.0.0",
		Built:         time.Date(2024, 11, 27, 14, 43, 17, 0, time.UTC),
		Error:         errors.New("checksum mismatch"),
	}

	tests := []struct {
		name         string
		format       string
		status       vulnerability.ProviderStatus
		expectedText string
		expectedErr  require.ErrorAssertionFunc
	}{
		{
			name:   "valid status, text format",
			format: textOutputFormat,
			status: validStatus,
			expectedText: `Path:      /Users/test/Library/Caches/grype/db/6/vulnerability.db
Schema:    6.0.0
Built:     2024-11-27T14:43:17Z
From:      https://grype.anchore.io/databases/v6/vulnerability-db_v6.0.2_2025-03-14T01:31:06Z_1741925227.tar.zst?checksum=sha256%3Ad4654e3b212f1d8a1aaab979599691099af541568d687c4a7c4e7c1da079b9b8
Status:    valid
`,
			expectedErr: require.NoError,
		},
		{
			name:   "invalid status, text format",
			format: textOutputFormat,
			status: invalidStatus,
			expectedText: `Path:      /Users/test/Library/Caches/grype/db/6/vulnerability.db
Schema:    6.0.0
Built:     2024-11-27T14:43:17Z
From:      https://grype.anchore.io/databases/v6/vulnerability-db_v6.0.2_2025-03-14T01:31:06Z_1741925227.tar.zst?checksum=sha256%3Ad4654e3b212f1d8a1aaab979599691099af541568d687c4a7c4e7c1da079b9b8
Status:    invalid
`,
			expectedErr: require.NoError,
		},
		{
			name:   "valid status, JSON format",
			format: jsonOutputFormat,
			status: validStatus,
			expectedText: `{
 "schemaVersion": "6.0.0",
 "from": "https://grype.anchore.io/databases/v6/vulnerability-db_v6.0.2_2025-03-14T01:31:06Z_1741925227.tar.zst?checksum=sha256%3Ad4654e3b212f1d8a1aaab979599691099af541568d687c4a7c4e7c1da079b9b8",
 "built": "2024-11-27T14:43:17Z",
 "path": "/Users/test/Library/Caches/grype/db/6/vulnerability.db",
 "valid": true
}
`,
			expectedErr: require.NoError,
		},
		{
			name:   "invalid status, JSON format",
			format: jsonOutputFormat,
			status: invalidStatus,
			expectedText: `{
 "schemaVersion": "6.0.0",
 "from": "https://grype.anchore.io/databases/v6/vulnerability-db_v6.0.2_2025-03-14T01:31:06Z_1741925227.tar.zst?checksum=sha256%3Ad4654e3b212f1d8a1aaab979599691099af541568d687c4a7c4e7c1da079b9b8",
 "built": "2024-11-27T14:43:17Z",
 "path": "/Users/test/Library/Caches/grype/db/6/vulnerability.db",
 "valid": false,
 "error": "checksum mismatch"
}
`,
			expectedErr: require.NoError,
		},
		{
			name:        "unsupported format",
			format:      "unsupported",
			status:      validStatus,
			expectedErr: requireErrorContains("unsupported output format"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.expectedErr == nil {
				tt.expectedErr = require.NoError
			}
			writer := &bytes.Buffer{}

			err := presentDBStatus(tt.format, writer, tt.status)
			tt.expectedErr(t, err)
			if err != nil {
				return
			}

			assert.Equal(t, strings.TrimSpace(tt.expectedText), strings.TrimSpace(writer.String()))
		})
	}
}
