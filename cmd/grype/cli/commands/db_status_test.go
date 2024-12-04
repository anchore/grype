package commands

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	v6 "github.com/anchore/grype/grype/db/v6"
)

func TestPresentDBStatus(t *testing.T) {
	validStatus := v6.Status{
		Path:          "/Users/test/Library/Caches/grype/db/6/vulnerability.db",
		SchemaVersion: "6.0.0",
		Built:         v6.Time{Time: time.Date(2024, 11, 27, 14, 43, 17, 0, time.UTC)},
		Checksum:      "xxh64:89d3ae128f6e718e",
		Err:           nil,
	}

	invalidStatus := v6.Status{
		Path:          "/Users/test/Library/Caches/grype/db/6/vulnerability.db",
		SchemaVersion: "6.0.0",
		Built:         v6.Time{Time: time.Date(2024, 11, 27, 14, 43, 17, 0, time.UTC)},
		Checksum:      "xxh64:89d3ae128f6e718e",
		Err:           errors.New("checksum mismatch"),
	}

	tests := []struct {
		name         string
		format       string
		status       v6.Status
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
Checksum:  xxh64:89d3ae128f6e718e
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
Checksum:  xxh64:89d3ae128f6e718e
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
 "built": "2024-11-27T14:43:17Z",
 "path": "/Users/test/Library/Caches/grype/db/6/vulnerability.db",
 "checksum": "xxh64:89d3ae128f6e718e",
 "error": ""
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
 "built": "2024-11-27T14:43:17Z",
 "path": "/Users/test/Library/Caches/grype/db/6/vulnerability.db",
 "checksum": "xxh64:89d3ae128f6e718e",
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
