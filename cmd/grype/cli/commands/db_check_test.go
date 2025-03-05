package commands

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	db "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/distribution"
	"github.com/anchore/grype/internal/schemaver"
)

func TestPresentNewDBCheck(t *testing.T) {
	currentDB := &db.Description{
		SchemaVersion: schemaver.New(6, 0, 0),
		Built:         db.Time{Time: time.Date(2023, 11, 25, 12, 0, 0, 0, time.UTC)},
	}

	candidateDB := &distribution.Archive{
		Description: db.Description{
			SchemaVersion: schemaver.New(6, 0, 1),
			Built:         db.Time{Time: time.Date(2023, 11, 26, 12, 0, 0, 0, time.UTC)},
		},
		Path:     "vulnerability-db_6.0.1_2023-11-26T12:00:00Z_6238463.tar.gz",
		Checksum: "sha256:1234561234567890345674561234567890345678",
	}
	tests := []struct {
		name            string
		format          string
		updateAvailable bool
		current         *db.Description
		candidate       *distribution.Archive
		expectedText    string
		expectErr       require.ErrorAssertionFunc
	}{
		{
			name:            "text format with update available",
			format:          textOutputFormat,
			updateAvailable: true,
			current:         currentDB,
			candidate:       candidateDB,
			expectedText: `
Installed DB version v6.0.0 was built on 2023-11-25T12:00:00Z
Updated DB version v6.0.1 was built on 2023-11-26T12:00:00Z
You can run 'grype db update' to update to the latest db
`,
		},
		{
			name:            "text format without update available",
			format:          textOutputFormat,
			updateAvailable: false,
			current:         currentDB,
			candidate:       nil,
			expectedText: `
Installed DB version v6.0.0 was built on 2023-11-25T12:00:00Z
No update available
`,
		},
		{
			name:            "json format with update available",
			format:          jsonOutputFormat,
			updateAvailable: true,
			current:         currentDB,
			candidate:       candidateDB,
			expectedText: `
{
 "currentDB": {
  "schemaVersion": "v6.0.0",
  "built": "2023-11-25T12:00:00Z"
 },
 "candidateDB": {
  "schemaVersion": "v6.0.1",
  "built": "2023-11-26T12:00:00Z",
  "path": "vulnerability-db_6.0.1_2023-11-26T12:00:00Z_6238463.tar.gz",
  "checksum": "sha256:1234561234567890345674561234567890345678"
 },
 "updateAvailable": true
}
`,
		},
		{
			name:            "json format without update available",
			format:          jsonOutputFormat,
			updateAvailable: false,
			current:         currentDB,
			candidate:       nil,
			expectedText: `
{
 "currentDB": {
  "schemaVersion": "v6.0.0",
  "built": "2023-11-25T12:00:00Z"
 },
 "candidateDB": null,
 "updateAvailable": false
}
`,
		},
		{
			name:      "unsupported format",
			format:    "xml",
			expectErr: requireErrorContains("unsupported output format: xml"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.expectErr == nil {
				tt.expectErr = require.NoError
			}
			buf := &bytes.Buffer{}
			err := presentNewDBCheck(tt.format, buf, tt.updateAvailable, tt.current, tt.candidate)

			tt.expectErr(t, err)
			if err != nil {
				return
			}

			assert.Equal(t, strings.TrimSpace(tt.expectedText), strings.TrimSpace(buf.String()))
		})
	}
}

func requireErrorContains(expected string) require.ErrorAssertionFunc {
	return func(t require.TestingT, err error, msgAndArgs ...interface{}) {
		require.Error(t, err)
		assert.Contains(t, err.Error(), expected)
	}
}
