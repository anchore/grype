package v6

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOperatingSystemAlias_VersionMutualExclusivity(t *testing.T) {
	db := setupTestStore(t).db

	msg := "cannot have both version and version_pattern set"

	tests := []struct {
		name   string
		input  *OperatingSystemAlias
		errMsg string
	}{
		{
			name: "version and version_pattern are mutually exclusive",
			input: &OperatingSystemAlias{
				Alias:          "ubuntu",
				Version:        "20.04",
				VersionPattern: "20.*",
			},
			errMsg: msg,
		},
		{
			name: "only version is set",
			input: &OperatingSystemAlias{
				Alias:   "ubuntu",
				Version: "20.04",
			},
			errMsg: "",
		},
		{
			name: "only version_pattern is set",
			input: &OperatingSystemAlias{
				Alias:          "ubuntu",
				VersionPattern: "20.*",
			},
			errMsg: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := db.Create(tt.input).Error
			if tt.errMsg == "" {
				assert.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			}
		})
	}
}
