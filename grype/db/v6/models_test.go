package v6

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOperatingSystem_LabelVersionMutualExclusivity(t *testing.T) {
	msg := "cannot have both label_version and major_version/minor_version set"
	db := setupTestStore(t).db

	tests := []struct {
		name   string
		input  *OperatingSystem
		errMsg string
	}{
		{
			name: "label version and major version are mutually exclusive",
			input: &OperatingSystem{
				Name:         "ubuntu",
				MajorVersion: "20",
				LabelVersion: "something",
			},
			errMsg: msg,
		},
		{
			name: "label version and major.minor version are mutually exclusive",
			input: &OperatingSystem{
				Name:         "ubuntu",
				MajorVersion: "20",
				MinorVersion: "04",
				LabelVersion: "something",
			},
			errMsg: msg,
		},
		{
			name: "label version and minor version are mutually exclusive",
			input: &OperatingSystem{
				Name:         "ubuntu",
				MinorVersion: "04",
				LabelVersion: "something",
			},
			errMsg: msg,
		},
		{
			name: "label version set",
			input: &OperatingSystem{
				Name:         "ubuntu",
				LabelVersion: "something",
			},
		},
		{
			name: "major/minor version set",
			input: &OperatingSystem{
				Name:         "ubuntu",
				MajorVersion: "20",
				MinorVersion: "04",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := db.Create(tt.input).Error
			if tt.errMsg == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.errMsg)
		})
	}
}

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
				Name:           "ubuntu",
				Version:        "20.04",
				VersionPattern: "20.*",
			},
			errMsg: msg,
		},
		{
			name: "only version is set",
			input: &OperatingSystemAlias{
				Name:    "ubuntu",
				Version: "20.04",
			},
			errMsg: "",
		},
		{
			name: "only version_pattern is set",
			input: &OperatingSystemAlias{
				Name:           "ubuntu",
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
