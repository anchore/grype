package file

import (
	"fmt"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
)

func TestValidateByHash(t *testing.T) {
	testsCases := []struct {
		name, path, hashStr, actualHash string
		setup                           func(fs afero.Fs)
		valid                           bool
		err                             bool
		errMsg                          error
	}{
		{
			name:    "Valid SHA256 hash",
			path:    "test.txt",
			hashStr: "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
			setup: func(fs afero.Fs) {
				afero.WriteFile(fs, "test.txt", []byte("test"), 0644)
			},
			actualHash: "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
			valid:      true,
			err:        false,
		},
		{
			name:    "Invalid SHA256 hash",
			path:    "test.txt",
			hashStr: "sha256:deadbeef",
			setup: func(fs afero.Fs) {
				afero.WriteFile(fs, "test.txt", []byte("test"), 0644)
			},
			actualHash: "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
			valid:      false,
			err:        false,
		},
		{
			name:    "Unsupported hash function",
			path:    "test.txt",
			hashStr: "md5:deadbeef",
			setup: func(fs afero.Fs) {
				afero.WriteFile(fs, "test.txt", []byte("test"), 0644)
			},
			actualHash: "",
			valid:      false,
			err:        true,
			errMsg:     fmt.Errorf("hasher not supported or specified (given: md5:deadbeef)"),
		},
		{
			name:       "File does not exist",
			path:       "nonexistent.txt",
			hashStr:    "sha256:deadbeef",
			setup:      func(fs afero.Fs) {},
			valid:      false,
			actualHash: "",
			err:        true,
		},
	}

	for _, tc := range testsCases {
		t.Run(tc.name, func(t *testing.T) {
			fs := afero.NewMemMapFs()
			tc.setup(fs)

			valid, actualHash, err := ValidateByHash(fs, tc.path, tc.hashStr)

			assert.Equal(t, tc.valid, valid)
			assert.Equal(t, tc.actualHash, actualHash)

			if tc.err {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			if tc.errMsg != nil {
				assert.Equal(t, tc.errMsg, err)
			}
		})
	}
}
