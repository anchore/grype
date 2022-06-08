package version

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_newGemfileVersion(t *testing.T) {
	semVer, err := newSemanticVersion("1.13.1")
	assert.NoError(t, err)

	tests := []struct {
		input   string
		want    *gemfileVersion
		wantErr assert.ErrorAssertionFunc
	}{
		{
			input: "1.13.1",
			want: &gemfileVersion{
				raw:    "1.13.1",
				semVer: semVer,
			},
			wantErr: assert.NoError,
		},
		{
			input: "1.13.1-armv7-linux",
			want: &gemfileVersion{
				raw:    "1.13.1-armv7-linux",
				semVer: semVer,
			},
			wantErr: assert.NoError,
		},
		{
			input: "1.13.1-arm-linux",
			want: &gemfileVersion{
				raw:    "1.13.1-arm-linux",
				semVer: semVer,
			},
			wantErr: assert.NoError,
		},
		{
			input: "1.13.1-x86-linux",
			want: &gemfileVersion{
				raw:    "1.13.1-x86-linux",
				semVer: semVer,
			},
			wantErr: assert.NoError,
		},
		{
			input: "1.13.1-x86_64-linux",
			want: &gemfileVersion{
				raw:    "1.13.1-x86_64-linux",
				semVer: semVer,
			},
			wantErr: assert.NoError,
		},
		{
			input: "1.13.1-x86-freebsd",
			want: &gemfileVersion{
				raw:    "1.13.1-x86-freebsd",
				semVer: semVer,
			},
			wantErr: assert.NoError,
		},
		{
			input: "1.13.1-x86-mswin32-80",
			want: &gemfileVersion{
				raw:    "1.13.1-x86-mswin32-80",
				semVer: semVer,
			},
			wantErr: assert.NoError,
		},
		{
			input: "1.13.1-universal-darwin-8",
			want: &gemfileVersion{
				raw:    "1.13.1-universal-darwin-8",
				semVer: semVer,
			},
			wantErr: assert.NoError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := newGemfileVersion(tt.input)
			if !tt.wantErr(t, err, fmt.Sprintf("newGemfileVersion(%v)", tt.input)) {
				return
			}
			assert.Equalf(t, tt.want, got, "newGemfileVersion(%v)", tt.input)
		})
	}
}
