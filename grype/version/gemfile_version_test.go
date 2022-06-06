package version

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	hashiVer "github.com/anchore/go-version"
)

func Test_newGemfileVersion(t *testing.T) {
	semVer := "1.13.1"
	verObj, err := hashiVer.NewVersion(semVer)
	assert.NoError(t, err)

	tests := []struct {
		name    string
		input   string
		want    *gemfileVersion
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name:  "just-sem-ver",
			input: semVer,
			want: &gemfileVersion{
				raw:    semVer,
				verObj: verObj,
			},
			wantErr: assert.NoError,
		},
		{
			name:  "with-arch-x86",
			input: "1.13.1-x86",
			want: &gemfileVersion{
				raw:    "1.13.1-x86",
				verObj: verObj,
			},
			wantErr: assert.NoError,
		},
		{
			name:  "with-distro",
			input: "1.13.1-linux",
			want: &gemfileVersion{
				raw:    "1.13.1-linux",
				verObj: verObj,
			},
			wantErr: assert.NoError,
		},
		{
			name:  "with-distro-and-arch",
			input: "1.13.1-linux-x86",
			want: &gemfileVersion{
				raw:    "1.13.1-linux-x86",
				verObj: verObj,
			},
			wantErr: assert.NoError,
		},
		{
			name:  "with-arch-and-distro",
			input: "1.13.1-x86_64-linux",
			want: &gemfileVersion{
				raw:    "1.13.1-x86_64-linux",
				verObj: verObj,
			},
			wantErr: assert.NoError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := newGemfileVersion(tt.input)
			if !tt.wantErr(t, err, fmt.Sprintf("newGemfileVersion(%v)", tt.input)) {
				return
			}
			assert.Equalf(t, tt.want, got, "newGemfileVersion(%v)", tt.input)
		})
	}
}
