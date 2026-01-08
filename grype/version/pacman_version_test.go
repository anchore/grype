package version

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPacmanVersionCompare(t *testing.T) {
	tests := []struct {
		name    string
		v1      string
		v2      string
		want    int
		wantErr bool
	}{
		{
			name:    "equal versions",
			v1:      "1.0.0",
			v2:      "1.0.0",
			want:    0,
			wantErr: false,
		},
		{
			name:    "first greater",
			v1:      "1.0.1",
			v2:      "1.0.0",
			want:    1,
			wantErr: false,
		},
		{
			name:    "second greater",
			v1:      "1.0.0",
			v2:      "1.0.1",
			want:    -1,
			wantErr: false,
		},
		{
			name:    "with release numbers",
			v1:      "1.0.0-1",
			v2:      "1.0.0-2",
			want:    -1,
			wantErr: false,
		},
		{
			name:    "with release numbers greater",
			v1:      "1.0.0-2",
			v2:      "1.0.0-1",
			want:    1,
			wantErr: false,
		},
		{
			name:    "complex version",
			v1:      "5.6.0-1",
			v2:      "5.6.0-2",
			want:    -1,
			wantErr: false,
		},
		{
			name:    "alpha vs release",
			v1:      "1.0.0alpha",
			v2:      "1.0.0",
			want:    1,
			wantErr: false,
		},
		{
			name:    "with epoch",
			v1:      "1:1.0.0",
			v2:      "2:1.0.0",
			want:    -1,
			wantErr: false,
		},
		{
			name:    "epoch takes precedence",
			v1:      "2:1.0.0",
			v2:      "1:2.0.0",
			want:    1,
			wantErr: false,
		},
		{
			name:    "tilde version",
			v1:      "1.0.0~rc1",
			v2:      "1.0.0",
			want:    -1,
			wantErr: false,
		},
		{
			name:    "leading zeros",
			v1:      "1.0.001",
			v2:      "1.0.1",
			want:    0,
			wantErr: false,
		},
		{
			name:    "version with plus sign",
			v1:      "0.115+24+g5230646-1",
			v2:      "0.116-1",
			want:    -1,
			wantErr: false,
		},
		{
			name:    "version with git hash suffix",
			v1:      "0.12.8+8+ga957a90b-1",
			v2:      "0.12.8+8+ga957a90b-2",
			want:    -1,
			wantErr: false,
		},
		{
			name:    "real arch versions curl",
			v1:      "8.4.0-1",
			v2:      "8.5.0-1",
			want:    -1,
			wantErr: false,
		},
		{
			name:    "real arch versions openssl with epoch",
			v1:      "1:3.0.7-4",
			v2:      "1:3.0.8-1",
			want:    -1,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v1, err := newPacmanVersion(tt.v1)
			assert.NoError(t, err)

			v2 := New(tt.v2, PacmanFormat)
			result, err := v1.Compare(v2)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, result)
			}
		})
	}
}

func TestPacmanVersionString(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{
			name: "simple version",
			raw:  "1.0.0",
			want: "1.0.0",
		},
		{
			name: "with release",
			raw:  "1.0.0-1",
			want: "1.0.0-1",
		},
		{
			name: "with epoch",
			raw:  "1:1.0.0",
			want: "1:1.0.0",
		},
		{
			name: "with epoch and release",
			raw:  "1:1.0.0-1",
			want: "1:1.0.0-1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, err := newPacmanVersion(tt.raw)
			assert.NoError(t, err)
			assert.Equal(t, tt.want, v.String())
		})
	}
}
