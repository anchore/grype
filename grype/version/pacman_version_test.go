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
			want:    -1,
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
			name:    "tilde is a plain separator",
			v1:      "1.0.0~rc1",
			v2:      "1.0.0",
			want:    1,
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

// TestPacmanVersionCompare_Vercmp runs the cases from pacman's own vercmp test suite
// (test/util/vercmptest.sh), each in both directions as the suite does.
func TestPacmanVersionCompare_Vercmp(t *testing.T) {
	tests := []struct {
		v1   string
		v2   string
		want int
	}{
		// all similar length, no pkgrel
		{"1.5.0", "1.5.0", 0},
		{"1.5.1", "1.5.0", 1},
		// mixed length
		{"1.5.1", "1.5", 1},
		// with pkgrel, simple
		{"1.5.0-1", "1.5.0-1", 0},
		{"1.5.0-1", "1.5.0-2", -1},
		{"1.5.0-1", "1.5.1-1", -1},
		{"1.5.0-2", "1.5.1-1", -1},
		// with pkgrel, mixed lengths
		{"1.5-1", "1.5.1-1", -1},
		{"1.5-2", "1.5.1-1", -1},
		{"1.5-2", "1.5.1-2", -1},
		// mixed pkgrel inclusion
		{"1.5", "1.5-1", 0},
		{"1.5-1", "1.5", 0},
		{"1.1-1", "1.1", 0},
		{"1.0-1", "1.1", -1},
		{"1.1-1", "1.0", 1},
		// alphanumeric versions
		{"1.5b-1", "1.5-1", -1},
		{"1.5b", "1.5", -1},
		{"1.5b-1", "1.5", -1},
		{"1.5b", "1.5.1", -1},
		// from the manpage
		{"1.0a", "1.0alpha", -1},
		{"1.0alpha", "1.0b", -1},
		{"1.0b", "1.0beta", -1},
		{"1.0beta", "1.0rc", -1},
		{"1.0rc", "1.0", -1},
		// alpha-dotted versions
		{"1.5.a", "1.5", 1},
		{"1.5.b", "1.5.a", 1},
		{"1.5.1", "1.5.b", 1},
		// alpha dots and dashes
		{"1.5.b-1", "1.5.b", 0},
		{"1.5-1", "1.5.b", -1},
		// same/similar content, differing separators
		{"2.0", "2_0", 0},
		{"2.0_a", "2_0.a", 0},
		{"2.0a", "2.0.a", -1},
		{"2___a", "2_a", 1},
		// epoch included version comparisons
		{"0:1.0", "0:1.0", 0},
		{"0:1.0", "0:1.1", -1},
		{"1:1.0", "0:1.0", 1},
		{"1:1.0", "0:1.1", 1},
		{"1:1.0", "2:1.1", -1},
		// epoch + sometimes present pkgrel
		{"1:1.0", "0:1.0-1", 1},
		{"1:1.0-1", "0:1.1-1", 1},
		// the vercmptest.sh cases with an epoch on only one side are not included:
		// grype intentionally ignores an epoch that is missing from one of the versions
	}

	for _, tt := range tests {
		for _, tc := range []struct {
			v1, v2 string
			want   int
		}{{tt.v1, tt.v2, tt.want}, {tt.v2, tt.v1, -tt.want}} {
			t.Run(tc.v1+" vs "+tc.v2, func(t *testing.T) {
				v1, err := newPacmanVersion(tc.v1)
				assert.NoError(t, err)

				result, err := v1.Compare(New(tc.v2, PacmanFormat))
				assert.NoError(t, err)
				assert.Equal(t, tc.want, result)
			})
		}
	}
}

func TestPacmanVersionConstraint(t *testing.T) {
	tests := []struct {
		name       string
		constraint string
		version    string
		satisfied  bool
	}{
		{
			// AVG-1348: tensorflow 2.4.0rc4-2 is affected, fixed in 2.4.0-1
			name:       "release candidate is before the release",
			constraint: "< 2.4.0-1",
			version:    "2.4.0rc4-2",
			satisfied:  true,
		},
		{
			// AVG-1350: tensorflow 2.3.1-7 is affected, fixed in 2.4.0rc4-1
			name:       "release is after the release candidate",
			constraint: "< 2.4.0rc4-1",
			version:    "2.4.0-1",
			satisfied:  false,
		},
		{
			name:       "dotted letter suffix is after the release",
			constraint: "< 1.1.1.w-1",
			version:    "1.1.1-1",
			satisfied:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := GetConstraint(tt.constraint, PacmanFormat)
			assert.NoError(t, err)

			satisfied, err := c.Satisfied(New(tt.version, PacmanFormat))
			assert.NoError(t, err)
			assert.Equal(t, tt.satisfied, satisfied)
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
