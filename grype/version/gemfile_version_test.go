package version

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGemfileVersionSemantic(t *testing.T) {
	tests := []testCase{
		// empty values
		{version: "2.3.1", constraint: "", satisfied: true},
		// typical cases
		{version: "1.2.0", constraint: ">1.0, <2.0", satisfied: true},
		{version: "1.2.0-x86-linux", constraint: ">1.0, <2.0", satisfied: true},
		{version: "1.2.0-x86", constraint: ">1.0, <2.0", satisfied: true},
		{version: "1.2.0-x86-linux", constraint: "= 1.2.0", satisfied: true},
		{version: "1.2.0-x86_64-linux", constraint: "= 1.2.0", satisfied: true},
		{version: "1.2.0-x86_64-linux", constraint: "< 1.2.1", satisfied: true},
		// https://semver.org/#spec-item-11
		{version: "1.2.0-alpha-x86-linux", constraint: "<1.2.0", satisfied: true},
		{version: "1.2.0-alpha-1-x86-linux", constraint: "<1.2.0", satisfied: true},
		{version: "1.2.0-alpha-1-x86-linux+meta", constraint: "<1.2.0", satisfied: true},
		{version: "1.2.0-alpha-1-x86-linux+meta", constraint: ">1.1.0", satisfied: true},
		{version: "1.2.0-alpha-1-arm-linux+meta", constraint: ">1.1.0", satisfied: true},
		{version: "1.0.0-alpha-a.b-c-somethinglong+build.1-aef.1-its-okay", constraint: "<1.0.0", satisfied: true},
		{version: "1.2.3----RC-SNAPSHOT.12.9.1--.12+788", constraint: "> 1.0.0", satisfied: true},
		{version: "1.2.3----RC-SNAPSHOT.12.9.1--.12+788-armv7-darwin", constraint: "> 1.0.0", satisfied: true},
	}

	for _, test := range tests {
		t.Run(test.tName(), func(t *testing.T) {
			constraint, err := newGemfileConstraint(test.constraint)
			assert.NoError(t, err, "unexpected error from newSemanticConstraint: %v", err)

			test.assertVersionConstraint(t, GemfileFormat, constraint)
		})
	}

}

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
