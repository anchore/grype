package version

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func makeSemVer(t *testing.T, raw string) *semanticVersion {
	semVer, err := newSemanticVersion(raw)
	assert.NoError(t, err)
	return semVer
}

func Test_newGemfileVersion(t *testing.T) {

	tests := []struct {
		input string
		want  *semanticVersion
	}{
		{input: "1.13.1", want: makeSemVer(t, "1.13.1")},
		{input: "1.13.1-arm-linux", want: makeSemVer(t, "1.13.1")},
		{input: "1.13.1-armv6-linux", want: makeSemVer(t, "1.13.1")},
		{input: "1.13.1-armv7-linux", want: makeSemVer(t, "1.13.1")},
		{input: "1.13.1-java", want: makeSemVer(t, "1.13.1")},
		{input: "1.13.1-dalvik", want: makeSemVer(t, "1.13.1")},
		{input: "1.13.1-mswin32", want: makeSemVer(t, "1.13.1")},
		{input: "1.13.1-x64-mswin64", want: makeSemVer(t, "1.13.1")},
		{input: "1.13.1-sparc-unix", want: makeSemVer(t, "1.13.1")},
		{input: "1.13.1-powerpc-darwin", want: makeSemVer(t, "1.13.1")},
		{input: "1.13.1-x86-linux", want: makeSemVer(t, "1.13.1")},
		{input: "1.13.1-x86_64-linux", want: makeSemVer(t, "1.13.1")},
		{input: "1.13.1-x86-freebsd", want: makeSemVer(t, "1.13.1")},
		{input: "1.13.1-x86-mswin32-80", want: makeSemVer(t, "1.13.1")},
		{input: "1.13.1-universal-darwin-8", want: makeSemVer(t, "1.13.1")},
		{input: "1.13.1-beta-universal-darwin-8", want: makeSemVer(t, "1.13.1.beta")},
		{input: "1.13.1-alpha-1-arm-linux+meta", want: makeSemVer(t, "1.13.1.alpha-1")},
		{input: "1.13.1-alpha-1-arm-linux+build.12", want: makeSemVer(t, "1.13.1.alpha-1")},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := newGemfileVersion(tt.input)
			if !assert.NoError(t, err, fmt.Sprintf("newGemfileVersion(%v)", tt.input)) {
				return
			}
			assert.Equalf(t, tt.want, got.semVer, "newGemfileVersion(%v)", tt.input)

			// check that semantic versions are comaprable to gemfile versions
			other, err := NewVersion(tt.want.verObj.String(), SemanticFormat)
			assert.NoError(t, err)

			v, err := got.Compare(other)
			assert.NoError(t, err)
			assert.Equal(t, 0, v)
		})
	}
}
