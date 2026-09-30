package echo

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsBuild(t *testing.T) {
	tests := []struct {
		version string
		want    bool
	}{
		{version: "v0.55.0+echo.1", want: true},
		{version: "go1.24.1+echo.10", want: true},
		{version: "go1.24.1+incompatible+echo.1", want: true},
		{version: "1.0.0", want: false},
		{version: "1.0.0+echo", want: false},
		{version: "1.0.0+echo.1.extra", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			assert.Equal(t, tt.want, IsBuild(tt.version))
		})
	}
}

func TestPackageName(t *testing.T) {
	assert.Equal(t, "echo:golang.org/x/net", PackageName("golang.org/x/net"))
	assert.Equal(t, "echo:@scope/package", PackageName("@scope/package"))
	assert.Equal(t, "echo:org.example:artifact", PackageName("org.example:artifact"))
	assert.Equal(t, "echo:echo:artifact", PackageName("echo:artifact"))
	assert.Empty(t, PackageName(""))
}
