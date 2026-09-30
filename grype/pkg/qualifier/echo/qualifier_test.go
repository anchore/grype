package echo

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/pkg"
)

func TestEchoQualifier_Satisfied(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    bool
	}{
		{"echo pypi build", "2.14.2+echo.1", true},
		{"echo later rebuild", "2.14.2+echo.2", true},
		{"echo maven build, multi-digit", "5.3.32+echo.10", true},
		{"echo go module", "v0.55.0+echo.1", true},
		{"echo go toolchain", "go1.24.1+echo.1", true},
		{"echo compound go metadata", "go1.24.1+incompatible+echo.1", true},
		{"plain upstream at base", "2.14.2", false},
		{"plain upstream higher", "26.1", false},
		{"plain upstream with non-echo local", "26.1+foo.1", false},
		{"echo without numeric revision", "1.0+echo", false},
		{"echo marker followed by more metadata", "1.0+echo.1.extra", false},
		{"echo marker embedded in other metadata", "1.0+build.echo.1", false},
		{"empty version", "", false},
	}

	q := New()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := q.Satisfied(pkg.Package{Version: tt.version})
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}
