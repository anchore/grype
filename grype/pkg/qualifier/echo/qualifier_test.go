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
		{"plain upstream at base", "2.14.2", false},
		{"plain upstream higher", "26.1", false},
		{"plain upstream with non-echo local", "26.1+foo.1", false},
		{"echo without numeric revision", "1.0+echo", false},
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
