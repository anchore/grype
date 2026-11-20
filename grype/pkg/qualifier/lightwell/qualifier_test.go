package lightwell

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/pkg"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

func TestLightwellBaseVersion_Satisfied(t *testing.T) {
	tests := []struct {
		name        string
		baseVersion string
		pkg         pkg.Package
		want        bool
	}{
		{
			name:        "Lightwell build on the advisory's line",
			baseVersion: "6.0.3",
			pkg:         pkg.Package{Name: "woodstox-core", Version: "6.0.3.rhlw-00001", Type: syftPkg.JavaPkg},
			want:        true,
		},
		{
			name:        "later Lightwell build on the advisory's line",
			baseVersion: "6.0.3",
			pkg:         pkg.Package{Name: "woodstox-core", Version: "6.0.3.rhlw-00002", Type: syftPkg.JavaPkg},
			want:        true,
		},
		{
			name:        "NAK: upstream build of the base version suppressed",
			baseVersion: "6.0.3",
			pkg:         pkg.Package{Name: "woodstox-core", Version: "6.0.3", Type: syftPkg.JavaPkg},
			want:        false,
		},
		{
			name:        "NAK: Lightwell build on another line suppressed",
			baseVersion: "5.0.3",
			pkg:         pkg.Package{Name: "woodstox-core", Version: "6.2.2.rhlw-00004", Type: syftPkg.JavaPkg},
			want:        false,
		},
		{
			name:        "dash separated Maven suffix",
			baseVersion: "4.1.100.Final",
			pkg:         pkg.Package{Name: "netty-codec-http", Version: "4.1.100.Final-rhlw-00001", Type: syftPkg.JavaPkg},
			want:        true,
		},
		{
			name:        "PyPI local version suffix",
			baseVersion: "3.0.1",
			pkg:         pkg.Package{Name: "pypdf2", Version: "3.0.1+rhlw.1", Type: syftPkg.PythonPkg},
			want:        true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := New(tt.baseVersion).Satisfied(tt.pkg)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
