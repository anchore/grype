package rootio

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/pkg"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

func TestRootIO_Satisfied(t *testing.T) {
	tests := []struct {
		name string
		pkg  pkg.Package
		want bool
	}{
		{
			name: "NAK: standard Alpine package suppressed",
			pkg:  pkg.Package{Name: "util-linux", Version: "2.38.1-r0", Type: syftPkg.ApkPkg},
			want: false,
		},
		{
			name: "Root IO Alpine package allowed",
			pkg:  pkg.Package{Name: "rootio-util-linux", Version: "2.38.1-r10071", Type: syftPkg.ApkPkg},
			want: true,
		},
		{
			name: "NAK: standard Debian package suppressed",
			pkg:  pkg.Package{Name: "imagemagick", Version: "8:6.9.11.60", Type: syftPkg.DebPkg},
			want: false,
		},
		{
			name: "Root IO Debian package allowed",
			pkg:  pkg.Package{Name: "rootio-imagemagick", Version: "8:6.9.11.root.io.1", Type: syftPkg.DebPkg},
			want: true,
		},
		{
			name: "NAK: standard NPM package suppressed",
			pkg:  pkg.Package{Name: "semver", Version: "7.5.4", Type: syftPkg.NpmPkg},
			want: false,
		},
		{
			name: "Root IO NPM scoped package allowed",
			pkg:  pkg.Package{Name: "@rootio/semver", Version: "7.5.4", Type: syftPkg.NpmPkg},
			want: true,
		},
		{
			name: "Root IO NPM version-suffix-only allowed",
			pkg:  pkg.Package{Name: "semver", Version: "7.5.4-root.io.1", Type: syftPkg.NpmPkg},
			want: true,
		},
		{
			name: "NAK: standard PyPI package suppressed",
			pkg:  pkg.Package{Name: "requests", Version: "2.31.0", Type: syftPkg.PythonPkg},
			want: false,
		},
		{
			name: "Root IO PyPI package allowed",
			pkg:  pkg.Package{Name: "rootio-requests", Version: "2.31.0+root.io.1", Type: syftPkg.PythonPkg},
			want: true,
		},
		{
			name: "NAK: standard Java package suppressed",
			pkg: pkg.Package{
				Name:    "jackson-databind",
				Version: "2.14.0",
				Type:    syftPkg.JavaPkg,
				Metadata: pkg.JavaMetadata{
					PomGroupID:    "com.fasterxml.jackson.core",
					PomArtifactID: "jackson-databind",
				},
			},
			want: false,
		},
		{
			name: "Root IO Java package allowed (groupID in metadata)",
			pkg: pkg.Package{
				Name:    "jackson-databind",
				Version: "2.14.0",
				Type:    syftPkg.JavaPkg,
				Metadata: pkg.JavaMetadata{
					PomGroupID:    "io.root.com.fasterxml.jackson.core",
					PomArtifactID: "jackson-databind",
				},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := New().Satisfied(tt.pkg)
			require.NoError(t, err)
			assert.Equal(t, tt.want, result)
		})
	}
}
