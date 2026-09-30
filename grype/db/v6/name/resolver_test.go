package name

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/grype/grype/pkg"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

func TestPackageNames_EchoBuild(t *testing.T) {
	tests := []struct {
		name string
		pkg  pkg.Package
		want []string
	}{
		{
			name: "plain Go module has no internal Echo key",
			pkg: pkg.Package{
				Name:    "golang.org/x/net",
				Version: "v0.55.0",
				Type:    syftPkg.GoModulePkg,
			},
			want: []string{"golang.org/x/net"},
		},
		{
			name: "Echo Go module adds internal key",
			pkg: pkg.Package{
				Name:    "golang.org/x/net",
				Version: "v0.55.0+echo.1",
				Type:    syftPkg.GoModulePkg,
			},
			want: []string{"golang.org/x/net", "echo:golang.org/x/net"},
		},
		{
			name: "scoped npm package keeps upstream name",
			pkg: pkg.Package{
				Name:    "@scope/package",
				Version: "1.2.3+echo.1",
				Type:    syftPkg.NpmPkg,
			},
			want: []string{"@scope/package", "echo:@scope/package"},
		},
		{
			name: "Python name is normalized before prefixing",
			pkg: pkg.Package{
				Name:    "some_package",
				Version: "1.2.3+echo.1",
				Type:    syftPkg.PythonPkg,
			},
			want: []string{"some-package", "echo:some-package"},
		},
		{
			name: "Maven coordinate beginning with echo is still encoded",
			pkg: pkg.Package{
				Name:    "artifact",
				Version: "1.2.3+echo.1",
				Type:    syftPkg.JavaPkg,
				Metadata: pkg.JavaMetadata{
					PomGroupID:    "echo",
					PomArtifactID: "artifact",
				},
			},
			want: []string{"echo:artifact", "echo:echo:artifact"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, PackageNames(tt.pkg))
		})
	}
}
