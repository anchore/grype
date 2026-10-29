package upstreammatch

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/pkg/qualifier"
	"github.com/anchore/grype/grype/pkg/qualifier/rootio"
)

func TestSatisfied(t *testing.T) {
	subpackage := pkg.Package{
		Name:      "foo-docs",
		Version:   "1.2.3-r0",
		Metadata:  pkg.ApkMetadata{Arch: "x86_64"},
		Upstreams: []pkg.UpstreamPackage{{Name: "foo"}},
	}
	upstreams := pkg.UpstreamPackages(subpackage)
	require.Len(t, upstreams, 1)

	tests := []struct {
		name string
		p    pkg.Package
		want bool
	}{
		{
			name: "cataloged apk package",
			p:    subpackage,
			want: true,
		},
		{
			name: "apk copy built to search the upstream package",
			p:    upstreams[0],
			want: false,
		},
		{
			name: "package without metadata",
			p:    pkg.Package{Name: "foo"},
			want: true,
		},
		{
			name: "rpm package",
			p:    pkg.Package{Name: "foo", Metadata: pkg.RpmMetadata{Arch: "src"}},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := New().Satisfied(tt.p)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}

	// marking the copy must not leak onto the cataloged package
	assert.False(t, pkg.IsUpstreamSearch(subpackage))
}

func TestExcludes(t *testing.T) {
	assert.True(t, Excludes([]qualifier.Qualifier{rootio.New(), New()}))
	assert.False(t, Excludes([]qualifier.Qualifier{rootio.New()}))
	assert.False(t, Excludes(nil))
}
