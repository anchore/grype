package internal

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/pkg"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

func TestUpstreamPackages(t *testing.T) {
	tests := []struct {
		name      string
		arch      string
		upstreams []pkg.UpstreamPackage
		want      []string // the names of the source packages searched, each tagged "src"
	}{
		{name: "binary with no upstream: its own name", arch: "amd64", want: []string{"openssl"}},
		{name: "binary with only an unnamed upstream: its own name", arch: "amd64", upstreams: []pkg.UpstreamPackage{{Version: "1.0"}}, want: []string{"openssl"}},
		{name: "binary with an upstream of its own name", arch: "amd64", upstreams: []pkg.UpstreamPackage{{Name: "openssl"}}, want: []string{"openssl"}},
		{name: "binary with an upstream of another name: only that upstream", arch: "amd64", upstreams: []pkg.UpstreamPackage{{Name: "openssl-src"}}, want: []string{"openssl-src"}},
		{name: "no arch and no upstream: none", arch: ""},
		{name: "no arch with an upstream of its own name: none", upstreams: []pkg.UpstreamPackage{{Name: "openssl"}}},
		{name: "no arch with an upstream of its own name at another version: that upstream", upstreams: []pkg.UpstreamPackage{{Name: "openssl", Version: "3.0.6"}}, want: []string{"openssl"}},
		{name: "no arch with an upstream of another name: that upstream", upstreams: []pkg.UpstreamPackage{{Name: "openssl-src"}}, want: []string{"openssl-src"}},
		{name: "source package: none", arch: "src"},
		{name: "source package, another spelling: none", arch: "source"},
		{name: "source package with an upstream of its own name: none", arch: "src", upstreams: []pkg.UpstreamPackage{{Name: "openssl"}}},
		{name: "source package with an upstream of its own name at another version: that upstream", arch: "src", upstreams: []pkg.UpstreamPackage{{Name: "openssl", Version: "3.0.6"}}, want: []string{"openssl"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := pkg.Package{Name: "openssl", Version: "3.0.7", Arch: tt.arch, Upstreams: tt.upstreams}
			var names []string
			for _, u := range UpstreamPackages(p) {
				require.Equal(t, "src", u.Arch)
				require.Empty(t, u.Upstreams)
				names = append(names, u.Name)
			}
			require.Equal(t, tt.want, names)
		})
	}
}

func TestUpstreamPackages_InheritsEpoch(t *testing.T) {
	tests := []struct {
		name       string
		pkgType    syftPkg.Type
		pkgVersion string
		metadata   any
		upstream   pkg.UpstreamPackage
		want       string
	}{
		{name: "source rpm of the same version-release", pkgType: syftPkg.RpmPkg, pkgVersion: "2:3.0.7-27.el9", upstream: pkg.UpstreamPackage{Name: "openssl", Version: "3.0.7-27.el9"}, want: "2:3.0.7-27.el9"},
		{name: "source rpm of another name: not inherited", pkgType: syftPkg.RpmPkg, pkgVersion: "2:3.0.7-27.el9", upstream: pkg.UpstreamPackage{Name: "openssl-src", Version: "3.0.7-27.el9"}, want: "3.0.7-27.el9"},
		{name: "epoch only in metadata", pkgType: syftPkg.RpmPkg, pkgVersion: "3.0.7-27.el9", metadata: pkg.RpmMetadata{Epoch: new(2)}, upstream: pkg.UpstreamPackage{Name: "openssl", Version: "3.0.7-27.el9"}, want: "2:3.0.7-27.el9"},
		{name: "synthesized source of its own name", pkgType: syftPkg.RpmPkg, pkgVersion: "3.0.7-27.el9", metadata: pkg.RpmMetadata{Epoch: new(2)}, want: "2:3.0.7-27.el9"},
		{name: "source rpm of another version: unknown epoch", pkgType: syftPkg.RpmPkg, pkgVersion: "2:3.0.6-1.el9", upstream: pkg.UpstreamPackage{Name: "openssl", Version: "3.0.7-27.el9"}, want: "3.0.7-27.el9"},
		{name: "source rpm with its own epoch", pkgType: syftPkg.RpmPkg, pkgVersion: "2:3.0.7-27.el9", upstream: pkg.UpstreamPackage{Name: "openssl", Version: "1:3.0.7-27.el9"}, want: "1:3.0.7-27.el9"},
		{name: "zero epoch is not inherited", pkgType: syftPkg.RpmPkg, pkgVersion: "0:3.0.7-27.el9", upstream: pkg.UpstreamPackage{Name: "openssl", Version: "3.0.7-27.el9"}, want: "3.0.7-27.el9"},
		{name: "deb source version is explicit", pkgType: syftPkg.DebPkg, pkgVersion: "2:3.0.7-1", upstream: pkg.UpstreamPackage{Name: "openssl", Version: "3.0.7-1"}, want: "3.0.7-1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := pkg.Package{Name: "openssl", Type: tt.pkgType, Version: tt.pkgVersion, Arch: "x86_64", Metadata: tt.metadata}
			if tt.upstream.Name != "" {
				p.Upstreams = []pkg.UpstreamPackage{tt.upstream}
			}
			upstreams := UpstreamPackages(p)
			require.Len(t, upstreams, 1)
			require.Equal(t, tt.want, upstreams[0].Version)
		})
	}
}

func TestIsOwnSource(t *testing.T) {
	tests := []struct {
		name            string
		upstreamName    string
		upstreamVersion string
		pkgVersion      string
		want            bool
	}{
		{name: "same name and version", upstreamName: "openssl", upstreamVersion: "3.0.7-1", pkgVersion: "3.0.7-1", want: true},
		{name: "same name, the upstream omits the epoch", upstreamName: "openssl", upstreamVersion: "3.0.7-1", pkgVersion: "1:3.0.7-1", want: true},
		{name: "same name, the package records the epoch elsewhere", upstreamName: "openssl", upstreamVersion: "1:3.0.7-1", pkgVersion: "3.0.7-1", want: true},
		{name: "same name, another epoch", upstreamName: "openssl", upstreamVersion: "2:3.0.7-1", pkgVersion: "1:3.0.7-1", want: false},
		{name: "same name, another version", upstreamName: "openssl", upstreamVersion: "3.0.7-1", pkgVersion: "3.0.7-1+b1", want: false},
		{name: "another name", upstreamName: "openssl-src", upstreamVersion: "3.0.7-1", pkgVersion: "3.0.7-1", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := pkg.Package{Name: "openssl", Version: tt.pkgVersion}
			u := pkg.Package{Name: tt.upstreamName, Version: tt.upstreamVersion}
			require.Equal(t, tt.want, IsSameUpstream(u, p))
		})
	}
}
