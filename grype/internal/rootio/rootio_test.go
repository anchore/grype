package rootio

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/grype/grype/pkg"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

func TestIsPackage(t *testing.T) {
	tests := []struct {
		name string
		pkg  pkg.Package
		want bool
	}{
		{
			name: "Alpine: rootio- prefix with -r1007N suffix",
			pkg:  pkg.Package{Name: "rootio-util-linux", Version: "2.38.1-r10071", Type: syftPkg.ApkPkg},
			want: true,
		},
		{
			name: "Alpine: rootio- prefix only",
			pkg:  pkg.Package{Name: "rootio-util-linux", Version: "2.38.1-r0", Type: syftPkg.ApkPkg},
			want: true,
		},
		{
			name: "Alpine: standard package",
			pkg:  pkg.Package{Name: "util-linux", Version: "2.38.1-r0", Type: syftPkg.ApkPkg},
			want: false,
		},
		{
			// Rootio ships upstream-named apk packages in production
			// (sqlite-libs@3.41.2-r30074, libcrypto3@3.1.8-r00073,
			// libssl3@3.1.8-r00073 observed in real images), so the
			// 5-digit `-rNNNNN` rev counter must classify a package as
			// rootio even without the `rootio-` name prefix. Stock Alpine
			// rev counters max out around two digits, so accidental FPs
			// at this threshold are implausible.
			name: "Alpine: 5-digit rev without rootio name IS rootio (upstream-named model)",
			pkg:  pkg.Package{Name: "libssl3", Version: "3.1.8-r00073", Type: syftPkg.ApkPkg},
			want: true,
		},
		{
			name: "Debian: rootio- prefix with .root.io.N suffix",
			pkg:  pkg.Package{Name: "rootio-imagemagick", Version: "8:6.9.11.root.io.1", Type: syftPkg.DebPkg},
			want: true,
		},
		{
			name: "Debian: rootio- prefix only",
			pkg:  pkg.Package{Name: "rootio-imagemagick", Version: "8:6.9.11", Type: syftPkg.DebPkg},
			want: true,
		},
		{
			name: "Debian: standard package",
			pkg:  pkg.Package{Name: "imagemagick", Version: "8:6.9.11", Type: syftPkg.DebPkg},
			want: false,
		},
		{
			name: "NPM: @rootio/ scoped package",
			pkg:  pkg.Package{Name: "@rootio/semver", Version: "7.5.4", Type: syftPkg.NpmPkg},
			want: true,
		},
		{
			name: "NPM: rootio- prefix",
			pkg:  pkg.Package{Name: "rootio-semver", Version: "7.5.4", Type: syftPkg.NpmPkg},
			want: true,
		},
		{
			name: "NPM: version suffix only",
			pkg:  pkg.Package{Name: "semver", Version: "7.5.4-root.io.1", Type: syftPkg.NpmPkg},
			want: true,
		},
		{
			name: "NPM: standard package",
			pkg:  pkg.Package{Name: "semver", Version: "7.5.4", Type: syftPkg.NpmPkg},
			want: false,
		},
		{
			name: "PyPI: rootio_ prefix with +root.io.N suffix",
			pkg:  pkg.Package{Name: "rootio_requests", Version: "2.31.0+root.io.1", Type: syftPkg.PythonPkg},
			want: true,
		},
		{
			name: "PyPI: rootio_ prefix only",
			pkg:  pkg.Package{Name: "rootio_requests", Version: "2.31.0", Type: syftPkg.PythonPkg},
			want: true,
		},
		{
			name: "PyPI: +root.io.N suffix only",
			pkg:  pkg.Package{Name: "requests", Version: "2.31.0+root.io.1", Type: syftPkg.PythonPkg},
			want: true,
		},
		{
			name: "PyPI: standard package",
			pkg:  pkg.Package{Name: "requests", Version: "2.31.0", Type: syftPkg.PythonPkg},
			want: false,
		},
		{
			// Realistic Syft shape: p.Name is the artifactID alone; the
			// rootio marker io.root. lives in JavaMetadata.PomGroupID.
			name: "Java: groupID prefix in JavaMetadata (realistic Syft shape)",
			pkg: pkg.Package{
				Name:    "spring-core",
				Version: "5.3.30",
				Type:    syftPkg.JavaPkg,
				Metadata: pkg.JavaMetadata{
					PomArtifactID: "spring-core",
					PomGroupID:    "io.root.org.springframework",
				},
			},
			want: true,
		},
		{
			// Hand-built shape: some callers pre-compose group:artifact in p.Name.
			name: "Java: io.root. prefix on p.Name (legacy hand-built shape)",
			pkg: pkg.Package{
				Name:    "io.root.org.springframework:spring-core",
				Version: "5.3.30",
				Type:    syftPkg.JavaPkg,
			},
			want: true,
		},
		{
			name: "Java: standard package, no rootio signal",
			pkg: pkg.Package{
				Name:    "spring-core",
				Version: "5.3.30",
				Type:    syftPkg.JavaPkg,
				Metadata: pkg.JavaMetadata{
					PomArtifactID: "spring-core",
					PomGroupID:    "org.springframework",
				},
			},
			want: false,
		},
		{
			name: "Java: rootio groupID with empty PomArtifactID still detected",
			pkg: pkg.Package{
				Name:    "spring-core",
				Version: "5.3.30",
				Type:    syftPkg.JavaPkg,
				Metadata: pkg.JavaMetadata{
					PomGroupID: "io.root.org.springframework",
				},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, IsPackage(tt.pkg))
		})
	}
}

func TestStripPrefix(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		pkgType syftPkg.Type
		want    string
	}{
		{name: "Alpine rootio-", input: "rootio-libssl3", pkgType: syftPkg.ApkPkg, want: "libssl3"},
		{name: "Debian rootio-", input: "rootio-imagemagick", pkgType: syftPkg.DebPkg, want: "imagemagick"},
		{name: "NPM scoped", input: "@rootio/express", pkgType: syftPkg.NpmPkg, want: "express"},
		{name: "NPM scoped with double-underscore namespace", input: "@rootio/babel__core", pkgType: syftPkg.NpmPkg, want: "@babel/core"},
		{name: "NPM unscoped", input: "rootio-semver", pkgType: syftPkg.NpmPkg, want: "semver"},
		{name: "PyPI underscore", input: "rootio_requests", pkgType: syftPkg.PythonPkg, want: "requests"},
		{name: "PyPI normalized hyphen", input: "rootio-requests", pkgType: syftPkg.PythonPkg, want: "requests"},
		{name: "Java io.root.", input: "io.root.org.springframework", pkgType: syftPkg.JavaPkg, want: "org.springframework"},
		{name: "no rootio prefix is identity", input: "libssl3", pkgType: syftPkg.ApkPkg, want: "libssl3"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, StripPrefix(tt.input, tt.pkgType))
		})
	}
}

func TestHasPrefix(t *testing.T) {
	tests := []struct {
		name    string
		pkg     pkg.Package
		pkgType syftPkg.Type
		want    bool
	}{
		{name: "rootio- prefix for Alpine", pkg: pkg.Package{Name: "rootio-util-linux"}, pkgType: syftPkg.ApkPkg, want: true},
		{name: "rootio- prefix for Debian", pkg: pkg.Package{Name: "rootio-imagemagick"}, pkgType: syftPkg.DebPkg, want: true},
		{name: "@rootio/ scoped NPM package", pkg: pkg.Package{Name: "@rootio/semver"}, pkgType: syftPkg.NpmPkg, want: true},
		{name: "rootio- prefix for NPM", pkg: pkg.Package{Name: "rootio-semver"}, pkgType: syftPkg.NpmPkg, want: true},
		{name: "rootio_ prefix for PyPI", pkg: pkg.Package{Name: "rootio_requests"}, pkgType: syftPkg.PythonPkg, want: true},
		{name: "no prefix", pkg: pkg.Package{Name: "util-linux"}, pkgType: syftPkg.ApkPkg, want: false},
		{name: "empty string", pkg: pkg.Package{Name: ""}, pkgType: syftPkg.ApkPkg, want: false},
		{
			name: "Java: groupID in metadata",
			pkg: pkg.Package{
				Name: "spring-core",
				Metadata: pkg.JavaMetadata{
					PomGroupID: "io.root.org.springframework",
				},
			},
			pkgType: syftPkg.JavaPkg,
			want:    true,
		},
		{
			name:    "Java: io.root. prefix on p.Name (hand-built)",
			pkg:     pkg.Package{Name: "io.root.org.springframework:spring-core"},
			pkgType: syftPkg.JavaPkg,
			want:    true,
		},
		{
			name: "Java: standard groupId without io.root. prefix",
			pkg: pkg.Package{
				Name: "spring-core",
				Metadata: pkg.JavaMetadata{
					PomGroupID: "org.springframework",
				},
			},
			pkgType: syftPkg.JavaPkg,
			want:    false,
		},
		{name: "name containing root but not prefix", pkg: pkg.Package{Name: "myroot-package"}, pkgType: syftPkg.ApkPkg, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, hasPrefix(tt.pkg, tt.pkgType))
		})
	}
}

func TestHasVersionSuffix(t *testing.T) {
	tests := []struct {
		name    string
		version string
		pkgType syftPkg.Type
		want    bool
	}{
		{name: "NPM: -root.io. suffix", version: "7.5.4-root.io.1", pkgType: syftPkg.NpmPkg, want: true},
		{name: "Debian: .root.io. suffix", version: "8:6.9.11.root.io.1", pkgType: syftPkg.DebPkg, want: true},
		{name: "PyPI: +root.io. suffix", version: "2.31.0+root.io.1", pkgType: syftPkg.PythonPkg, want: true},
		{name: "Alpine: -r10071 suffix", version: "2.38.1-r10071", pkgType: syftPkg.ApkPkg, want: true},
		{name: "Alpine: -r10077 (real-world rootio-krb5-libs)", version: "1.20.2-r10077", pkgType: syftPkg.ApkPkg, want: true},
		{name: "Alpine: -r00073 (real-world rootio-libssl3)", version: "3.1.8-r00073", pkgType: syftPkg.ApkPkg, want: true},
		{name: "Alpine: -r20074 (real-world rootio-openssh)", version: "9.3_p2-r20074", pkgType: syftPkg.ApkPkg, want: true},
		{name: "Alpine: standard -r0 suffix", version: "2.38.1-r0", pkgType: syftPkg.ApkPkg, want: false},
		{name: "Alpine: standard -r1 suffix", version: "2.38.1-r1", pkgType: syftPkg.ApkPkg, want: false},
		{name: "Alpine: -r1007 (four-digit boundary)", version: "2.38.1-r1007", pkgType: syftPkg.ApkPkg, want: false},
		{name: "Alpine: -r10071a (digits then letter)", version: "2.38.1-r10071a", pkgType: syftPkg.ApkPkg, want: false},
		{name: "no suffix", version: "2.38.1", pkgType: syftPkg.ApkPkg, want: false},
		{name: "empty version", version: "", pkgType: syftPkg.ApkPkg, want: false},
		{name: "Java: any version returns false (no convention)", version: "2.14.0.root.io.1", pkgType: syftPkg.JavaPkg, want: false},
		{name: "PyPI: wrong suffix type (should use +)", version: "2.31.0.root.io.1", pkgType: syftPkg.PythonPkg, want: false},
		{name: "NPM: wrong suffix type (should use -)", version: "7.5.4.root.io.1", pkgType: syftPkg.NpmPkg, want: false},
		{name: "NPM: wrong suffix with +", version: "7.5.4+root.io.1", pkgType: syftPkg.NpmPkg, want: false},
		{name: "Debian: wrong suffix with -", version: "5.10.234-1-root.io.1", pkgType: syftPkg.DebPkg, want: false},
		{name: "Debian: wrong suffix with +", version: "5.10.234-1+root.io.1", pkgType: syftPkg.DebPkg, want: false},
		{name: "PyPI: wrong suffix with -", version: "2.31.0-root.io.1", pkgType: syftPkg.PythonPkg, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, hasVersionSuffix(tt.version, tt.pkgType))
		})
	}
}
