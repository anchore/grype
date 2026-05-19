package rootio

import (
	"testing"

	"github.com/stretchr/testify/assert"

	syftPkg "github.com/anchore/syft/syft/pkg"
)

func TestIsPackage(t *testing.T) {
	tests := []struct {
		name        string
		pkgName     string
		version     string
		pkgType     syftPkg.Type
		javaGroupID string
		want        bool
	}{
		{
			name:    "Alpine: rootio- prefix with -r1007N suffix",
			pkgName: "rootio-util-linux", version: "2.38.1-r10071", pkgType: syftPkg.ApkPkg,
			want: true,
		},
		{
			name:    "Alpine: rootio- prefix only",
			pkgName: "rootio-util-linux", version: "2.38.1-r0", pkgType: syftPkg.ApkPkg,
			want: true,
		},
		{
			name:    "Alpine: standard package",
			pkgName: "util-linux", version: "2.38.1-r0", pkgType: syftPkg.ApkPkg,
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
			name:    "Alpine: 5-digit rev without rootio name IS rootio (upstream-named model)",
			pkgName: "libssl3", version: "3.1.8-r00073", pkgType: syftPkg.ApkPkg,
			want: true,
		},
		{
			name:    "Debian: rootio- prefix with .root.io.N suffix",
			pkgName: "rootio-imagemagick", version: "8:6.9.11.root.io.1", pkgType: syftPkg.DebPkg,
			want: true,
		},
		{
			name:    "Debian: rootio- prefix only",
			pkgName: "rootio-imagemagick", version: "8:6.9.11", pkgType: syftPkg.DebPkg,
			want: true,
		},
		{
			name:    "Debian: standard package",
			pkgName: "imagemagick", version: "8:6.9.11", pkgType: syftPkg.DebPkg,
			want: false,
		},
		{
			name:    "NPM: @rootio/ scoped package",
			pkgName: "@rootio/semver", version: "7.5.4", pkgType: syftPkg.NpmPkg,
			want: true,
		},
		{
			name:    "NPM: rootio- prefix",
			pkgName: "rootio-semver", version: "7.5.4", pkgType: syftPkg.NpmPkg,
			want: true,
		},
		{
			name:    "NPM: version suffix only",
			pkgName: "semver", version: "7.5.4-root.io.1", pkgType: syftPkg.NpmPkg,
			want: true,
		},
		{
			name:    "NPM: standard package",
			pkgName: "semver", version: "7.5.4", pkgType: syftPkg.NpmPkg,
			want: false,
		},
		{
			name:    "PyPI: rootio_ prefix with +root.io.N suffix",
			pkgName: "rootio_requests", version: "2.31.0+root.io.1", pkgType: syftPkg.PythonPkg,
			want: true,
		},
		{
			name:    "PyPI: rootio_ prefix only",
			pkgName: "rootio_requests", version: "2.31.0", pkgType: syftPkg.PythonPkg,
			want: true,
		},
		{
			name:    "PyPI: +root.io.N suffix only",
			pkgName: "requests", version: "2.31.0+root.io.1", pkgType: syftPkg.PythonPkg,
			want: true,
		},
		{
			name:    "PyPI: standard package",
			pkgName: "requests", version: "2.31.0", pkgType: syftPkg.PythonPkg,
			want: false,
		},
		{
			// Realistic Syft shape: artifactID alone in name; the rootio marker
			// io.root. lives in JavaMetadata.PomGroupID, passed here as javaGroupID.
			name:    "Java: groupID prefix passed via javaGroupID arg (realistic Syft shape)",
			pkgName: "spring-core", version: "5.3.30", pkgType: syftPkg.JavaPkg,
			javaGroupID: "io.root.org.springframework",
			want:        true,
		},
		{
			// Hand-built shape: some callers pre-compose group:artifact in the name.
			name:    "Java: io.root. prefix on name (legacy hand-built shape)",
			pkgName: "io.root.org.springframework:spring-core", version: "5.3.30", pkgType: syftPkg.JavaPkg,
			want: true,
		},
		{
			name:    "Java: standard package, no rootio signal",
			pkgName: "spring-core", version: "5.3.30", pkgType: syftPkg.JavaPkg,
			javaGroupID: "org.springframework",
			want:        false,
		},
		{
			name:    "Java: rootio groupID alone is sufficient",
			pkgName: "spring-core", version: "5.3.30", pkgType: syftPkg.JavaPkg,
			javaGroupID: "io.root.org.springframework",
			want:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, IsPackage(tt.pkgName, tt.version, tt.pkgType, tt.javaGroupID))
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

func TestAddPrefix(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		pkgType syftPkg.Type
		want    string
	}{
		// canonical "bare upstream name" → "rootio-prefixed" inversion
		{name: "Alpine bare", input: "libssl3", pkgType: syftPkg.ApkPkg, want: "rootio-libssl3"},
		{name: "Debian bare binary", input: "libgcrypt20", pkgType: syftPkg.DebPkg, want: "rootio-libgcrypt20"},
		{name: "Debian bare source", input: "pam", pkgType: syftPkg.DebPkg, want: "rootio-pam"},
		{name: "NPM unscoped bare", input: "semver", pkgType: syftPkg.NpmPkg, want: "@rootio/semver"},
		{name: "NPM scoped bare uses __ encoding", input: "@babel/core", pkgType: syftPkg.NpmPkg, want: "@rootio/babel__core"},
		{name: "PyPI bare", input: "requests", pkgType: syftPkg.PythonPkg, want: "rootio-requests"},
		{name: "Java bare groupID", input: "org.springframework", pkgType: syftPkg.JavaPkg, want: "io.root.org.springframework"},

		// idempotent: already-prefixed input returns unchanged so duplicate
		// search-name entries don't leak through the resolver fanout.
		{name: "Alpine already prefixed", input: "rootio-libssl3", pkgType: syftPkg.ApkPkg, want: "rootio-libssl3"},
		{name: "Debian already prefixed", input: "rootio-pam", pkgType: syftPkg.DebPkg, want: "rootio-pam"},
		{name: "NPM already @rootio scoped", input: "@rootio/semver", pkgType: syftPkg.NpmPkg, want: "@rootio/semver"},
		{name: "PyPI already underscore prefixed", input: "rootio_requests", pkgType: syftPkg.PythonPkg, want: "rootio_requests"},
		{name: "PyPI already hyphen prefixed", input: "rootio-requests", pkgType: syftPkg.PythonPkg, want: "rootio-requests"},
		{name: "Java already prefixed", input: "io.root.org.springframework", pkgType: syftPkg.JavaPkg, want: "io.root.org.springframework"},

		// degenerate inputs
		{name: "empty string", input: "", pkgType: syftPkg.DebPkg, want: ""},
		{name: "NPM scoped with no name returns empty", input: "@scope/", pkgType: syftPkg.NpmPkg, want: "@rootio/scope__"},
		{name: "NPM '@' alone is malformed → empty", input: "@", pkgType: syftPkg.NpmPkg, want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, AddPrefix(tt.input, tt.pkgType))
		})
	}
}

// TestStripAddPrefix_RoundTrip locks in that AddPrefix and StripPrefix are
// mutual inverses for the names rootio uses in its dataset. Round-tripping
// matters because the resolver fanout appends both StripPrefix(n) and
// AddPrefix(n) to the search list; if the two drift, the matcher would search
// inconsistent name spaces for affected vs unaffected lookups.
func TestStripAddPrefix_RoundTrip(t *testing.T) {
	cases := []struct {
		name    string
		bare    string
		pkgType syftPkg.Type
	}{
		{"deb binary", "libgcrypt20", syftPkg.DebPkg},
		{"deb source", "pam", syftPkg.DebPkg},
		{"apk", "libssl3", syftPkg.ApkPkg},
		{"npm unscoped", "semver", syftPkg.NpmPkg},
		{"npm scoped", "@babel/core", syftPkg.NpmPkg},
		{"pypi", "requests", syftPkg.PythonPkg},
		{"java group", "org.springframework", syftPkg.JavaPkg},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			prefixed := AddPrefix(tc.bare, tc.pkgType)
			bareAgain := StripPrefix(prefixed, tc.pkgType)
			assert.Equal(t, tc.bare, bareAgain, "AddPrefix → StripPrefix should be identity on the upstream name")
		})
	}
}

func TestHasPrefix(t *testing.T) {
	tests := []struct {
		name        string
		pkgName     string
		pkgType     syftPkg.Type
		javaGroupID string
		want        bool
	}{
		{name: "rootio- prefix for Alpine", pkgName: "rootio-util-linux", pkgType: syftPkg.ApkPkg, want: true},
		{name: "rootio- prefix for Debian", pkgName: "rootio-imagemagick", pkgType: syftPkg.DebPkg, want: true},
		{name: "@rootio/ scoped NPM package", pkgName: "@rootio/semver", pkgType: syftPkg.NpmPkg, want: true},
		{name: "rootio- prefix for NPM", pkgName: "rootio-semver", pkgType: syftPkg.NpmPkg, want: true},
		{name: "rootio_ prefix for PyPI", pkgName: "rootio_requests", pkgType: syftPkg.PythonPkg, want: true},
		{name: "no prefix", pkgName: "util-linux", pkgType: syftPkg.ApkPkg, want: false},
		{name: "empty string", pkgName: "", pkgType: syftPkg.ApkPkg, want: false},
		{
			name:        "Java: groupID via javaGroupID arg",
			pkgName:     "spring-core",
			pkgType:     syftPkg.JavaPkg,
			javaGroupID: "io.root.org.springframework",
			want:        true,
		},
		{
			name:    "Java: io.root. prefix on name (hand-built)",
			pkgName: "io.root.org.springframework:spring-core",
			pkgType: syftPkg.JavaPkg,
			want:    true,
		},
		{
			name:        "Java: standard groupId without io.root. prefix",
			pkgName:     "spring-core",
			pkgType:     syftPkg.JavaPkg,
			javaGroupID: "org.springframework",
			want:        false,
		},
		{name: "name containing root but not prefix", pkgName: "myroot-package", pkgType: syftPkg.ApkPkg, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, hasPrefix(tt.pkgName, tt.pkgType, tt.javaGroupID))
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
