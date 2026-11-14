package architecture

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestMatches pins down the arch matching rules, which are identical for affected and unaffected
// vulnerability entries: an unset value on either side always matches; a source package matches only
// src entries (in any spelling the alias table folds to src) and a src entry matches only source
// packages; between binaries, arch-independent (rpm "noarch", deb "all") and binary-no-arch values
// match anything, and concrete arches compare in canonical form. Dialect spellings are folded
// through the given alias table first (see TestCanonical).
func TestMatches(t *testing.T) {
	tests := []struct {
		name       string
		recordArch string            // arch stored on the vulnerability entry
		pkgArch    string            // arch of the scanned package
		aliases    map[string]string // alias table; nil uses DefaultAliases
		want       bool
	}{
		// unset
		{
			name:       "empty package arch / concrete entry -> matches",
			recordArch: "x86_64",
			pkgArch:    "",
			want:       true,
		},
		{
			name:       "concrete package / empty entry -> matches",
			recordArch: "",
			pkgArch:    "x86_64",
			want:       true,
		},
		{
			name:       "empty package arch / binary-no-arch entry -> matches",
			recordArch: ArchBinaryNoArchSpecified,
			pkgArch:    "",
			want:       true,
		},

		// arch-independent
		{
			name:       "noarch package / concrete entry -> matches",
			recordArch: "x86_64",
			pkgArch:    "noarch",
			want:       true,
		},
		{
			name:       "concrete package / noarch entry -> matches",
			recordArch: "noarch",
			pkgArch:    "aarch64",
			want:       true,
		},
		{
			name:       "noarch package / noarch entry -> matches",
			recordArch: "noarch",
			pkgArch:    "noarch",
			want:       true,
		},

		// source
		{
			name:       "source package / src entry -> matches",
			recordArch: ArchSource,
			pkgArch:    ArchSource,
			want:       true,
		},
		{
			// a binary reaches its own source's entries through its upstream search, so a source
			// package that only shares the binary's name does not apply to it
			name:       "binary package / src entry -> does not match",
			recordArch: ArchSource,
			pkgArch:    "x86_64",
			want:       false,
		},
		{
			name:       "source package / empty entry -> matches",
			recordArch: "",
			pkgArch:    ArchSource,
			want:       true,
		},
		{
			name:       "source package / concrete entry -> does not match",
			recordArch: "x86_64",
			pkgArch:    ArchSource,
			want:       false,
		},
		{
			// a noarch entry is a binary package's
			name:       "source package / noarch entry -> does not match",
			recordArch: "noarch",
			pkgArch:    ArchSource,
			want:       false,
		},
		{
			name:       "noarch package / src entry -> does not match",
			recordArch: ArchSource,
			pkgArch:    "noarch",
			want:       false,
		},
		{
			name:       "source package / src entry, different case -> matches",
			recordArch: "SRC",
			pkgArch:    ArchSource,
			want:       true,
		},
		{
			name:       "source package / deb 'source' entry, default aliases -> matches",
			recordArch: "source",
			pkgArch:    ArchSource,
			aliases:    DefaultAliases(),
			want:       true,
		},
		{
			name:       "deb 'source' package / src entry, default aliases -> matches",
			recordArch: ArchSource,
			pkgArch:    "source",
			aliases:    DefaultAliases(),
			want:       true,
		},
		{
			// a DB alias table can name source spellings the built-in defaults don't know about
			name:       "source package / entry spelled by the DB table -> matches",
			recordArch: "srpm",
			pkgArch:    ArchSource,
			aliases:    map[string]string{"srpm": ArchSource},
			want:       true,
		},
		{
			// the DB table replaces the defaults, so a spelling only the defaults fold is not a source
			name:       "source package / deb 'source' entry, DB table without it -> does not match",
			recordArch: "source",
			pkgArch:    ArchSource,
			aliases:    map[string]string{"srpm": ArchSource},
			want:       false,
		},

		// binary-no-arch
		{
			// keeps a binary record from matching through a synthesized src upstream
			name:       "source package / binary-no-arch entry -> does not match",
			recordArch: ArchBinaryNoArchSpecified,
			pkgArch:    ArchSource,
			want:       false,
		},
		{
			name:       "aarch64 package / binary-no-arch entry -> matches",
			recordArch: ArchBinaryNoArchSpecified,
			pkgArch:    "aarch64",
			want:       true,
		},
		{
			name:       "binary-no-arch package / binary-no-arch entry -> matches",
			recordArch: ArchBinaryNoArchSpecified,
			pkgArch:    ArchBinaryNoArchSpecified,
			want:       true,
		},
		{
			// a binary whose arch was not recorded cannot be ruled out by an arch-scoped entry
			name:       "binary-no-arch package / concrete entry -> matches",
			recordArch: "x86_64",
			pkgArch:    ArchBinaryNoArchSpecified,
			want:       true,
		},
		{
			name:       "binary-no-arch package / src entry -> does not match",
			recordArch: ArchSource,
			pkgArch:    ArchBinaryNoArchSpecified,
			want:       false,
		},
		{
			name:       "noarch package / binary-no-arch entry -> matches",
			recordArch: ArchBinaryNoArchSpecified,
			pkgArch:    "noarch",
			want:       true,
		},

		// concrete
		{
			name:       "same arch -> matches",
			recordArch: "aarch64",
			pkgArch:    "aarch64",
			want:       true,
		},
		{
			name:       "different arch -> does not match",
			recordArch: "aarch64",
			pkgArch:    "x86_64",
			want:       false,
		},
		{
			name:       "amd64 package / x86_64 entry, default aliases -> matches",
			recordArch: "x86_64",
			pkgArch:    "amd64",
			aliases:    DefaultAliases(),
			want:       true,
		},
		{
			name:       "deb 'all' package / concrete entry, default aliases -> matches",
			recordArch: "amd64",
			pkgArch:    "all",
			aliases:    DefaultAliases(),
			want:       true,
		},
		{
			name:       "deb 'source' package / binary-no-arch entry, default aliases -> does not match",
			recordArch: ArchBinaryNoArchSpecified,
			pkgArch:    "source",
			aliases:    DefaultAliases(),
			want:       false,
		},
		{
			name:       "amd64 package / x86_64 entry, nil aliases use the defaults -> matches",
			recordArch: "x86_64",
			pkgArch:    "amd64",
			want:       true,
		},
		{
			name:       "amd64 package / x86_64 entry, empty alias table -> does not match",
			recordArch: "x86_64",
			pkgArch:    "amd64",
			aliases:    map[string]string{},
			want:       false,
		},
		{
			name:       "source package / deb 'source' entry, empty alias table -> does not match",
			recordArch: "source",
			pkgArch:    ArchSource,
			aliases:    map[string]string{},
			want:       false,
		},
		{
			name:       "case and whitespace are ignored",
			recordArch: " X86_64",
			pkgArch:    "x86_64 ",
			want:       true,
		},
		{
			name:       "amd64 package / arm64 entry -> does not match",
			recordArch: "arm64",
			pkgArch:    "amd64",
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, Matches(tt.pkgArch, tt.recordArch, tt.aliases))
		})
	}
}

// TestCanonical pins that canonical normalizes and then folds architecture and role spellings through
// the given alias table, and only that table: a spelling absent from it is its own canonical form.
// The default-table cases also pin the built-in table (the fallback for pre-table databases and the
// seed source for the DB), including that every canonical token resolves to itself.
func TestCanonical(t *testing.T) {
	defaults := DefaultAliases()
	// a DB whose table folds a dialect the built-in defaults don't know about ("riscv64" =
	// "riscv") and intentionally omits the built-in amd64 fold.
	custom := map[string]string{"riscv64": "riscv"}

	tests := []struct {
		name    string
		in      string
		aliases map[string]string
		want    string
	}{
		{name: "empty", in: "", aliases: defaults, want: ""},
		{name: "x86_64 -> amd64", in: "x86_64", aliases: defaults, want: "amd64"},
		{name: "x86-64 -> amd64", in: "x86-64", aliases: defaults, want: "amd64"},
		{name: "canonical spelling is unchanged", in: "amd64", aliases: defaults, want: "amd64"},
		{name: "src is canonical", in: ArchSource, aliases: defaults, want: ArchSource},
		{name: "binary-no-arch-specified is canonical", in: ArchBinaryNoArchSpecified, aliases: defaults, want: ArchBinaryNoArchSpecified},
		{name: "noarch is canonical", in: "noarch", aliases: defaults, want: "noarch"},
		{name: "normalized before folding", in: " AArch64 ", aliases: defaults, want: "arm64"},
		{name: "i686 -> 386", in: "i686", aliases: defaults, want: "386"},
		{name: "ppc64el -> ppc64le", in: "ppc64el", aliases: defaults, want: "ppc64le"},
		{
			// 32-bit ARM spellings are not folded: the same name is a different ABI across ecosystems
			name: "armhf is not folded", in: "armhf", aliases: defaults, want: "armhf",
		},
		{name: "armv7hl is not folded", in: "armv7hl", aliases: defaults, want: "armv7hl"},
		{name: "deb source -> src", in: "source", aliases: defaults, want: ArchSource},
		{name: "deb all -> noarch", in: "all", aliases: defaults, want: "noarch"},
		{name: "deb any is not folded", in: "any", aliases: defaults, want: "any"},
		{name: "role spelling from the provided table", in: "sources", aliases: map[string]string{"sources": ArchSource}, want: ArchSource},
		{name: "role spelling absent from the provided table", in: "source", aliases: custom, want: "source"},
		{name: "provided table folds", in: "riscv64", aliases: custom, want: "riscv"},
		{name: "provided table is used exclusively", in: "x86_64", aliases: custom, want: "x86_64"},
		{name: "no table only normalizes", in: "X86_64", aliases: nil, want: "x86_64"},
		{name: "no table trims whitespace", in: " AArch64 ", aliases: nil, want: "aarch64"},
		{name: "no table lower-cases a role token", in: "SRC", aliases: nil, want: ArchSource},
		{name: "no table leaves a role spelling", in: "source", aliases: nil, want: "source"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, canonical(tt.in, tt.aliases))
		})
	}
}

func TestBinaryDefault(t *testing.T) {
	tests := []struct {
		name string
		arch string
		want string
	}{
		{name: "recorded arch is kept", arch: "x86_64", want: "x86_64"},
		{name: "source package is kept", arch: ArchSource, want: ArchSource},
		{name: "unrecorded arch is a binary", arch: "", want: ArchBinaryNoArchSpecified},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, BinaryDefault(tt.arch))
		})
	}
}

func TestIsSource(t *testing.T) {
	tests := []struct {
		arch string
		want bool
	}{
		{arch: ArchSource, want: true},
		{arch: "SRC", want: true},
		{arch: "source", want: true},
		{arch: "", want: false},
		{arch: "amd64", want: false},
		{arch: "all", want: false},
		{arch: ArchBinaryNoArchSpecified, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.arch, func(t *testing.T) {
			require.Equal(t, tt.want, IsSource(tt.arch))
		})
	}
}
