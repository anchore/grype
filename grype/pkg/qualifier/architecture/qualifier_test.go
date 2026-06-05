package architecture

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/pkg"
)

// TestArchitecture_Arch covers the Arch() accessor used by criteria like
// SourceOrUnspecifiedArch — it must round-trip whatever string the transformer
// stored (including the two reserved sentinels and the unset empty string).
func TestArchitecture_Arch(t *testing.T) {
	tests := []struct {
		name string
		arch string
	}{
		{name: "source sentinel", arch: ArchSource},
		{name: "binary-no-arch-specified sentinel", arch: ArchBinaryNoArchSpecified},
		{name: "literal architecture", arch: "x86_64"},
		{name: "empty (provider does not distinguish)", arch: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q := New(tt.arch)
			archer, ok := q.(interface{ Arch() string })
			require.True(t, ok, "qualifier must expose Arch() so criteria can read the stored value")
			require.Equal(t, tt.arch, archer.Arch())
		})
	}
}

// TestArchitecture_Satisfied pins down the per-package gating logic. The
// qualifier short-circuits to true when the scanned package has no
// architecture recorded (older providers / non-PURL inputs that don't carry
// arch); otherwise it requires an exact string match against the vulnerability
// entry's stored arch. Mismatches filter the vuln out for the package.
func TestArchitecture_Satisfied(t *testing.T) {
	tests := []struct {
		name          string
		qualifierArch string
		pkgArch       string
		want          bool
	}{
		{
			// Inert path: no arch on the package means the provider didn't
			// surface one, so the qualifier cannot decide and must pass.
			// Preserves pre-change behavior for every input path that doesn't
			// populate p.Arch (today: any non-PURL provider).
			name:          "package without arch passes through specific qualifier",
			qualifierArch: "x86_64",
			pkgArch:       "",
			want:          true,
		},
		{
			name:          "package without arch passes through empty qualifier",
			qualifierArch: "",
			pkgArch:       "",
			want:          true,
		},
		{
			name:          "package arch matches qualifier",
			qualifierArch: "x86_64",
			pkgArch:       "x86_64",
			want:          true,
		},
		{
			name:          "package arch differs from qualifier filters out",
			qualifierArch: "x86_64",
			pkgArch:       "aarch64",
			want:          false,
		},
		{
			// Sentinels are compared as opaque strings; a package whose own
			// arch is literally "src" matches the source sentinel. RPM source
			// packages from PURLs (`?arch=src`) hit this path.
			name:          "package arch matches source sentinel literally",
			qualifierArch: ArchSource,
			pkgArch:       "src",
			want:          true,
		},
		{
			// The binary-no-arch sentinel is synthetic — no scanned package
			// will ever carry it as its actual arch, so any real arch on the
			// package mismatches it.
			name:          "concrete package arch does not match binary-no-arch sentinel",
			qualifierArch: ArchBinaryNoArchSpecified,
			pkgArch:       "x86_64",
			want:          false,
		},
		{
			// Documents current behavior: when the qualifier's arch is empty
			// but the package has a concrete arch, Satisfied filters the vuln
			// out. Transformers should emit a nil PackageQualifiers.Architecture
			// (not an empty string) when they don't know the arch, so this
			// case is defensive — it would only trigger if a future transformer
			// regressed and stored "" explicitly.
			name:          "empty qualifier with concrete package arch filters out",
			qualifierArch: "",
			pkgArch:       "x86_64",
			want:          false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q := New(tt.qualifierArch)
			got, err := q.Satisfied(pkg.Package{Arch: tt.pkgArch})
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}
