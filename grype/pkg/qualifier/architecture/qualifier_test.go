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
// qualifier is inert for non-APK packages (returns true); for packages with
// ApkMetadata it requires an exact string match against the vulnerability
// entry's stored arch. Mismatches filter the vuln out.
func TestArchitecture_Satisfied(t *testing.T) {
	tests := []struct {
		name          string
		qualifierArch string
		pkgMetadata   any
		want          bool
	}{
		{
			// Inert path: non-APK packages (no ApkMetadata) always pass through.
			name:          "non-APK package passes through specific qualifier",
			qualifierArch: "x86_64",
			pkgMetadata:   nil,
			want:          true,
		},
		{
			name:          "non-APK package passes through empty qualifier",
			qualifierArch: "",
			pkgMetadata:   pkg.JavaMetadata{},
			want:          true,
		},
		{
			name:          "APK package arch matches qualifier",
			qualifierArch: "x86_64",
			pkgMetadata:   pkg.ApkMetadata{Arch: "x86_64"},
			want:          true,
		},
		{
			name:          "APK package arch differs from qualifier filters out",
			qualifierArch: "x86_64",
			pkgMetadata:   pkg.ApkMetadata{Arch: "aarch64"},
			want:          false,
		},
		{
			// Sentinels are compared as opaque strings; an APK package whose
			// arch is literally "src" matches the source sentinel.
			name:          "APK package arch matches source sentinel literally",
			qualifierArch: ArchSource,
			pkgMetadata:   pkg.ApkMetadata{Arch: "src"},
			want:          true,
		},
		{
			// The binary-no-arch sentinel is synthetic — no scanned package
			// will ever carry it as its actual arch, so any real arch mismatches it.
			name:          "APK concrete arch does not match binary-no-arch sentinel",
			qualifierArch: ArchBinaryNoArchSpecified,
			pkgMetadata:   pkg.ApkMetadata{Arch: "x86_64"},
			want:          false,
		},
		{
			// Defensive: when the qualifier's arch is empty but the APK package
			// has a concrete arch, Satisfied filters the vuln out.
			name:          "APK concrete arch filters out empty qualifier",
			qualifierArch: "",
			pkgMetadata:   pkg.ApkMetadata{Arch: "x86_64"},
			want:          false,
		},
		{
			// APK with no arch recorded vs empty qualifier matches.
			name:          "APK without arch matches empty qualifier",
			qualifierArch: "",
			pkgMetadata:   pkg.ApkMetadata{Arch: ""},
			want:          true,
		},
		{
			// APK with no arch recorded passes through even a specific qualifier — we
			// cannot filter on an arch we don't have, so the qualifier is inert.
			name:          "APK without arch passes through specific qualifier",
			qualifierArch: "x86_64",
			pkgMetadata:   pkg.ApkMetadata{Arch: ""},
			want:          true,
		},
		{
			// Same inert behaviour for the binary-no-arch sentinel.
			name:          "APK without arch passes through binary-no-arch sentinel qualifier",
			qualifierArch: ArchBinaryNoArchSpecified,
			pkgMetadata:   pkg.ApkMetadata{Arch: ""},
			want:          true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q := New(tt.qualifierArch)
			got, err := q.Satisfied(pkg.Package{Metadata: tt.pkgMetadata})
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}
