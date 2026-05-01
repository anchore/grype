package rpmarch

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/pkg"
)

func TestRpmArch_ArchAndInertSatisfied(t *testing.T) {
	tests := []struct {
		name string
		arch string
	}{
		{name: "source", arch: ArchSource},
		{name: "binary-no-arch-specified", arch: ArchBinaryNoArchSpecified},
		{name: "literal architecture", arch: "x86_64"},
		{name: "empty (provider does not distinguish)", arch: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q := New(tt.arch)

			ok, err := q.Satisfied(pkg.Package{Name: "anything"})
			require.NoError(t, err)
			require.True(t, ok, "Satisfied must always return true; the rpmarch value is consumed by SourceOrUnspecifiedArch, not by per-package qualifier evaluation")

			archer, ok := q.(interface{ Arch() string })
			require.True(t, ok, "qualifier must expose Arch() so criteria can read the stored value")
			require.Equal(t, tt.arch, archer.Arch())
		})
	}
}
