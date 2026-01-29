package kernel

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability/mock"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

func TestMatcher_PackageTypes(t *testing.T) {
	m := Matcher{}
	assert.Equal(t, []syftPkg.Type{syftPkg.LinuxKernelPkg}, m.PackageTypes())
}

func TestMatcher_Type(t *testing.T) {
	m := Matcher{}
	assert.Equal(t, match.KernelMatcher, m.Type())
}

func TestMatcher_Match_UbuntuKernel_ReturnsNoMatches(t *testing.T) {
	// Ubuntu kernel packages should return no matches from kernel matcher.
	// Vulnerabilities are found via dpkg matcher with distro-specific data.
	m := Matcher{}
	d := distro.New(distro.Ubuntu, "22.04", "")

	p := pkg.Package{
		ID:      pkg.ID(uuid.NewString()),
		Name:    "linux-image-5.15.0-50-generic",
		Version: "5.15.0-50.56",
		Type:    syftPkg.LinuxKernelPkg,
		Distro:  d,
	}

	store := mock.VulnerabilityProvider()
	matches, ignores, err := m.Match(store, p)

	require.NoError(t, err)
	assert.Empty(t, matches)
	assert.Empty(t, ignores)
}

func TestMatcher_Match_NilDistro_ReturnsNoMatches(t *testing.T) {
	m := Matcher{}

	p := pkg.Package{
		ID:      pkg.ID(uuid.NewString()),
		Name:    "linux",
		Version: "5.15.0",
		Type:    syftPkg.LinuxKernelPkg,
		Distro:  nil,
	}

	store := mock.VulnerabilityProvider()
	matches, ignores, err := m.Match(store, p)

	require.NoError(t, err)
	assert.Empty(t, matches)
	assert.Empty(t, ignores)
}

func TestHasBackportedKernelFixes(t *testing.T) {
	tests := []struct {
		name     string
		distro   *distro.Distro
		expected bool
	}{
		{
			name:     "nil distro",
			distro:   nil,
			expected: false,
		},
		{
			name:     "Ubuntu has backported fixes",
			distro:   distro.New(distro.Ubuntu, "22.04", ""),
			expected: true,
		},
		{
			name:     "Alpine no backported fixes",
			distro:   distro.New(distro.Alpine, "3.18", ""),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, hasBackportedKernelFixes(tt.distro))
		})
	}
}
