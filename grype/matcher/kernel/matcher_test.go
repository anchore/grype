package kernel

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/grype/vulnerability/mock"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

func TestMatcher_PackageTypes(t *testing.T) {
	m := NewKernelMatcher(MatcherConfig{})
	assert.Equal(t, []syftPkg.Type{syftPkg.LinuxKernelPkg}, m.PackageTypes())
}

func TestMatcher_Type(t *testing.T) {
	m := NewKernelMatcher(MatcherConfig{})
	assert.Equal(t, match.KernelMatcher, m.Type())
}

func TestHasReliableKernelData(t *testing.T) {
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
			name:     "Ubuntu has reliable kernel data",
			distro:   distro.New(distro.Ubuntu, "22.04", ""),
			expected: true,
		},
		{
			name:     "Debian has reliable kernel data",
			distro:   distro.New(distro.Debian, "11", ""),
			expected: true,
		},
		{
			name:     "RedHat has reliable kernel data",
			distro:   distro.New(distro.RedHat, "8", ""),
			expected: true,
		},
		{
			name:     "Fedora has reliable kernel data",
			distro:   distro.New(distro.Fedora, "38", ""),
			expected: true,
		},
		{
			name:     "Alpine has reliable kernel data",
			distro:   distro.New(distro.Alpine, "3.18", ""),
			expected: true,
		},
		{
			name:     "SLES has reliable kernel data",
			distro:   distro.New(distro.SLES, "15", ""),
			expected: true,
		},
		{
			name:     "AmazonLinux has reliable kernel data",
			distro:   distro.New(distro.AmazonLinux, "2", ""),
			expected: true,
		},
		{
			name:     "ArchLinux does not have reliable kernel data",
			distro:   distro.New(distro.ArchLinux, "", ""),
			expected: false,
		},
		{
			name:     "Gentoo does not have reliable kernel data",
			distro:   distro.New(distro.Gentoo, "", ""),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := hasReliableKernelData(tt.distro)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMatcher_Match_UbuntuDistroMatching(t *testing.T) {
	matcher := NewKernelMatcher(MatcherConfig{UseCPEs: false})

	d := distro.New(distro.Ubuntu, "22.04", "jammy")

	p := pkg.Package{
		ID:      pkg.ID(uuid.NewString()),
		Name:    "linux-image-5.15.0-164-generic",
		Version: "5.15.0-164.171",
		Type:    syftPkg.LinuxKernelPkg,
		Distro:  d,
	}

	// Ubuntu backported fix to 5.15.0-79 so 5.15.0-164 should not be vuln
	vp := mock.VulnerabilityProvider(
		vulnerability.Vulnerability{
			PackageName: "linux-image-5.15.0-164-generic",
			Reference:   vulnerability.Reference{ID: "CVE-2023-2163", Namespace: "ubuntu:distro:ubuntu:22.04"},
			Constraint:  version.MustGetConstraint("< 5.15.0-79.86", version.DebFormat),
		},
	)

	matches, _, err := matcher.Match(vp, p)
	require.NoError(t, err)

	// Should not match cause 5.15.0-164.171 > 5.15.0-79.86 ( backported fix ver)
	assert.Empty(t, matches, "expected no matches for kernel pkg with backported fix")
}

func TestMatcher_Match_UbuntuVulnerableKernel(t *testing.T) {
	matcher := NewKernelMatcher(MatcherConfig{UseCPEs: false})

	d := distro.New(distro.Ubuntu, "22.04", "jammy")

	// old kernel ver that IS vuln
	p := pkg.Package{
		ID:      pkg.ID(uuid.NewString()),
		Name:    "linux-image-5.15.0-50-generic",
		Version: "5.15.0-50.56",
		Type:    syftPkg.LinuxKernelPkg,
		Distro:  d,
	}

	vp := mock.VulnerabilityProvider(
		vulnerability.Vulnerability{
			PackageName: "linux-image-5.15.0-50-generic",
			Reference:   vulnerability.Reference{ID: "CVE-2023-2163", Namespace: "ubuntu:distro:ubuntu:22.04"},
			Constraint:  version.MustGetConstraint("< 5.15.0-79.86", version.DebFormat),
		},
	)

	matches, _, err := matcher.Match(vp, p)
	require.NoError(t, err)

	// should match cause 5.15.0-50.56 < 5.15.0-79.86
	assert.Len(t, matches, 1, "expected one match for vuln kernel pkg")
	if len(matches) > 0 {
		assert.Equal(t, "CVE-2023-2163", matches[0].Vulnerability.ID)
		assert.Equal(t, match.KernelMatcher, matches[0].Details[0].Matcher)
	}
}

func TestMatcher_Match_UpstreamPackages(t *testing.T) {
	matcher := NewKernelMatcher(MatcherConfig{UseCPEs: false})

	d := distro.New(distro.Ubuntu, "22.04", "jammy")

	p := pkg.Package{
		ID:      pkg.ID(uuid.NewString()),
		Name:    "linux-image-5.15.0-50-generic",
		Version: "5.15.0-50.56",
		Type:    syftPkg.LinuxKernelPkg,
		Distro:  d,
		Upstreams: []pkg.UpstreamPackage{
			{
				Name: "linux",
			},
		},
	}

	vp := mock.VulnerabilityProvider(
		vulnerability.Vulnerability{
			PackageName: "linux",
			Reference:   vulnerability.Reference{ID: "CVE-2023-1234", Namespace: "ubuntu:distro:ubuntu:22.04"},
			Constraint:  version.MustGetConstraint("< 5.15.0-79.86", version.DebFormat),
		},
	)

	matches, _, err := matcher.Match(vp, p)
	require.NoError(t, err)

	// should match via upstream pkg
	assert.Len(t, matches, 1, "expected one indirect match")
	if len(matches) > 0 {
		assert.Equal(t, "CVE-2023-1234", matches[0].Vulnerability.ID)
		assert.Equal(t, match.ExactIndirectMatch, matches[0].Details[0].Type)
		assert.Equal(t, p.Name, matches[0].Package.Name, "should track original pkg name")
	}
}

func TestMatcher_Match_NoDistro(t *testing.T) {
	matcher := NewKernelMatcher(MatcherConfig{UseCPEs: false})

	p := pkg.Package{
		ID:      pkg.ID(uuid.NewString()),
		Name:    "linux-image-5.15.0-164-generic",
		Version: "5.15.0-164.171",
		Type:    syftPkg.LinuxKernelPkg,
		Distro:  nil,
	}

	vp := mock.VulnerabilityProvider()

	matches, _, err := matcher.Match(vp, p)
	require.NoError(t, err)
	assert.Empty(t, matches, "expected no matches when distro is nil and UseCPEs is false")
}

func TestMatcher_Match_UnknownDistroWithCPEFallback(t *testing.T) {
	matcher := NewKernelMatcher(MatcherConfig{UseCPEs: true})

	// distro doesnt have reliable kernel data
	d := distro.New(distro.ArchLinux, "", "")

	p := pkg.Package{
		ID:      pkg.ID(uuid.NewString()),
		Name:    "linux",
		Version: "6.1.0",
		Type:    syftPkg.LinuxKernelPkg,
		Distro:  d,
	}

	vp := mock.VulnerabilityProvider()

	matches, _, err := matcher.Match(vp, p)
	require.NoError(t, err)
	assert.Empty(t, matches)
}

func TestMatcher_Match_UnknownDistroWithoutCPEFallback(t *testing.T) {
	matcher := NewKernelMatcher(MatcherConfig{UseCPEs: false})

	// distro doesnt have reliable kernel data
	d := distro.New(distro.ArchLinux, "", "")

	p := pkg.Package{
		ID:      pkg.ID(uuid.NewString()),
		Name:    "linux",
		Version: "6.1.0",
		Type:    syftPkg.LinuxKernelPkg,
		Distro:  d,
	}

	vp := mock.VulnerabilityProvider(
		vulnerability.Vulnerability{
			PackageName: "linux",
			Reference:   vulnerability.Reference{ID: "CVE-2023-9999", Namespace: "nvd:cpe"},
			Constraint:  version.MustGetConstraint("< 6.2.0", version.SemanticFormat),
		},
	)

	matches, _, err := matcher.Match(vp, p)
	require.NoError(t, err)
	assert.Empty(t, matches, "expected no matches when distro has no reliable data and UseCPEs is false")
}
