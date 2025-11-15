package common

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

func TestIsRootIoPackage(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    bool
	}{
		{
			name:    "package with root.io marker",
			version: "1.2.3.root.io.1",
			want:    true,
		},
		{
			name:    "package with root.io in middle",
			version: "1.2.root.io.3",
			want:    true,
		},
		{
			name:    "regular package version",
			version: "1.2.3",
			want:    false,
		},
		{
			name:    "package with similar string",
			version: "1.2.3-rootio",
			want:    false,
		},
		{
			name:    "empty version",
			version: "",
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := pkg.Package{
				Version: tt.version,
			}
			got := IsRootIoPackage(p)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestGetRootIoDistroName(t *testing.T) {
	tests := []struct {
		name       string
		distroType distro.Type
		want       string
	}{
		{
			name:       "alpine maps to alpine",
			distroType: distro.Alpine,
			want:       "alpine",
		},
		{
			name:       "wolfi maps to alpine",
			distroType: distro.Wolfi,
			want:       "alpine",
		},
		{
			name:       "chainguard maps to alpine",
			distroType: distro.Chainguard,
			want:       "alpine",
		},
		{
			name:       "debian stays debian",
			distroType: distro.Debian,
			want:       "debian",
		},
		{
			name:       "ubuntu stays ubuntu",
			distroType: distro.Ubuntu,
			want:       "ubuntu",
		},
		{
			name:       "centos stays centos",
			distroType: distro.CentOS,
			want:       "centos",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getRootIoDistroName(tt.distroType)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestFilterRootIoUnaffectedMatches_NoMatches(t *testing.T) {
	// Test early return when there are no matches
	store := &mockStore{}
	p := pkg.Package{
		Name:    "test-package",
		Version: "1.0.0.root.io.1",
		Type:    syftPkg.ApkPkg,
	}
	p.SetDistro(distro.Distro{
		Type: distro.Alpine,
		Version: &distro.Version{
			Raw: "3.17",
		},
	})

	matches := []match.Match{}
	result := FilterRootIoUnaffectedMatches(store, p, matches)
	assert.Equal(t, matches, result)
	assert.False(t, store.called, "store should not be called with empty matches")
}

func TestFilterRootIoUnaffectedMatches_NonRootIoPackage(t *testing.T) {
	// Test early return for non-Root.io packages
	store := &mockStore{}
	p := pkg.Package{
		Name:    "test-package",
		Version: "1.0.0", // No .root.io marker
		Type:    syftPkg.ApkPkg,
	}
	p.SetDistro(distro.Distro{
		Type: distro.Alpine,
		Version: &distro.Version{
			Raw: "3.17",
		},
	})

	matches := []match.Match{
		{
			Vulnerability: vulnerability.Vulnerability{
				ID: "CVE-2023-1234",
			},
		},
	}

	result := FilterRootIoUnaffectedMatches(store, p, matches)
	assert.Equal(t, matches, result)
	assert.False(t, store.called, "store should not be called for non-Root.io packages")
}

func TestFilterRootIoUnaffectedMatches_FiltersCorrectly(t *testing.T) {
	// Test that unaffected vulnerabilities are filtered out
	store := &mockStore{
		vulnerabilities: []vulnerability.Vulnerability{
			{
				ID:        "CVE-2023-1234",
				Namespace: "rootio:distro:alpine:3.17",
				Fix: vulnerability.Fix{
					Versions: []string{"ROOTIO_UNAFFECTED"},
				},
			},
		},
	}

	p := pkg.Package{
		Name:    "test-package",
		Version: "1.0.0.root.io.1",
		Type:    syftPkg.ApkPkg,
	}
	p.SetDistro(distro.Distro{
		Type: distro.Alpine,
		Version: &distro.Version{
			Raw: "3.17",
		},
	})

	matches := []match.Match{
		{
			Vulnerability: vulnerability.Vulnerability{
				ID: "CVE-2023-1234", // Should be filtered
			},
		},
		{
			Vulnerability: vulnerability.Vulnerability{
				ID: "CVE-2023-5678", // Should remain
			},
		},
	}

	result := FilterRootIoUnaffectedMatches(store, p, matches)
	require.Len(t, result, 1)
	assert.Equal(t, "CVE-2023-5678", result[0].Vulnerability.ID)
	assert.True(t, store.called, "store should be called")
}

func TestFilterRootIoUnaffectedMatchesForLanguage(t *testing.T) {
	// Test language-specific filtering
	store := &mockStore{
		vulnerabilities: []vulnerability.Vulnerability{
			{
				ID:        "CVE-2023-1234",
				Namespace: "rootio:language:python",
				Fix: vulnerability.Fix{
					Versions: []string{"ROOTIO_UNAFFECTED"},
				},
			},
		},
	}

	p := pkg.Package{
		Name:    "requests",
		Version: "2.28.0.root.io.1",
		Type:    syftPkg.PythonPkg,
	}

	matches := []match.Match{
		{
			Vulnerability: vulnerability.Vulnerability{
				ID: "CVE-2023-1234", // Should be filtered
			},
		},
		{
			Vulnerability: vulnerability.Vulnerability{
				ID: "CVE-2023-5678", // Should remain
			},
		},
	}

	result := FilterRootIoUnaffectedMatchesForLanguage(store, p, "python", matches)
	require.Len(t, result, 1)
	assert.Equal(t, "CVE-2023-5678", result[0].Vulnerability.ID)
}

// mockStore implements a minimal vulnerability.Provider for testing
type mockStore struct {
	vulnerabilities []vulnerability.Vulnerability
	called          bool
}

func (m *mockStore) PackageSearchNames(_ pkg.Package) []string {
	return nil
}

func (m *mockStore) FindVulnerabilities(criteria ...vulnerability.Criteria) ([]vulnerability.Vulnerability, error) {
	m.called = true
	// Simple mock - just return configured vulnerabilities
	return m.vulnerabilities, nil
}

func (m *mockStore) VulnerabilityMetadata(_ vulnerability.Reference) (*vulnerability.Metadata, error) {
	return nil, nil
}

func (m *mockStore) Close() error {
	return nil
}
