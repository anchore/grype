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

func TestFilterRootIoUnaffectedMatches_NoMatches(t *testing.T) {
	store := &mockStore{}
	p := pkg.Package{
		Name:    "test-package",
		Version: "1.0.0.root.io.1",
		Type:    syftPkg.ApkPkg,
		Distro: &distro.Distro{
			Type:    distro.Alpine,
			Version: "3.17",
		},
	}

	matches := []match.Match{}
	result := FilterRootIoUnaffectedMatches(store, p, matches)
	assert.Equal(t, matches, result)
	assert.False(t, store.findUnaffectedCalled)
}

func TestFilterRootIoUnaffectedMatches_NoDistro(t *testing.T) {
	store := &mockStore{}
	p := pkg.Package{
		Name:    "test-package",
		Version: "1.0.0.root.io.1",
		Type:    syftPkg.ApkPkg,
		Distro:  nil,
	}

	matches := []match.Match{
		{
			Vulnerability: vulnerability.Vulnerability{
				Reference: vulnerability.Reference{
					ID: "CVE-2023-1234",
				},
			},
		},
	}

	result := FilterRootIoUnaffectedMatches(store, p, matches)
	assert.Equal(t, matches, result)
	assert.False(t, store.findUnaffectedCalled)
}

func TestFilterRootIoUnaffectedMatches_NoUnaffectedInDB(t *testing.T) {
	store := &mockStore{
		unaffectedPackages: []vulnerability.UnaffectedPackage{},
	}

	p := pkg.Package{
		Name:    "libssl3",
		Version: "3.0.8-r4.root.io.1",
		Type:    syftPkg.ApkPkg,
	}
	p.Distro = &distro.Distro{
		Type:    distro.Alpine,
		Version: "3.17",
	}

	matches := []match.Match{
		{
			Vulnerability: vulnerability.Vulnerability{
				Reference: vulnerability.Reference{
					ID: "CVE-2023-0464",
				},
			},
		},
		{
			Vulnerability: vulnerability.Vulnerability{
				Reference: vulnerability.Reference{
					ID: "CVE-2023-0465",
				},
			},
		},
	}

	result := FilterRootIoUnaffectedMatches(store, p, matches)
	assert.Len(t, result, 2)
	assert.True(t, store.findUnaffectedCalled)
}

func TestFilterRootIoUnaffectedMatches_FiltersCVEInDB(t *testing.T) {
	store := &mockStore{
		unaffectedPackages: []vulnerability.UnaffectedPackage{
			{
				CVE:        "CVE-2023-0464",
				Package:    "libssl3",
				Constraint: "version_contains .root.io",
			},
		},
	}

	p := pkg.Package{
		Name:    "libssl3",
		Version: "3.0.8-r4.root.io.1",
		Type:    syftPkg.ApkPkg,
	}
	p.Distro = &distro.Distro{
		Type:    distro.Alpine,
		Version: "3.17",
	}

	matches := []match.Match{
		{
			Vulnerability: vulnerability.Vulnerability{
				Reference: vulnerability.Reference{
					ID: "CVE-2023-0464",
				}, // Should be filtered
			},
		},
		{
			Vulnerability: vulnerability.Vulnerability{
				Reference: vulnerability.Reference{
					ID: "CVE-2023-0465",
				}, // Should remain (not in unaffected list)
			},
		},
	}

	result := FilterRootIoUnaffectedMatches(store, p, matches)
	require.Len(t, result, 1)
	assert.Equal(t, "CVE-2023-0465", result[0].Vulnerability.ID)
	assert.True(t, store.findUnaffectedCalled)
}

func TestFilterRootIoUnaffectedMatches_KeepsCVENotInDB(t *testing.T) {
	store := &mockStore{
		unaffectedPackages: []vulnerability.UnaffectedPackage{
			{
				CVE:        "CVE-2023-0464",
				Package:    "libssl3",
				Constraint: "version_contains .root.io",
			},
		},
	}

	p := pkg.Package{
		Name:    "libssl3",
		Version: "3.0.8-r4.root.io.1",
		Type:    syftPkg.ApkPkg,
	}
	p.Distro = &distro.Distro{
		Type:    distro.Alpine,
		Version: "3.17",
	}

	matches := []match.Match{
		{
			Vulnerability: vulnerability.Vulnerability{
				Reference: vulnerability.Reference{
					ID: "CVE-2023-9999",
				},
			},
		},
	}

	result := FilterRootIoUnaffectedMatches(store, p, matches)
	require.Len(t, result, 1)
	assert.Equal(t, "CVE-2023-9999", result[0].Vulnerability.ID)
}

func TestFilterRootIoUnaffectedMatches_KeepsCVEWhenVersionDoesntMatch(t *testing.T) {
	store := &mockStore{
		unaffectedPackages: []vulnerability.UnaffectedPackage{
			{
				CVE:        "CVE-2023-0464",
				Package:    "libssl3",
				Constraint: "version_contains .root.io",
			},
		},
	}

	p := pkg.Package{
		Name:    "libssl3",
		Version: "3.0.8-r4",
		Type:    syftPkg.ApkPkg,
	}
	p.Distro = &distro.Distro{
		Type:    distro.Alpine,
		Version: "3.17",
	}

	matches := []match.Match{
		{
			Vulnerability: vulnerability.Vulnerability{
				Reference: vulnerability.Reference{
					ID: "CVE-2023-0464",
				},
			},
		},
	}

	result := FilterRootIoUnaffectedMatches(store, p, matches)
	require.Len(t, result, 1)
	assert.Equal(t, "CVE-2023-0464", result[0].Vulnerability.ID)
}

func TestFilterRootIoUnaffectedMatches_MultipleCVEs(t *testing.T) {
	store := &mockStore{
		unaffectedPackages: []vulnerability.UnaffectedPackage{
			{
				CVE:        "CVE-2023-0464",
				Package:    "libssl3",
				Constraint: "version_contains .root.io",
			},
			{
				CVE:        "CVE-2023-0465",
				Package:    "libssl3",
				Constraint: "version_contains .root.io",
			},
		},
	}

	p := pkg.Package{
		Name:    "libssl3",
		Version: "3.0.8-r4.root.io.1",
		Type:    syftPkg.ApkPkg,
	}
	p.Distro = &distro.Distro{
		Type:    distro.Alpine,
		Version: "3.17",
	}

	matches := []match.Match{
		{
			Vulnerability: vulnerability.Vulnerability{
				Reference: vulnerability.Reference{
					ID: "CVE-2023-0464",
				},
			},
		},
		{
			Vulnerability: vulnerability.Vulnerability{
				Reference: vulnerability.Reference{
					ID: "CVE-2023-0465",
				},
			},
		},
		{
			Vulnerability: vulnerability.Vulnerability{
				Reference: vulnerability.Reference{
					ID: "CVE-2023-9999",
				},
			},
		},
	}

	result := FilterRootIoUnaffectedMatches(store, p, matches)
	require.Len(t, result, 1)
	assert.Equal(t, "CVE-2023-9999", result[0].Vulnerability.ID)
}

func TestFilterRootIoUnaffectedMatchesForLanguage(t *testing.T) {
	store := &mockStore{
		unaffectedPackages: []vulnerability.UnaffectedPackage{
			{
				CVE:        "CVE-2023-1234",
				Package:    "requests",
				Constraint: "version_contains .root.io",
			},
		},
	}

	p := pkg.Package{
		Name:    "requests",
		Version: "2.28.0.root.io.1",
		Type:    syftPkg.PythonPkg,
	}
	p.Distro = &distro.Distro{
		Type:    distro.Debian,
		Version: "11",
	}

	matches := []match.Match{
		{
			Vulnerability: vulnerability.Vulnerability{
				Reference: vulnerability.Reference{
					ID: "CVE-2023-1234",
				},
			},
		},
		{
			Vulnerability: vulnerability.Vulnerability{
				Reference: vulnerability.Reference{
					ID: "CVE-2023-5678",
				},
			},
		},
	}

	result := FilterRootIoUnaffectedMatchesForLanguage(store, p, "python", matches)
	require.Len(t, result, 1)
	assert.Equal(t, "CVE-2023-5678", result[0].Vulnerability.ID)
}

type mockStore struct {
	unaffectedPackages   []vulnerability.UnaffectedPackage
	findUnaffectedCalled bool
	findUnaffectedError  error
}

func (m *mockStore) PackageSearchNames(_ pkg.Package) []string {
	return nil
}

func (m *mockStore) FindVulnerabilities(criteria ...vulnerability.Criteria) ([]vulnerability.Vulnerability, error) {
	return nil, nil
}

func (m *mockStore) FindUnaffectedPackages(_ pkg.Package, _ ...vulnerability.Criteria) ([]vulnerability.UnaffectedPackage, error) {
	m.findUnaffectedCalled = true
	if m.findUnaffectedError != nil {
		return nil, m.findUnaffectedError
	}
	return m.unaffectedPackages, nil
}

func (m *mockStore) VulnerabilityMetadata(_ vulnerability.Reference) (*vulnerability.Metadata, error) {
	return nil, nil
}

func (m *mockStore) Close() error {
	return nil
}
