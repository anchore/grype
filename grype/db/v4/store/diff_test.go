package store

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"

	v4 "github.com/anchore/grype/grype/db/v4"
)

func Test_GetAllVulnerabilities(t *testing.T) {
	//GIVEN
	dbTempFile := t.TempDir()
	s, err := New(dbTempFile, true)
	if err != nil {
		t.Fatalf("could not create store: %+v", err)
	}

	//WHEN
	result, err := s.GetAllVulnerabilities()

	//THEN
	assert.NotNil(t, result)
	assert.NoError(t, err)
}

func Test_GetAllVulnerabilityMetadata(t *testing.T) {
	//GIVEN
	dbTempFile := t.TempDir()
	s, err := New(dbTempFile, true)
	if err != nil {
		t.Fatalf("could not create store: %+v", err)
	}

	//WHEN
	result, err := s.GetAllVulnerabilityMetadata()

	//THEN
	assert.NotNil(t, result)
	assert.NoError(t, err)
}

func Test_Diff_Vulnerabilities(t *testing.T) {
	//GIVEN
	dbTempFile := t.TempDir()

	s1, err := New(dbTempFile, true)
	if err != nil {
		t.Fatalf("could not create store: %+v", err)
	}
	dbTempFile = t.TempDir()
	s2, err := New(dbTempFile, true)
	if err != nil {
		t.Fatalf("could not create store: %+v", err)
	}

	baseVulns := []v4.Vulnerability{
		{
			Namespace:         "github:language:python",
			ID:                "CVE-123-4567",
			PackageName:       "pypi:requests",
			VersionConstraint: "< 2.0 >= 1.29",
			CPEs:              []string{"cpe:2.3:pypi:requests:*:*:*:*:*:*"},
		},
		{
			Namespace:         "github:language:python",
			ID:                "CVE-123-4567",
			PackageName:       "pypi:requests",
			VersionConstraint: "< 3.0 >= 2.17",
			CPEs:              []string{"cpe:2.3:pypi:requests:*:*:*:*:*:*"},
		},
		{
			Namespace:         "npm",
			ID:                "CVE-123-7654",
			PackageName:       "npm:axios",
			VersionConstraint: "< 3.0 >= 2.17",
			CPEs:              []string{"cpe:2.3:npm:axios:*:*:*:*:*:*"},
			Fix: v4.Fix{
				State: v4.UnknownFixState,
			},
		},
	}
	targetVulns := []v4.Vulnerability{
		{
			Namespace:         "github:language:python",
			ID:                "CVE-123-4567",
			PackageName:       "pypi:requests",
			VersionConstraint: "< 2.0 >= 1.29",
			CPEs:              []string{"cpe:2.3:pypi:requests:*:*:*:*:*:*"},
		},
		{
			Namespace:         "github:language:go",
			ID:                "GHSA-....-....",
			PackageName:       "hashicorp:nomad",
			VersionConstraint: "< 3.0 >= 2.17",
			CPEs:              []string{"cpe:2.3:golang:hashicorp:nomad:*:*:*:*:*"},
		},
		{
			Namespace:         "npm",
			ID:                "CVE-123-7654",
			PackageName:       "npm:axios",
			VersionConstraint: "< 3.0 >= 2.17",
			CPEs:              []string{"cpe:2.3:npm:axios:*:*:*:*:*:*"},
			Fix: v4.Fix{
				State: v4.WontFixState,
			},
		},
	}
	expectedDiffs := []v4.Diff{
		{
			Reason:    v4.DiffChanged,
			ID:        "CVE-123-4567",
			Namespace: "github:language:python",
			Packages:  []string{"pypi:requests"},
		},
		{
			Reason:    v4.DiffChanged,
			ID:        "CVE-123-7654",
			Namespace: "npm",
			Packages:  []string{"npm:axios"},
		},
		{
			Reason:    v4.DiffAdded,
			ID:        "GHSA-....-....",
			Namespace: "github:language:go",
			Packages:  []string{"hashicorp:nomad"},
		},
	}

	for _, vuln := range baseVulns {
		s1.AddVulnerability(vuln)
	}
	for _, vuln := range targetVulns {
		s2.AddVulnerability(vuln)
	}

	//WHEN
	result, err := s1.DiffStore(s2)
	sort.SliceStable(*result, func(i, j int) bool {
		return (*result)[i].ID < (*result)[j].ID
	})

	//THEN
	assert.NoError(t, err)
	assert.Equal(t, expectedDiffs, *result)
}

func Test_Diff_Metadata(t *testing.T) {
	//GIVEN
	dbTempFile := t.TempDir()

	s1, err := New(dbTempFile, true)
	if err != nil {
		t.Fatalf("could not create store: %+v", err)
	}
	dbTempFile = t.TempDir()

	s2, err := New(dbTempFile, true)
	if err != nil {
		t.Fatalf("could not create store: %+v", err)
	}

	baseVulns := []v4.VulnerabilityMetadata{
		{
			Namespace:  "github:language:python",
			ID:         "CVE-123-4567",
			DataSource: "nvd",
		},
		{
			Namespace:  "github:language:python",
			ID:         "CVE-123-4567",
			DataSource: "nvd",
		},
		{
			Namespace:  "npm",
			ID:         "CVE-123-7654",
			DataSource: "nvd",
		},
	}
	targetVulns := []v4.VulnerabilityMetadata{
		{
			Namespace:  "github:language:go",
			ID:         "GHSA-....-....",
			DataSource: "nvd",
		},
		{
			Namespace:  "npm",
			ID:         "CVE-123-7654",
			DataSource: "vulndb",
		},
	}
	expectedDiffs := []v4.Diff{
		{
			Reason:    v4.DiffRemoved,
			ID:        "CVE-123-4567",
			Namespace: "github:language:python",
			Packages:  []string{},
		},
		{
			Reason:    v4.DiffChanged,
			ID:        "CVE-123-7654",
			Namespace: "npm",
			Packages:  []string{},
		},
		{
			Reason:    v4.DiffAdded,
			ID:        "GHSA-....-....",
			Namespace: "github:language:go",
			Packages:  []string{},
		},
	}

	for _, vuln := range baseVulns {
		s1.AddVulnerabilityMetadata(vuln)
	}
	for _, vuln := range targetVulns {
		s2.AddVulnerabilityMetadata(vuln)
	}

	//WHEN
	result, err := s1.DiffStore(s2)

	//THEN
	sort.SliceStable(*result, func(i, j int) bool {
		return (*result)[i].ID < (*result)[j].ID
	})

	assert.NoError(t, err)
	assert.Equal(t, expectedDiffs, *result)
}
