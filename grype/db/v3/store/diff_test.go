package store

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"

	v3 "github.com/anchore/grype/grype/db/v3"
)

func Test_GetAllSerializedVulnerabilities(t *testing.T) {
	//GIVEN
	dbTempFile, err := ioutil.TempFile("", "grype-db-test-store")
	if err != nil {
		t.Fatalf("could not create temp file: %+v", err)
	}
	defer os.Remove(dbTempFile.Name())

	s, err := New(dbTempFile.Name(), true)
	if err != nil {
		t.Fatalf("could not create store: %+v", err)
	}

	//WHEN
	result, err := s.GetAllSerializedVulnerabilities()

	//THEN
	assert.NotNil(t, result)
	assert.NoError(t, err)
}

func Test_GetAllSerializedVulnerabilityMetadata(t *testing.T) {
	//GIVEN
	dbTempFile, err := ioutil.TempFile("", "grype-db-test-store")
	if err != nil {
		t.Fatalf("could not create temp file: %+v", err)
	}
	defer os.Remove(dbTempFile.Name())

	s, err := New(dbTempFile.Name(), true)
	if err != nil {
		t.Fatalf("could not create store: %+v", err)
	}

	//WHEN
	result, err := s.GetAllSerializedVulnerabilityMetadata()

	//THEN
	assert.NotNil(t, result)
	assert.NoError(t, err)
}

func Test_diffDatabaseTable(t *testing.T) {
	//GIVEN
	dbTempFile, err := ioutil.TempFile("", "grype-db-test-store")
	if err != nil {
		t.Fatalf("could not create temp file: %+v", err)
	}
	defer os.Remove(dbTempFile.Name())

	s1, err := New(dbTempFile.Name(), true)
	if err != nil {
		t.Fatalf("could not create store: %+v", err)
	}
	dbTempFile, err = ioutil.TempFile("", "grype-db-test-store")
	if err != nil {
		t.Fatalf("could not create temp file: %+v", err)
	}
	defer os.Remove(dbTempFile.Name())

	s2, err := New(dbTempFile.Name(), true)
	if err != nil {
		t.Fatalf("could not create store: %+v", err)
	}

	baseVulns := []v3.Vulnerability{
		{
			Namespace:         "github:python",
			ID:                "CVE-123-4567",
			PackageName:       "pypi:requests",
			VersionConstraint: "< 2.0 >= 1.29",
			CPEs:              []string{"cpe:2.3:pypi:requests:*:*:*:*:*:*"},
		},
		{
			Namespace:         "github:python",
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
			Fix: v3.Fix{
				State: v3.UnknownFixState,
			},
		},
	}
	targetVulns := []v3.Vulnerability{
		{
			Namespace:         "github:python",
			ID:                "CVE-123-4567",
			PackageName:       "pypi:requests",
			VersionConstraint: "< 2.0 >= 1.29",
			CPEs:              []string{"cpe:2.3:pypi:requests:*:*:*:*:*:*"},
		},
		{
			Namespace:         "github:go",
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
			Fix: v3.Fix{
				State: v3.WontFixState,
			},
		},
	}
	expectedDiffs := []v3.Diff{
		{
			Reason:    v3.DiffAdded,
			ID:        "GHSA-....-....",
			Namespace: "github:go",
		},
		{
			Reason:    v3.DiffChanged,
			ID:        "CVE-123-7654",
			Namespace: "npm",
		},
		{
			Reason:    v3.DiffRemoved,
			ID:        "CVE-123-4567",
			Namespace: "github:python",
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

	//THEN
	assert.NoError(t, err)
	assert.Equal(t, expectedDiffs, *result)
}
