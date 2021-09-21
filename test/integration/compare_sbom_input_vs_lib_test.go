package integration

import (
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	"github.com/anchore/grype/grype"
	"github.com/anchore/grype/grype/db"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/internal"
	syftPkg "github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
	"github.com/scylladb/go-set/strset"
	"github.com/stretchr/testify/assert"
)

func TestCompareSBOMInputToLibResults(t *testing.T) {
	// TODO: cache images between runs and use the tar

	observedPkgTypes := strset.New()
	definedPkgTypes := strset.New()
	for _, p := range syftPkg.AllPkgs {
		definedPkgTypes.Add(string(p))
	}
	// exceptions: rust and msrc (kb) are not under test
	definedPkgTypes.Remove(string(syftPkg.RustPkg), string(syftPkg.KbPkg))

	cases := []struct {
		image string
	}{
		{
			"anchore/test_images:vulnerabilities-alpine",
		},
		{
			"anchore/test_images:gems",
		},
		{
			"anchore/test_images:vulnerabilities-debian",
		},
		{
			"anchore/test_images:vulnerabilities-centos",
		},
		{
			"anchore/test_images:npm",
		},
		{
			"anchore/engine-cli:v0.3.4",
		},
		{
			"anchore/test_images:java",
		},
		{
			"jenkins/jenkins:lts",
		},
		{
			"golangci/golangci-lint:latest-alpine",
		},
	}

	// get a grype DB
	vulnProvider, _, _, err := grype.LoadVulnerabilityDb(db.Config{
		DbRootDir:           "test-fixtures/grype-db",
		ListingURL:          internal.DBUpdateURL,
		ValidateByHashOnGet: false,
	}, true)
	assert.NoError(t, err)

	for _, test := range cases {
		t.Run(test.image, func(t *testing.T) {
			t.Logf("Running case %s", test.image)

			// get SBOM from syft, write to temp file
			sbomBytes := getSyftSBOM(t, test.image)
			sbomFile, err := ioutil.TempFile("", "")
			assert.NoError(t, err)
			t.Cleanup(func() {
				assert.NoError(t, os.Remove(sbomFile.Name()))
			})
			_, err = sbomFile.WriteString(sbomBytes)
			assert.NoError(t, err)
			assert.NoError(t, sbomFile.Close())

			// get vulns (sbom)
			matchesFromSbom, _, pkgsFromSbom, err := grype.FindVulnerabilities(vulnProvider, fmt.Sprintf("sbom:%s", sbomFile.Name()), source.SquashedScope, nil)
			assert.NoError(t, err)

			// get vulns (image)
			matchesFromImage, _, _, err := grype.FindVulnerabilities(vulnProvider, test.image, source.SquashedScope, nil)
			assert.NoError(t, err)

			// compare packages (shallow)
			matchSetFromSbom := getMatchSet(matchesFromSbom)
			matchSetFromImage := getMatchSet(matchesFromImage)

			assert.Empty(t, strset.SymmetricDifference(matchSetFromSbom, matchSetFromImage).List())

			// track all covered package types (for use after the test)
			for _, p := range pkgsFromSbom {
				observedPkgTypes.Add(string(p.Type))
			}

		})
	}

	// ensure we've covered all package types (-rust, -kb)
	unobservedPackageTypes := strset.Difference(definedPkgTypes, observedPkgTypes)
	assert.Empty(t, unobservedPackageTypes.List(), "not all package type were covered in testing")

}

func getMatchSet(matches match.Matches) *strset.Set {
	s := strset.New()
	for _, m := range matches.Sorted() {
		s.Add(fmt.Sprintf("%s-%s-%s-%s", m.Vulnerability.ID, m.Package.Name, m.Package.Version, string(m.Package.Type)))
	}
	return s
}
