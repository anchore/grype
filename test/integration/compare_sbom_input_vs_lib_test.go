package integration

import (
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	"github.com/anchore/grype/grype"
	"github.com/anchore/grype/grype/db"
	"github.com/anchore/grype/internal"
	syftPkg "github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
	"github.com/stretchr/testify/assert"

	"github.com/scylladb/go-set/strset"
)

func TestCompareSBOMInputToLibResults(t *testing.T) {
	images := []string{
		"anchore/test_images:vulnerabilities-alpine",
		"anchore/test_images:gems",
		"anchore/test_images:vulnerabilities-debian",
		"anchore/test_images:vulnerabilities-centos",
		"anchore/test_images:npm",
		"anchore/test_images:java",
		"anchore/test_images:golang",
	}

	// get a grype DB
	vulnProvider, _, _, err := grype.LoadVulnerabilityDB(db.Config{
		DBRootDir:           "test-fixtures/grype-db",
		ListingURL:          internal.DBUpdateURL,
		ValidateByHashOnGet: false,
	}, true)
	assert.NoError(t, err)

	definedPkgTypes := strset.New()
	for _, p := range syftPkg.AllPkgs {
		definedPkgTypes.Add(string(p))
	}
	// exceptions: rust and msrc (kb) are not under test
	definedPkgTypes.Remove(string(syftPkg.RustPkg), string(syftPkg.KbPkg))
	observedPkgTypes := strset.New()

	for _, image := range images {
		t.Run(image, func(t *testing.T) {

			t.Logf("Running case %s", image)

			imageArchive := PullThroughImageCache(t, image)
			imageSource := fmt.Sprintf("docker-archive:%s", imageArchive)

			// get SBOM from syft, write to temp file
			sbomBytes := getSyftSBOM(t, imageSource)
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
			matchesFromImage, _, _, err := grype.FindVulnerabilities(vulnProvider, imageSource, source.SquashedScope, nil)
			assert.NoError(t, err)

			// compare packages (shallow)
			matchSetFromSbom := getMatchSet(matchesFromSbom)
			matchSetFromImage := getMatchSet(matchesFromImage)

			assert.Empty(t, strset.Difference(matchSetFromSbom, matchSetFromImage).List(), "vulnerabilities present only in results when using sbom as input")
			assert.Empty(t, strset.Difference(matchSetFromImage, matchSetFromSbom).List(), "vulnerabilities present only in results when using image as input")

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
