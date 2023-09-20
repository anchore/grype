package integration

import (
	"fmt"
	"os"
	"testing"

	"github.com/scylladb/go-set/strset"
	"github.com/stretchr/testify/assert"

	"github.com/anchore/grype/grype"
	"github.com/anchore/grype/grype/db"
	"github.com/anchore/grype/internal"
	"github.com/anchore/syft/syft"
	syftPkg "github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

var imagesWithVulnerabilities = []string{
	"anchore/test_images:vulnerabilities-alpine",
	"anchore/test_images:gems",
	"anchore/test_images:vulnerabilities-debian",
	"anchore/test_images:vulnerabilities-centos",
	"anchore/test_images:npm",
	"anchore/test_images:java",
	"anchore/test_images:golang-56d52bc",
	"anchore/test_images:arch",
}

func getListingURL() string {
	if value, ok := os.LookupEnv("GRYPE_DB_UPDATE_URL"); ok {
		return value
	}
	return internal.DBUpdateURL
}

func TestCompareSBOMInputToLibResults(t *testing.T) {
	// get a grype DB
	store, _, closer, err := grype.LoadVulnerabilityDB(db.Config{
		DBRootDir:           "test-fixtures/grype-db",
		ListingURL:          getListingURL(),
		ValidateByHashOnGet: false,
	}, true)
	assert.NoError(t, err)

	if closer != nil {
		defer closer.Close()
	}

	definedPkgTypes := strset.New()
	for _, p := range syftPkg.AllPkgs {
		definedPkgTypes.Add(string(p))
	}
	// exceptions: rust, php, dart, msrc (kb), etc. are not under test
	definedPkgTypes.Remove(
		string(syftPkg.BinaryPkg), // these are removed due to overlap-by-file-ownership
		string(syftPkg.RustPkg),
		string(syftPkg.KbPkg),
		string(syftPkg.DartPubPkg),
		string(syftPkg.DotnetPkg),
		string(syftPkg.PhpComposerPkg),
		string(syftPkg.ConanPkg),
		string(syftPkg.HexPkg),
		string(syftPkg.PortagePkg),
		string(syftPkg.CocoapodsPkg),
		string(syftPkg.HackagePkg),
		string(syftPkg.NixPkg),
		string(syftPkg.JenkinsPluginPkg), // package type cannot be inferred for all formats
		string(syftPkg.LinuxKernelPkg),
		string(syftPkg.LinuxKernelModulePkg),
		string(syftPkg.Rpkg),
		string(syftPkg.SwiftPkg),
		string(syftPkg.GithubActionPkg),
		string(syftPkg.GithubActionWorkflowPkg),
	)
	observedPkgTypes := strset.New()
	testCases := []struct {
		name   string
		image  string
		format sbom.FormatID
	}{
		{
			image:  "anchore/test_images:vulnerabilities-alpine",
			format: syft.JSONFormatID,
			name:   "alpine-syft-json",
		},

		{
			image:  "anchore/test_images:vulnerabilities-alpine",
			format: syft.SPDXJSONFormatID,
			name:   "alpine-spdx-json",
		},

		{
			image:  "anchore/test_images:vulnerabilities-alpine",
			format: syft.SPDXTagValueFormatID,
			name:   "alpine-spdx-tag-value",
		},

		{
			image:  "anchore/test_images:gems",
			format: syft.JSONFormatID,
			name:   "gems-syft-json",
		},

		{
			image:  "anchore/test_images:gems",
			format: syft.SPDXJSONFormatID,
			name:   "gems-spdx-json",
		},

		{
			image:  "anchore/test_images:gems",
			format: syft.SPDXTagValueFormatID,
			name:   "gems-spdx-tag-value",
		},

		{
			image:  "anchore/test_images:vulnerabilities-debian",
			format: syft.JSONFormatID,
			name:   "debian-syft-json",
		},

		{
			image:  "anchore/test_images:vulnerabilities-debian",
			format: syft.SPDXJSONFormatID,
			name:   "debian-spdx-json",
		},

		{
			image:  "anchore/test_images:vulnerabilities-debian",
			format: syft.SPDXTagValueFormatID,
			name:   "debian-spdx-tag-value",
		},

		{
			image:  "anchore/test_images:vulnerabilities-centos",
			format: syft.JSONFormatID,
			name:   "centos-syft-json",
		},

		{
			image:  "anchore/test_images:vulnerabilities-centos",
			format: syft.SPDXJSONFormatID,
			name:   "centos-spdx-json",
		},

		{
			image:  "anchore/test_images:vulnerabilities-centos",
			format: syft.SPDXTagValueFormatID,
			name:   "centos-spdx-tag-value",
		},

		{
			image:  "anchore/test_images:npm",
			format: syft.JSONFormatID,
			name:   "npm-syft-json",
		},

		{
			image:  "anchore/test_images:npm",
			format: syft.SPDXJSONFormatID,
			name:   "npm-spdx-json",
		},

		{
			image:  "anchore/test_images:npm",
			format: syft.SPDXTagValueFormatID,
			name:   "npm-spdx-tag-value",
		},

		{
			image:  "anchore/test_images:java",
			format: syft.JSONFormatID,
			name:   "java-syft-json",
		},

		{
			image:  "anchore/test_images:java",
			format: syft.SPDXJSONFormatID,
			name:   "java-spdx-json",
		},

		{
			image:  "anchore/test_images:java",
			format: syft.SPDXTagValueFormatID,
			name:   "java-spdx-tag-value",
		},

		{
			image:  "anchore/test_images:golang-56d52bc",
			format: syft.JSONFormatID,
			name:   "go-syft-json",
		},

		{
			image:  "anchore/test_images:golang-56d52bc",
			format: syft.SPDXJSONFormatID,
			name:   "go-spdx-json",
		},

		{
			image:  "anchore/test_images:golang-56d52bc",
			format: syft.SPDXTagValueFormatID,
			name:   "go-spdx-tag-value",
		},

		{
			image:  "anchore/test_images:arch",
			format: syft.JSONFormatID,
			name:   "arch-syft-json",
		},

		{
			image:  "anchore/test_images:arch",
			format: syft.SPDXJSONFormatID,
			name:   "arch-spdx-json",
		},

		{
			image:  "anchore/test_images:arch",
			format: syft.SPDXTagValueFormatID,
			name:   "arch-spdx-tag-value",
		},
	}
	for _, tc := range testCases {
		imageArchive := PullThroughImageCache(t, tc.image)
		imageSource := fmt.Sprintf("docker-archive:%s", imageArchive)
		f := syft.FormatByID(tc.format)
		if f == nil {
			t.Errorf("Invalid formatID: %s", tc.format)
		}
		t.Run(tc.name, func(t *testing.T) {
			// get SBOM from syft, write to temp file
			sbomBytes := getSyftSBOM(t, imageSource, f)
			sbomFile, err := os.CreateTemp("", "")
			assert.NoError(t, err)
			t.Cleanup(func() {
				assert.NoError(t, os.Remove(sbomFile.Name()))
			})
			_, err = sbomFile.WriteString(sbomBytes)
			assert.NoError(t, err)
			assert.NoError(t, sbomFile.Close())

			// get vulns (sbom)
			matchesFromSbom, _, pkgsFromSbom, err := grype.FindVulnerabilities(*store, fmt.Sprintf("sbom:%s", sbomFile.Name()), source.SquashedScope, nil)
			assert.NoError(t, err)

			// get vulns (image)
			matchesFromImage, _, _, err := grype.FindVulnerabilities(*store, imageSource, source.SquashedScope, nil)
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
