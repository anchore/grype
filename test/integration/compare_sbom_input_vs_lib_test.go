package integration

import (
	"fmt"
	"os"
	"testing"

	"github.com/scylladb/go-set/strset"
	"github.com/stretchr/testify/assert"

	"github.com/anchore/grype/grype"
	"github.com/anchore/grype/grype/db/v5/distribution"
	"github.com/anchore/grype/internal"
	"github.com/anchore/grype/internal/log"
	"github.com/anchore/syft/syft/format/spdxjson"
	"github.com/anchore/syft/syft/format/spdxtagvalue"
	"github.com/anchore/syft/syft/format/syftjson"
	syftPkg "github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

func getListingURL() string {
	if value, ok := os.LookupEnv("GRYPE_DB_UPDATE_URL"); ok {
		return value
	}
	return internal.DBUpdateURL
}

func must(e sbom.FormatEncoder, err error) sbom.FormatEncoder {
	if err != nil {
		panic(err)
	}
	return e
}

func TestCompareSBOMInputToLibResults(t *testing.T) {
	// get a grype DB
	store, status, err := grype.LoadVulnerabilityDB(distribution.Config{
		DBRootDir:           "test-fixtures/grype-db",
		ListingURL:          getListingURL(),
		ValidateByHashOnGet: false,
	}, true)
	assert.NoError(t, err)
	defer log.CloseAndLogError(store, status.Location)

	definedPkgTypes := strset.New()
	for _, p := range syftPkg.AllPkgs {
		definedPkgTypes.Add(string(p))
	}
	// exceptions: rust, php, dart, msrc (kb), etc. are not under test
	definedPkgTypes.Remove(
		string(syftPkg.BinaryPkg), // these are removed due to overlap-by-file-ownership
		string(syftPkg.BitnamiPkg),
		string(syftPkg.PhpPeclPkg),
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
		string(syftPkg.OpamPkg),
		string(syftPkg.Rpkg),
		string(syftPkg.SwiplPackPkg),
		string(syftPkg.SwiftPkg),
		string(syftPkg.GithubActionPkg),
		string(syftPkg.GithubActionWorkflowPkg),
		string(syftPkg.GraalVMNativeImagePkg),
		string(syftPkg.ErlangOTPPkg),
		string(syftPkg.WordpressPluginPkg), // TODO: remove me when there is a matcher for this merged in https://github.com/anchore/grype/pull/1553
		string(syftPkg.LuaRocksPkg),
		string(syftPkg.TerraformPkg),
	)
	observedPkgTypes := strset.New()
	testCases := []struct {
		name   string
		image  string
		format sbom.FormatEncoder
	}{
		{
			image:  "anchore/test_images:vulnerabilities-alpine",
			format: syftjson.NewFormatEncoder(),
			name:   "alpine-syft-json",
		},

		{
			image:  "anchore/test_images:vulnerabilities-alpine",
			format: must(spdxjson.NewFormatEncoderWithConfig(spdxjson.DefaultEncoderConfig())),
			name:   "alpine-spdx-json",
		},

		{
			image:  "anchore/test_images:vulnerabilities-alpine",
			format: must(spdxtagvalue.NewFormatEncoderWithConfig(spdxtagvalue.DefaultEncoderConfig())),
			name:   "alpine-spdx-tag-value",
		},

		{
			image:  "anchore/test_images:gems",
			format: syftjson.NewFormatEncoder(),
			name:   "gems-syft-json",
		},

		{
			image:  "anchore/test_images:gems",
			format: must(spdxjson.NewFormatEncoderWithConfig(spdxjson.DefaultEncoderConfig())),
			name:   "gems-spdx-json",
		},

		{
			image:  "anchore/test_images:gems",
			format: must(spdxtagvalue.NewFormatEncoderWithConfig(spdxtagvalue.DefaultEncoderConfig())),
			name:   "gems-spdx-tag-value",
		},

		{
			image:  "anchore/test_images:vulnerabilities-debian",
			format: syftjson.NewFormatEncoder(),
			name:   "debian-syft-json",
		},

		{
			image:  "anchore/test_images:vulnerabilities-debian",
			format: must(spdxjson.NewFormatEncoderWithConfig(spdxjson.DefaultEncoderConfig())),
			name:   "debian-spdx-json",
		},

		{
			image:  "anchore/test_images:vulnerabilities-debian",
			format: must(spdxtagvalue.NewFormatEncoderWithConfig(spdxtagvalue.DefaultEncoderConfig())),
			name:   "debian-spdx-tag-value",
		},

		{
			image:  "anchore/test_images:vulnerabilities-centos",
			format: syftjson.NewFormatEncoder(),
			name:   "centos-syft-json",
		},

		{
			image:  "anchore/test_images:vulnerabilities-centos",
			format: must(spdxjson.NewFormatEncoderWithConfig(spdxjson.DefaultEncoderConfig())),
			name:   "centos-spdx-json",
		},

		{
			image:  "anchore/test_images:vulnerabilities-centos",
			format: must(spdxtagvalue.NewFormatEncoderWithConfig(spdxtagvalue.DefaultEncoderConfig())),
			name:   "centos-spdx-tag-value",
		},

		{
			image:  "anchore/test_images:npm",
			format: syftjson.NewFormatEncoder(),
			name:   "npm-syft-json",
		},

		{
			image:  "anchore/test_images:npm",
			format: must(spdxjson.NewFormatEncoderWithConfig(spdxjson.DefaultEncoderConfig())),
			name:   "npm-spdx-json",
		},

		{
			image:  "anchore/test_images:npm",
			format: must(spdxtagvalue.NewFormatEncoderWithConfig(spdxtagvalue.DefaultEncoderConfig())),
			name:   "npm-spdx-tag-value",
		},

		{
			image:  "anchore/test_images:java",
			format: syftjson.NewFormatEncoder(),
			name:   "java-syft-json",
		},

		{
			image:  "anchore/test_images:java",
			format: must(spdxjson.NewFormatEncoderWithConfig(spdxjson.DefaultEncoderConfig())),
			name:   "java-spdx-json",
		},

		{
			image:  "anchore/test_images:java",
			format: must(spdxtagvalue.NewFormatEncoderWithConfig(spdxtagvalue.DefaultEncoderConfig())),
			name:   "java-spdx-tag-value",
		},

		{
			image:  "anchore/test_images:golang-56d52bc",
			format: syftjson.NewFormatEncoder(),
			name:   "go-syft-json",
		},

		{
			image:  "anchore/test_images:golang-56d52bc",
			format: must(spdxjson.NewFormatEncoderWithConfig(spdxjson.DefaultEncoderConfig())),
			name:   "go-spdx-json",
		},

		{
			image:  "anchore/test_images:golang-56d52bc",
			format: must(spdxtagvalue.NewFormatEncoderWithConfig(spdxtagvalue.DefaultEncoderConfig())),
			name:   "go-spdx-tag-value",
		},

		{
			image:  "anchore/test_images:arch",
			format: syftjson.NewFormatEncoder(),
			name:   "arch-syft-json",
		},

		{
			image:  "anchore/test_images:arch",
			format: must(spdxjson.NewFormatEncoderWithConfig(spdxjson.DefaultEncoderConfig())),
			name:   "arch-spdx-json",
		},

		{
			image:  "anchore/test_images:arch",
			format: must(spdxtagvalue.NewFormatEncoderWithConfig(spdxtagvalue.DefaultEncoderConfig())),
			name:   "arch-spdx-tag-value",
		},
	}
	for _, tc := range testCases {
		imageArchive := PullThroughImageCache(t, tc.image)

		t.Run(tc.name, func(t *testing.T) {
			// get SBOM from syft, write to temp file
			sbomBytes := getSyftSBOM(t, imageArchive, "docker-archive", tc.format)
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
			imageSource := fmt.Sprintf("docker-archive:%s", imageArchive)
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
