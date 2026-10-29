package integration

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/scylladb/go-set/strset"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype"
	"github.com/anchore/grype/grype/db/v6/distribution"
	"github.com/anchore/grype/grype/db/v6/installation"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/format/spdxjson"
	"github.com/anchore/syft/syft/format/spdxtagvalue"
	"github.com/anchore/syft/syft/format/syftjson"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

// pinnedDBRef matches the DB the quality gate pins: the archive URL and its sha256
var pinnedDBRef = regexp.MustCompile(`(https://grype\.anchore\.io/databases/v6/[^"@]+)@sha256:([0-9a-f]{64})`)

// TestSBOMFormats checks that scanning an image matches the same vulnerabilities as scanning an SBOM of that image
// in each format. Every format has quirks, so a difference a format is known to cause is listed against it.
func TestSBOMFormats(t *testing.T) {
	store := pinnedDB(t)

	formats := map[string]sbom.FormatEncoder{
		"syft-json":      syftjson.NewFormatEncoder(),
		"spdx-json":      must(spdxjson.NewFormatEncoderWithConfig(spdxjson.DefaultEncoderConfig())),
		"spdx-tag-value": must(spdxtagvalue.NewFormatEncoderWithConfig(spdxtagvalue.DefaultEncoderConfig())),
	}

	// the images are quality gate subjects, so they are pinned by digest and representative of their ecosystem
	tests := []struct {
		name  string
		image string
		// knownFormatLoss lists, by format, the matches (vulnerability-package-version) that differ from the image
		// scan because the format cannot carry something the image scan used
		knownFormatLoss map[string][]string
	}{
		{name: "alpine", image: "ghcr.io/anchore/test-images/vulnerabilities-alpine-3.12@sha256:55c9ba4e24e15c0467a071d93fead0990b8f04bb60b359b4056a997598aa56a1"},
		{name: "debian", image: "docker.io/debian:7@sha256:81e88820a7759038ffa61cff59dfcc12d3772c3a2e75b7cfe963c952da2ad264"},
		{name: "centos", image: "docker.io/anchore/test_images:vulnerabilities-centos@sha256:746d31247006cc06434ce91ccf3523b2c230ff6c378ffed7ca1c60bbb48ea86f"},
		{name: "arch", image: "ghcr.io/anchore/test-images/archlinux@sha256:a933b27534e5c911e2c660f7090aa497dee763fbbcb214a37207c2320cfedd98"},
		{name: "gems", image: "ghcr.io/anchore/test-images/gems@sha256:5763c8a225f950961bf01ddec68e36f18e236130e182f2b9290a6e03b9777bfe"},
		{name: "npm", image: "ghcr.io/anchore/test-images/npm@sha256:ba42ded8613fc643d407a050faf5ab48cfb405ad3ef2015bf6feeb5dff44738d"},
		{name: "java", image: "ghcr.io/anchore/test-images/java@sha256:10008791acbc5866de04108746a02a0c4029ce3a4400a9b3dad45d7f2245f9da"},
		{name: "golang", image: "ghcr.io/anchore/test-images/golang@sha256:d1819e59e89e8ea90073460acb4ebb2ee18ccead9fa880dae91e8fc61b19ca1c"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// the image is pulled and cataloged once; each format re-reads the SBOM that catalog produced
			imagePkgs, _, s, err := pkg.Provide("registry:"+tt.image, providerConfig())
			require.NoError(t, err)
			imageMatches := findMatches(store, imagePkgs)
			require.NotEmpty(t, imageMatches.Sorted(), "the image scan matched nothing, so there is nothing to compare")

			for name, encoder := range formats {
				t.Run(name, func(t *testing.T) {
					t.Parallel()

					var buf bytes.Buffer
					require.NoError(t, encoder.Encode(&buf, *s))
					sbomPkgs, _, _, err := pkg.ProvideFromReader(bytes.NewReader(buf.Bytes()), providerConfig())
					require.NoError(t, err)
					sbomMatches := findMatches(store, sbomPkgs)

					fromImage, fromSBOM := matchSet(imageMatches), matchSet(sbomMatches)
					allowed := strset.New(tt.knownFormatLoss[name]...)
					onlyImage, onlySBOM := missingFrom(fromImage, fromSBOM, allowed), missingFrom(fromSBOM, fromImage, allowed)

					assert.Empty(t, onlyImage, "matched scanning the image but not the %s SBOM", name)
					assert.Empty(t, onlySBOM, "matched scanning the %s SBOM but not the image", name)
					if t.Failed() {
						logPackageDiffs(t, imagePkgs, sbomPkgs, append(onlyImage, onlySBOM...))
					}
				})
			}
		})
	}
}

// pinnedDB loads the DB pinned in the quality gate, importing it into a cache dir named by its checksum on first use
func pinnedDB(t *testing.T) vulnerability.Provider {
	gate, err := os.ReadFile(filepath.Join("gates", "pr.yaml"))
	require.NoError(t, err)
	ref := pinnedDBRef.FindSubmatch(gate)
	require.NotNil(t, ref, "no pinned DB in gates/pr.yaml")

	distCfg := distribution.DefaultConfig()
	installCfg := installation.Config{DBRootDir: filepath.Join(".cache", "grype-db", string(ref[2]))}

	store, _, err := grype.LoadVulnerabilityDB(distCfg, installCfg, false)
	if err != nil {
		client, err := distribution.NewClient(distCfg)
		require.NoError(t, err)
		curator, err := installation.NewCurator(installCfg, client)
		require.NoError(t, err)
		// go-getter checks the archive against the checksum query and does not send it to the server
		require.NoError(t, curator.Import(fmt.Sprintf("%s?checksum=sha256:%s", ref[1], ref[2])))
		store, _, err = grype.LoadVulnerabilityDB(distCfg, installCfg, false)
		require.NoError(t, err)
	}
	return store
}

func providerConfig() pkg.ProviderConfig {
	cfg := pkg.ProviderConfig{
		SyftProviderConfig: pkg.SyftProviderConfig{
			SBOMOptions: syft.DefaultCreateSBOMConfig(),
			Platform:    "linux/amd64",
		},
	}
	cfg.SBOMOptions.Search.Scope = source.SquashedScope
	return cfg
}

func findMatches(store vulnerability.Provider, pkgs []pkg.Package) match.Matches {
	return grype.FindVulnerabilitiesForPackage(store, matcher.NewDefaultMatchers(matcher.Config{}), pkgs)
}

// matchSet keys each match by vulnerability, package name and version, to the package it matched
func matchSet(matches match.Matches) map[string]pkg.Package {
	out := map[string]pkg.Package{}
	for _, m := range matches.Sorted() {
		out[fmt.Sprintf("%s-%s-%s", m.Vulnerability.ID, m.Package.Name, m.Package.Version)] = m.Package
	}
	return out
}

// missingFrom lists the packages of matches in a that b does not have, other than the allowed ones
func missingFrom(a, b map[string]pkg.Package, allowed *strset.Set) []pkg.Package {
	var out []pkg.Package
	for k, p := range a {
		if _, ok := b[k]; !ok && !allowed.Has(k) {
			out = append(out, p)
		}
	}
	return out
}

// logPackageDiffs shows how the packages behind the differing matches differ between the image and the SBOM, which
// is usually the format quirk to name when listing a known loss
func logPackageDiffs(t *testing.T, imagePkgs, sbomPkgs []pkg.Package, differing []pkg.Package) {
	t.Helper()
	find := func(pkgs []pkg.Package, name, version string) *pkg.Package {
		for i := range pkgs {
			if pkgs[i].Name == name && pkgs[i].Version == version {
				return &pkgs[i]
			}
		}
		return nil
	}
	logged := strset.New()
	for _, p := range differing {
		key := p.Name + "@" + p.Version
		if logged.Has(key) {
			continue
		}
		logged.Add(key)
		diff := cmp.Diff(find(imagePkgs, p.Name, p.Version), find(sbomPkgs, p.Name, p.Version),
			cmpopts.IgnoreFields(pkg.Package{}, "ID"),
			// packages hold syft types with unexported fields (location sets, file references)
			cmp.Exporter(func(reflect.Type) bool { return true }))
		t.Logf("package %s (-image +sbom):\n%s", key, diff)
	}
}

func must(e sbom.FormatEncoder, err error) sbom.FormatEncoder {
	if err != nil {
		panic(err)
	}
	return e
}
