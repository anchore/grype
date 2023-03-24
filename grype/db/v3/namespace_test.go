package v3

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/scylladb/go-set/strset"
	"github.com/stretchr/testify/assert"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/pkg"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

func Test_NamespaceFromRecordSource(t *testing.T) {
	tests := []struct {
		Feed, Group string
		Namespace   string
	}{
		{
			Feed:      "vulnerabilities",
			Group:     "ubuntu:20.04",
			Namespace: "ubuntu:20.04",
		},
		{
			Feed:      "vulnerabilities",
			Group:     "alpine:3.9",
			Namespace: "alpine:3.9",
		},
		{
			Feed:      "nvdv2",
			Group:     "nvdv2:cves",
			Namespace: "nvd",
		},
		{
			Feed:      "github",
			Group:     "github:python",
			Namespace: "github:python",
		},
		{
			Feed:      "vulndb",
			Group:     "vulndb:vulnerabilities",
			Namespace: "vulndb",
		},
		{
			Feed:      "microsoft",
			Group:     "msrc:11769",
			Namespace: "msrc:11769",
		},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("feed=%q group=%q namespace=%q", test.Feed, test.Group, test.Namespace), func(t *testing.T) {
			actual, err := NamespaceForFeedGroup(test.Feed, test.Group)
			assert.NoError(t, err)
			assert.Equal(t, test.Namespace, actual)
		})
	}
}

func Test_NamespaceForDistro(t *testing.T) {
	tests := []struct {
		dist     distro.Type
		version  string
		expected string
	}{
		// regression: https://github.com/anchore/grype/issues/221
		{
			dist:     distro.RedHat,
			version:  "8.3",
			expected: "rhel:8",
		},
		{
			dist:     distro.CentOS,
			version:  "8.3",
			expected: "rhel:8",
		},
		{
			dist:     distro.AmazonLinux,
			version:  "8.3",
			expected: "amzn:8",
		},
		{
			dist:     distro.OracleLinux,
			version:  "8.3",
			expected: "ol:8",
		},
		{
			dist:    distro.Fedora,
			version: "31.1",
			// TODO: this is incorrect and will be solved in a future issue (to map the fedora version to the rhel latest version)
			expected: "rhel:31",
		},
		// end of regression #221
		{
			dist:     distro.RedHat,
			version:  "8",
			expected: "rhel:8",
		},
		{
			dist:     distro.AmazonLinux,
			version:  "2",
			expected: "amzn:2",
		},
		{
			dist:     distro.OracleLinux,
			version:  "6",
			expected: "ol:6",
		},
		{
			dist:     distro.Alpine,
			version:  "1.3.1",
			expected: "alpine:1.3",
		},
		{
			dist:     distro.Debian,
			version:  "8",
			expected: "debian:8",
		},
		{
			dist:     distro.Fedora,
			version:  "31",
			expected: "rhel:31",
		},
		{
			dist:     distro.Busybox,
			version:  "3.1.1",
			expected: "busybox:3.1.1",
		},
		{
			dist:     distro.CentOS,
			version:  "7",
			expected: "rhel:7",
		},
		{
			dist:     distro.Ubuntu,
			version:  "18.04",
			expected: "ubuntu:18.04",
		},
		{
			// TODO: this is not correct. This should be mapped to a feed source.
			dist:     distro.ArchLinux,
			version:  "", // ArchLinux doesn't expose a version
			expected: "archlinux:rolling",
		},
		{
			// TODO: this is not correct. This should be mapped to a feed source.
			dist:     distro.OpenSuseLeap,
			version:  "15.2",
			expected: "opensuseleap:15.2",
		},
		{
			// TODO: this is not correct. This should be mapped to a feed source.
			dist:     distro.Photon,
			version:  "4.0",
			expected: "photon:4.0",
		},
		{
			dist:     distro.SLES,
			version:  "12.5",
			expected: "sles:12.5",
		},
		{
			dist:     distro.Windows,
			version:  "471816",
			expected: "msrc:471816",
		},
		{
			dist:     distro.RockyLinux,
			version:  "8.5",
			expected: "rhel:8",
		},
		{
			dist:     distro.AlmaLinux,
			version:  "8.5",
			expected: "rhel:8",
		},
		{
			dist:     distro.Gentoo,
			version:  "", // Gentoo is a rolling release
			expected: "gentoo:rolling",
		},
		{
			dist:     distro.Wolfi,
			version:  "2022yzblah", // Wolfi is a rolling release
			expected: "wolfi:rolling",
		},
		{
			dist:     distro.Chainguard,
			expected: "chainguard:rolling",
		},
	}

	observedDistros := strset.New()
	allDistros := strset.New()

	for _, d := range distro.All {
		allDistros.Add(d.String())
	}

	// TODO: what do we do with mariner
	allDistros.Remove(distro.Mariner.String())

	for _, test := range tests {
		name := fmt.Sprintf("%s:%s", test.dist, test.version)
		t.Run(name, func(t *testing.T) {
			d, err := distro.New(test.dist, test.version, "")
			assert.NoError(t, err)
			observedDistros.Add(d.Type.String())
			assert.Equal(t, test.expected, NamespaceForDistro(d))
		})
	}

	assert.ElementsMatch(t, allDistros.List(), observedDistros.List(), "at least one distro doesn't have a corresponding test")
}

func Test_NamespacesIndexedByCPE(t *testing.T) {
	assert.ElementsMatch(t, NamespacesIndexedByCPE(), []string{"nvd", "vulndb"})
}

func Test_NamespacesForLanguage(t *testing.T) {
	tests := []struct {
		language           syftPkg.Language
		namerInput         *pkg.Package
		expectedNamespaces []string
		expectedNames      []string
	}{
		// default languages
		{
			language: syftPkg.Rust,
			namerInput: &pkg.Package{
				ID:   pkg.ID(uuid.NewString()),
				Name: "a-name",
			},
			expectedNamespaces: []string{
				"github:rust",
			},
			expectedNames: []string{
				"a-name",
			},
		},
		{
			language: syftPkg.Go,
			namerInput: &pkg.Package{
				ID:   pkg.ID(uuid.NewString()),
				Name: "a-name",
			},
			expectedNamespaces: []string{
				"github:go",
			},
			expectedNames: []string{
				"a-name",
			},
		},
		// supported languages
		{
			language: syftPkg.Ruby,
			namerInput: &pkg.Package{
				ID:   pkg.ID(uuid.NewString()),
				Name: "a-name",
			},
			expectedNamespaces: []string{
				"github:gem",
			},
			expectedNames: []string{
				"a-name",
			},
		},
		{
			language: syftPkg.JavaScript,
			namerInput: &pkg.Package{
				ID:   pkg.ID(uuid.NewString()),
				Name: "a-name",
			},
			expectedNamespaces: []string{
				"github:npm",
			},
			expectedNames: []string{
				"a-name",
			},
		},
		{
			language: syftPkg.Python,
			namerInput: &pkg.Package{
				ID:   pkg.ID(uuid.NewString()),
				Name: "a-name",
			},
			expectedNamespaces: []string{
				"github:python",
			},
			expectedNames: []string{
				"a-name",
			},
		},
		{
			language: syftPkg.Java,
			namerInput: &pkg.Package{
				ID:   pkg.ID(uuid.NewString()),
				Name: "a-name",
				Metadata: pkg.JavaMetadata{
					VirtualPath:   "v-path",
					PomArtifactID: "art-id",
					PomGroupID:    "g-id",
					ManifestName:  "man-name",
				},
			},
			expectedNamespaces: []string{
				"github:java",
			},
			expectedNames: []string{
				"g-id:art-id",
				"g-id:man-name",
			},
		},
		{
			language: syftPkg.Dart,
			namerInput: &pkg.Package{
				ID:   pkg.ID(uuid.NewString()),
				Name: "a-name",
			},
			expectedNamespaces: []string{
				"github:dart",
			},
			expectedNames: []string{
				"a-name",
			},
		},
		{
			language: syftPkg.Dotnet,
			namerInput: &pkg.Package{
				ID:   pkg.ID(uuid.NewString()),
				Name: "a-name",
			},
			expectedNamespaces: []string{
				"github:nuget",
			},
			expectedNames: []string{
				"a-name",
			},
		},
		{
			language: syftPkg.Haskell,
			namerInput: &pkg.Package{
				ID:   pkg.ID(uuid.NewString()),
				Name: "h-name",
			},
			expectedNamespaces: []string{
				"github:haskell",
			},
			expectedNames: []string{
				"h-name",
			},
		},
		{
			language: syftPkg.Elixir,
			namerInput: &pkg.Package{
				ID:   pkg.ID(uuid.NewString()),
				Name: "e-name",
			},
			expectedNamespaces: []string{
				"github:elixir",
			},
			expectedNames: []string{
				"e-name",
			},
		},
		{
			language: syftPkg.Erlang,
			namerInput: &pkg.Package{
				ID:   pkg.ID(uuid.NewString()),
				Name: "2-name",
			},
			expectedNamespaces: []string{
				"github:erlang",
			},
			expectedNames: []string{
				"2-name",
			},
		},
	}

	observedLanguages := strset.New()
	allLanguages := strset.New()

	for _, l := range syftPkg.AllLanguages {
		allLanguages.Add(string(l))
	}

	// remove PHP, CPP for coverage as feed has not been updated
	allLanguages.Remove(string(syftPkg.PHP))
	allLanguages.Remove(string(syftPkg.CPP))
	allLanguages.Remove(string(syftPkg.Swift))

	for _, test := range tests {
		t.Run(string(test.language), func(t *testing.T) {
			observedLanguages.Add(string(test.language))
			var actualNamespaces, actualNames []string
			namers := NamespacePackageNamersForLanguage(test.language)
			for namespace, namerFn := range namers {
				actualNamespaces = append(actualNamespaces, namespace)
				actualNames = append(actualNames, namerFn(*test.namerInput)...)
			}
			assert.ElementsMatch(t, actualNamespaces, test.expectedNamespaces)
			assert.ElementsMatch(t, actualNames, test.expectedNames)
		})
	}

	assert.ElementsMatch(t, allLanguages.List(), observedLanguages.List(), "at least one language doesn't have a corresponding test")
}

func Test_githubJavaPackageNamer(t *testing.T) {
	tests := []struct {
		name       string
		namerInput pkg.Package
		expected   []string
	}{
		{
			name: "both artifact and manifest",
			namerInput: pkg.Package{
				ID:   pkg.ID(uuid.NewString()),
				Name: "a-name",
				Metadata: pkg.JavaMetadata{
					VirtualPath:   "v-path",
					PomArtifactID: "art-id",
					PomGroupID:    "g-id",
					ManifestName:  "man-name",
				},
			},
			expected: []string{
				"g-id:art-id",
				"g-id:man-name",
			},
		},
		{
			name: "no group id",
			namerInput: pkg.Package{
				ID:   pkg.ID(uuid.NewString()),
				Name: "a-name",
				Metadata: pkg.JavaMetadata{
					VirtualPath:   "v-path",
					PomArtifactID: "art-id",
					ManifestName:  "man-name",
				},
			},
			expected: []string{},
		},
		{
			name: "only manifest",
			namerInput: pkg.Package{
				ID:   pkg.ID(uuid.NewString()),
				Name: "a-name",
				Metadata: pkg.JavaMetadata{
					VirtualPath:  "v-path",
					PomGroupID:   "g-id",
					ManifestName: "man-name",
				},
			},
			expected: []string{
				"g-id:man-name",
			},
		},
		{
			name: "only artifact",
			namerInput: pkg.Package{
				ID:   pkg.ID(uuid.NewString()),
				Name: "a-name",
				Metadata: pkg.JavaMetadata{
					VirtualPath:   "v-path",
					PomArtifactID: "art-id",
					PomGroupID:    "g-id",
				},
			},
			expected: []string{
				"g-id:art-id",
			},
		},
		{
			name: "no artifact or manifest",
			namerInput: pkg.Package{
				ID:   pkg.ID(uuid.NewString()),
				Name: "a-name",
				Metadata: pkg.JavaMetadata{
					VirtualPath: "v-path",
					PomGroupID:  "g-id",
				},
			},
			expected: []string{},
		},
		{
			name: "with valid purl",
			namerInput: pkg.Package{
				ID:   pkg.ID(uuid.NewString()),
				Name: "a-name",
				PURL: "pkg:maven/org.anchore/b-name@0.2",
			},
			expected: []string{"org.anchore:b-name"},
		},
		{
			name: "ignore invalid pURLs",
			namerInput: pkg.Package{
				ID:   pkg.ID(uuid.NewString()),
				Name: "a-name",
				PURL: "pkg:BAD/",
				Metadata: pkg.JavaMetadata{
					VirtualPath:   "v-path",
					PomArtifactID: "art-id",
					PomGroupID:    "g-id",
				},
			},
			expected: []string{
				"g-id:art-id",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.ElementsMatch(t, githubJavaPackageNamer(test.namerInput), test.expected)
		})
	}
}
