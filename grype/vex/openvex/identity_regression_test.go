package openvex

import (
	"strings"
	"testing"

	openvex "github.com/openvex/go-vex/pkg/vex"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/source"
)

const testDigest = "sha256:124c7d2707904eea7431fffe91522a01e5a861a624ee31d03372cc1d138a3126"

// suppressed reports whether a vex document scoped to docProduct filters out a
// finding on an image described by src.
func suppressed(t *testing.T, src source.Description, docProduct string) bool {
	t.Helper()

	doc := &openvex.VEX{
		Statements: []openvex.Statement{
			{
				Vulnerability: openvex.Vulnerability{Name: "CVE-2024-0001"},
				Products:      []openvex.Product{{Component: openvex.Component{ID: docProduct}}},
				Status:        openvex.StatusFixed,
			},
		},
	}

	matches := match.NewMatches(match.Match{
		Vulnerability: vulnerability.Vulnerability{
			Reference: vulnerability.Reference{ID: "CVE-2024-0001"},
		},
		Package: pkg.Package{
			Name: "example",
			PURL: "pkg:golang/example.com/example@v1.0.0",
		},
	})

	remaining, ignored, err := New().FilterMatches(doc, nil, &pkg.Context{Source: &src}, &matches, nil)
	require.NoError(t, err)

	return len(remaining.Sorted()) == 0 && len(ignored) == 1
}

// the docker daemon reports unqualified repo digests for docker hub images
// (stereoscope passes them through verbatim), so this is the shape produced by
// a plain `grype debian:bookworm`. withholding repository_url for it means no
// repository_url-bearing document can ever match, including the spec-conformant
// one this repo ships as its own fixture.
func TestFilterMatches_DockerDaemonBareDigest(t *testing.T) {
	src := source.Description{
		Name: "debian",
		Metadata: source.ImageMetadata{
			RepoDigests: []string{"debian@" + testDigest},
		},
	}

	require.True(t,
		suppressed(t, src, "pkg:oci/debian@"+testDigest+"?repository_url=index.docker.io/library/debian"),
		"a spec-conformant document must suppress a docker-daemon sourced image",
	)
}

// the comment on ociRepositoryIdentity cites the purl-spec oci example
// `repository_url=docker.io/library/debian`, but the code emits index.docker.io
// and qualifier values are compared byte-for-byte. copying the spec example
// verbatim gets the user nothing.
func TestFilterMatches_PurlSpecDockerHubSpelling(t *testing.T) {
	src := source.Description{
		Name: "index.docker.io/library/debian",
		Metadata: source.ImageMetadata{
			RepoDigests: []string{"index.docker.io/library/debian@" + testDigest},
		},
	}

	require.True(t,
		suppressed(t, src, "pkg:oci/debian@"+testDigest+"?repository_url=docker.io/library/debian"),
		"the docker.io spelling used by the purl-spec oci examples must match",
	)
}

// Tags is the daemon's RepoTags and routinely spans registries for one local
// image, but baseName/repoURL are derived once from Source.Name and stamped on
// every entry. that fabricates a product that was never scanned, and it
// suppresses.
func TestFilterMatches_TagFromDifferentRegistryIsNotFabricated(t *testing.T) {
	src := source.Description{
		Name: "gcr.io/foo/alpine",
		Metadata: source.ImageMetadata{
			Tags: []string{"gcr.io/foo/alpine:1.0", "alpine:latest"},
		},
	}

	require.False(t,
		suppressed(t, src, "pkg:oci/alpine?repository_url=gcr.io/foo/alpine&tag=latest"),
		"gcr.io/foo/alpine:latest was never scanned and must not suppress",
	)
}

func TestIdentifiersFromTags_DoesNotFabricateForeignRepositoryURL(t *testing.T) {
	ids := identifiersFromTags([]string{"gcr.io/foo/alpine:1.0", "alpine:latest"}, "gcr.io/foo/alpine")

	require.NotContains(t, ids, "pkg:oci/alpine?repository_url=gcr.io%2Ffoo%2Falpine&tag=latest",
		"the docker hub tag must not inherit Source.Name's registry")
}

// Source.Name for archive and directory scans is the raw user input
// (nameIfUnset(UserInput) in syft), and a path parses as host/repo.
func TestIdentifiersFromTags_ArchiveSourceNameIsNotARepositoryURL(t *testing.T) {
	ids := identifiersFromTags([]string{"myimage:1.0"}, "docker-archive:/tmp/img.tar")

	require.Contains(t, ids, "pkg:oci/myimage?tag=1.0",
		"identity should come from the tag, not from a filesystem path")
}

// every synthesized purl is handed to doc.Matches, so it has to be a purl.
func TestIdentifiersFromTags_AlwaysProducesValidPurls(t *testing.T) {
	for name, sourceName := range map[string]string{"empty source name": "", "unparseable source name": "  alpine  "} {
		t.Run(name, func(t *testing.T) {
			for _, id := range identifiersFromTags([]string{"debian:latest"}, sourceName) {
				if !strings.HasPrefix(id, "pkg:") {
					// the raw image reference is also emitted as an identifier
					continue
				}
				_, err := packageurl.FromString(id)
				require.NoError(t, err, "invalid purl synthesized: %q", id)
			}
		})
	}
}

// tagSuffix splits on ":" and takes the last segment, so a digest lands in the
// tag qualifier and a real tag alongside a digest is discarded.
func TestTagSuffix_DigestQualifiedReferences(t *testing.T) {
	t.Run("digest is not a tag", func(t *testing.T) {
		_, ok := tagSuffix("alpine@" + testDigest)
		require.False(t, ok, "a digest-qualified reference carries no tag")
	})

	t.Run("tag alongside a digest is kept", func(t *testing.T) {
		tag, ok := tagSuffix("alpine:1.0@" + testDigest)
		require.True(t, ok)
		require.Equal(t, "1.0", tag)
	})

	t.Run("empty tag is not a tag", func(t *testing.T) {
		_, ok := tagSuffix("alpine:")
		require.False(t, ok, "an empty tag produces the unparseable purl `pkg:oci/alpine?tag=`")
	})
}

// this one passes today. it is the test TestFilterMatches_OCIProductWithFullRepositoryURL
// should have been: that test supplies both Tags and RepoDigests, and
// findMatchingStatement returns on the first hit, so the digest identifier
// satisfies it and the tag path is never exercised. reverting identifiersFromTags
// to its pre-#3659 form leaves that test green while this one fails.
func TestFilterMatches_OCIProductTagOnly(t *testing.T) {
	src := source.Description{
		Name: "registry.access.redhat.com/ubi10/podman",
		Metadata: source.ImageMetadata{
			Tags: []string{"registry.access.redhat.com/ubi10/podman:10.2"},
		},
	}

	require.True(t,
		suppressed(t, src, "pkg:oci/podman?repository_url=registry.access.redhat.com/ubi10/podman&tag=10.2"),
		"the tag path alone must satisfy a repository_url-qualified product",
	)
}
