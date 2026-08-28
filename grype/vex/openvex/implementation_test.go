package openvex

import (
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	openvex "github.com/openvex/go-vex/pkg/vex"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/source"
)

func TestIdentifiersFromTags(t *testing.T) {
	for _, tc := range []struct {
		sut      string
		name     string
		expected []string
	}{
		{
			// a bare Docker Hub-style name resolves to Docker Hub; every
			// spelling of it is emitted, along with an unqualified identifier
			// for documents that name no repository_url at all
			"alpine:v1.2.3",
			"alpine",
			[]string{
				"alpine:v1.2.3",
				"pkg:oci/alpine?tag=v1.2.3",
				"pkg:oci/alpine?repository_url=index.docker.io%2Flibrary%2Falpine&tag=v1.2.3",
				"pkg:oci/alpine?repository_url=docker.io%2Flibrary%2Falpine&tag=v1.2.3",
				"pkg:oci/alpine?repository_url=docker.io%2Falpine&tag=v1.2.3",
			},
		},
		{
			"alpine",
			"alpine",
			[]string{"alpine"},
		},
		{
			// two-segment names without a host-like first segment default to
			// Docker Hub, but carry no implicit "library" namespace
			"myorg/myimage:1.0",
			"myorg/myimage",
			[]string{
				"myorg/myimage:1.0",
				"pkg:oci/myimage?tag=1.0",
				"pkg:oci/myimage?repository_url=index.docker.io%2Fmyorg%2Fmyimage&tag=1.0",
				"pkg:oci/myimage?repository_url=docker.io%2Fmyorg%2Fmyimage&tag=1.0",
			},
		},
		{
			// regression test for https://github.com/anchore/grype/issues/3657:
			// namespaced/registry-qualified image names must produce an oci purl
			// with the image's base name (not the full path) while the repository_url
			// qualifier still carrys the full path
			"registry.access.redhat.com/ubi10/podman:10.2",
			"registry.access.redhat.com/ubi10/podman",
			[]string{
				"registry.access.redhat.com/ubi10/podman:10.2",
				"pkg:oci/podman?tag=10.2",
				"pkg:oci/podman?repository_url=registry.access.redhat.com%2Fubi10%2Fpodman&tag=10.2",
			},
		},
		{
			// an explicit Docker Hub host must still be recognized and
			"docker.io/alpine:v1.2.3",
			"docker.io/alpine",
			[]string{
				"docker.io/alpine:v1.2.3",
				"pkg:oci/alpine?tag=v1.2.3",
				"pkg:oci/alpine?repository_url=index.docker.io%2Flibrary%2Falpine&tag=v1.2.3",
				"pkg:oci/alpine?repository_url=docker.io%2Flibrary%2Falpine&tag=v1.2.3",
				"pkg:oci/alpine?repository_url=docker.io%2Falpine&tag=v1.2.3",
			},
		},
		{
			// a registry host:port must not be mistaken for a tag delimiter:
			// the tag here is "1.0", not "5000/myimage:1.0".
			"localhost:5000/myimage:1.0",
			"localhost:5000/myimage",
			[]string{
				"localhost:5000/myimage:1.0",
				"pkg:oci/myimage?tag=1.0",
				"pkg:oci/myimage?repository_url=localhost%3A5000%2Fmyimage&tag=1.0",
			},
		},
	} {
		res := identifiersFromTags([]string{tc.sut}, tc.name)
		require.Equal(t, tc.expected, res)
	}
}

func TestIdentifiersFromDigests(t *testing.T) {
	for _, tc := range []struct {
		sut      string
		expected []string
	}{
		{
			// a bare digest ref is what the docker daemon reports for a Docker
			// Hub image, so every spelling of Docker Hub is emitted
			"alpine@sha256:124c7d2707904eea7431fffe91522a01e5a861a624ee31d03372cc1d138a3126",
			[]string{
				"alpine@sha256:124c7d2707904eea7431fffe91522a01e5a861a624ee31d03372cc1d138a3126",
				"pkg:oci/alpine@sha256%3A124c7d2707904eea7431fffe91522a01e5a861a624ee31d03372cc1d138a3126",
				"pkg:oci/alpine@sha256%3A124c7d2707904eea7431fffe91522a01e5a861a624ee31d03372cc1d138a3126?repository_url=index.docker.io%2Flibrary%2Falpine",
				"pkg:oci/alpine@sha256%3A124c7d2707904eea7431fffe91522a01e5a861a624ee31d03372cc1d138a3126?repository_url=docker.io%2Flibrary%2Falpine",
				"pkg:oci/alpine@sha256%3A124c7d2707904eea7431fffe91522a01e5a861a624ee31d03372cc1d138a3126?repository_url=docker.io%2Falpine",
				"124c7d2707904eea7431fffe91522a01e5a861a624ee31d03372cc1d138a3126",
			},
		},
		{
			// repository_url is the full registry+repository path, including
			// the trailing image name, matching the purl-spec oci examples
			// (e.g. repository_url=docker.io/library/debian).
			"cgr.dev/chainguard/curl@sha256:9543ed09a38605c25c75486573cf530bd886615b993d5e1d1aa58fe5491287bc",
			[]string{
				"cgr.dev/chainguard/curl@sha256:9543ed09a38605c25c75486573cf530bd886615b993d5e1d1aa58fe5491287bc",
				"pkg:oci/curl@sha256%3A9543ed09a38605c25c75486573cf530bd886615b993d5e1d1aa58fe5491287bc",
				"pkg:oci/curl@sha256%3A9543ed09a38605c25c75486573cf530bd886615b993d5e1d1aa58fe5491287bc?repository_url=cgr.dev%2Fchainguard%2Fcurl",
				"9543ed09a38605c25c75486573cf530bd886615b993d5e1d1aa58fe5491287bc",
			},
		},
		{
			"registry.access.redhat.com/ubi10/podman@sha256:0dbb10bb65e5df8a6d6aecb69f130441dc941e306ce89844c2870a25152c44a2",
			[]string{
				"registry.access.redhat.com/ubi10/podman@sha256:0dbb10bb65e5df8a6d6aecb69f130441dc941e306ce89844c2870a25152c44a2",
				"pkg:oci/podman@sha256%3A0dbb10bb65e5df8a6d6aecb69f130441dc941e306ce89844c2870a25152c44a2",
				"pkg:oci/podman@sha256%3A0dbb10bb65e5df8a6d6aecb69f130441dc941e306ce89844c2870a25152c44a2?repository_url=registry.access.redhat.com%2Fubi10%2Fpodman",
				"0dbb10bb65e5df8a6d6aecb69f130441dc941e306ce89844c2870a25152c44a2",
			},
		},
		{
			"alpine",
			[]string{"alpine"},
		},
	} {
		res := identifiersFromDigests([]string{tc.sut})
		require.Equal(t, tc.expected, res)
	}
}

func TestFilterMatches_NoErrorOnEmptyProducts(t *testing.T) {
	tests := []struct {
		name        string
		pkgContext  *pkg.Context
		vexDoc      *openvex.VEX
		matches     *match.Matches
		ignoreRules []match.IgnoreRule
		wantErr     require.ErrorAssertionFunc
	}{
		{
			name: "no error when context has empty products and VEX document has products",
			// when context returns empty products, the code should fall back to VEX products without error
			pkgContext: &pkg.Context{
				Source: &source.Description{
					Name: "alpine",
					Metadata: source.ImageMetadata{
						Tags:        []string{},
						RepoDigests: []string{},
					},
				},
			},
			vexDoc: &openvex.VEX{
				Statements: []openvex.Statement{
					{
						Vulnerability: openvex.Vulnerability{Name: "CVE-2024-1234"},
						Products: []openvex.Product{
							{Component: openvex.Component{ID: "pkg:oci/alpine@sha256:abc123"}},
						},
						Status: openvex.StatusNotAffected,
					},
				},
			},
			matches: func() *match.Matches {
				m := match.NewMatches()
				m.Add(match.Match{
					Vulnerability: vulnerability.Vulnerability{
						Reference: vulnerability.Reference{
							ID: "CVE-2024-1234",
						},
					},
					Package: pkg.Package{
						PURL: "pkg:npm/test@1.0.0",
					},
				})
				return &m
			}(),
			ignoreRules: []match.IgnoreRule{
				{VexStatus: string(openvex.StatusNotAffected)},
			},
		},
		{
			name: "no error when VEX document has multiple products",
			pkgContext: &pkg.Context{
				Source: &source.Description{
					Name: "ubuntu",
					Metadata: source.ImageMetadata{
						Tags:        []string{},
						RepoDigests: []string{},
					},
				},
			},
			vexDoc: &openvex.VEX{
				Statements: []openvex.Statement{
					{
						Vulnerability: openvex.Vulnerability{Name: "CVE-2024-5678"},
						Products: []openvex.Product{
							{Component: openvex.Component{ID: "pkg:oci/ubuntu@sha256:def456"}},
							{Component: openvex.Component{ID: "pkg:oci/debian@sha256:abc789"}},
						},
						Status: openvex.StatusFixed,
					},
				},
			},
			matches: func() *match.Matches {
				m := match.NewMatches()
				return &m
			}(),
			ignoreRules: []match.IgnoreRule{
				{VexStatus: string(openvex.StatusFixed)},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr == nil {
				tt.wantErr = require.NoError
			}

			processor := New()
			remainingMatches, _, err := processor.FilterMatches(
				tt.vexDoc,
				tt.ignoreRules,
				tt.pkgContext,
				tt.matches,
				nil,
			)
			tt.wantErr(t, err)

			if err != nil {
				return
			}

			// basic sanity checks - we're mainly testing that the fallback doesn't cause errors
			require.NotNil(t, remainingMatches)
		})
	}
}

func TestFilterMatches_ImageProductNoSubcomponents(t *testing.T) {
	// Scenario 1: Image product, no subcomponents → applies to entire scan.
	// When a VEX statement specifies an image product with no subcomponents,
	// ALL matches for that products CVE should be filtered, regardless of which package.
	processor := New()

	pkgCtx := &pkg.Context{
		Source: &source.Description{
			Name: "alpine",
			Metadata: source.ImageMetadata{
				RepoDigests: []string{
					"alpine@sha256:124c7d2707904eea7431fffe91522a01e5a861a624ee31d03372cc1d138a3126",
				},
			},
		},
	}

	vexDoc := &openvex.VEX{
		Statements: []openvex.Statement{
			{
				Vulnerability: openvex.Vulnerability{Name: "CVE-2023-1255"},
				Products: []openvex.Product{
					{
						Component: openvex.Component{
							ID: "pkg:oci/alpine@sha256%3A124c7d2707904eea7431fffe91522a01e5a861a624ee31d03372cc1d138a3126",
						},
						// No subcomponents — applies to entire product
					},
				},
				Status: openvex.StatusFixed,
			},
		},
	}

	matchLibcrypto := match.Match{
		Vulnerability: vulnerability.Vulnerability{
			Reference: vulnerability.Reference{
				ID: "CVE-2023-1255",
			},
		},
		Package: pkg.Package{
			ID:   "cc8f90662d91481d",
			Name: "libcrypto3",
			PURL: "pkg:apk/alpine/libcrypto3@3.0.8-r3",
		},
	}
	matchLibssl := match.Match{
		Vulnerability: vulnerability.Vulnerability{
			Reference: vulnerability.Reference{
				ID: "CVE-2023-1255",
			},
		},
		Package: pkg.Package{
			ID:   "aa1234567890abcd",
			Name: "libssl3",
			PURL: "pkg:apk/alpine/libssl3@3.0.8-r3",
		},
	}

	matches := match.NewMatches(matchLibcrypto, matchLibssl)

	remaining, ignored, err := processor.FilterMatches(
		vexDoc, nil, pkgCtx, &matches, nil,
	)
	require.NoError(t, err)

	// Both matches should be filtered because there are no subcomponents
	require.Empty(t, remaining.Sorted(), "all matches for the CVE should be filtered when no subcomponents are specified")
	require.Len(t, ignored, 2, "both matches should be in the ignored list")
}

func TestFilterMatches_PackageProductDirectoryScan(t *testing.T) {
	// When the source is a directory scan and the VEX product is a package PURL,
	// the second pass of findMatchingStatement matches the package PURL as the product.
	processor := New()

	pkgCtx := &pkg.Context{
		Source: &source.Description{
			Metadata: source.DirectoryMetadata{
				Path: "/some/project",
			},
		},
	}

	vexDoc := &openvex.VEX{
		Statements: []openvex.Statement{
			{
				Vulnerability: openvex.Vulnerability{Name: "CVE-2023-1255"},
				Products: []openvex.Product{
					{
						Component: openvex.Component{
							ID: "pkg:apk/alpine/libcrypto3@3.0.8-r3",
						},
					},
				},
				Status: openvex.StatusFixed,
			},
		},
	}

	matchLibcrypto := match.Match{
		Vulnerability: vulnerability.Vulnerability{
			Reference: vulnerability.Reference{
				ID: "CVE-2023-1255",
			},
		},
		Package: pkg.Package{
			ID:   "cc8f90662d91481d",
			Name: "libcrypto3",
			PURL: "pkg:apk/alpine/libcrypto3@3.0.8-r3",
		},
	}

	matches := match.NewMatches(matchLibcrypto)

	remaining, ignored, err := processor.FilterMatches(
		vexDoc, nil, pkgCtx, &matches, nil,
	)
	require.NoError(t, err)

	require.Empty(t, remaining.Sorted(), "match should be filtered when package PURL matches VEX product")
	require.Len(t, ignored, 1, "match should be in the ignored list")
}

func TestFilterMatches_PackageProductNoOverMatch(t *testing.T) {
	// When the VEX product is a package PURL (not an image), only the matching
	// package should be filtered — not other packages with the same CVE.
	vexDoc := &openvex.VEX{
		Statements: []openvex.Statement{
			{
				Vulnerability: openvex.Vulnerability{Name: "CVE-2023-1255"},
				Products: []openvex.Product{
					{
						Component: openvex.Component{
							ID: "pkg:apk/alpine/libcrypto3@3.0.8-r3",
						},
					},
				},
				Status: openvex.StatusFixed,
			},
		},
	}

	matchLibcrypto := match.Match{
		Vulnerability: vulnerability.Vulnerability{
			Reference: vulnerability.Reference{
				ID: "CVE-2023-1255",
			},
		},
		Package: pkg.Package{
			ID:   "cc8f90662d91481d",
			Name: "libcrypto3",
			PURL: "pkg:apk/alpine/libcrypto3@3.0.8-r3",
		},
	}
	matchCurl := match.Match{
		Vulnerability: vulnerability.Vulnerability{
			Reference: vulnerability.Reference{
				ID: "CVE-2023-1255",
			},
		},
		Package: pkg.Package{
			ID:   "bb9876543210fedc",
			Name: "curl",
			PURL: "pkg:apk/alpine/curl@8.1.2-r0",
		},
	}

	tests := []struct {
		name       string
		pkgContext *pkg.Context
	}{
		{
			name: "image scan",
			pkgContext: &pkg.Context{
				Source: &source.Description{
					Name: "alpine",
					Metadata: source.ImageMetadata{
						RepoDigests: []string{
							"alpine@sha256:124c7d2707904eea7431fffe91522a01e5a861a624ee31d03372cc1d138a3126",
						},
					},
				},
			},
		},
		{
			name: "directory scan",
			pkgContext: &pkg.Context{
				Source: &source.Description{
					Metadata: source.DirectoryMetadata{
						Path: "/some/project",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			processor := New()
			matches := match.NewMatches(matchLibcrypto, matchCurl)

			remaining, ignored, err := processor.FilterMatches(
				vexDoc, nil, tt.pkgContext, &matches, nil,
			)
			require.NoError(t, err)

			require.Len(t, remaining.Sorted(), 1, "only the non-matching package should remain")
			require.Equal(t, "curl", remaining.Sorted()[0].Package.Name)
			require.Len(t, ignored, 1, "only the matching package should be ignored")
			require.Equal(t, "libcrypto3", ignored[0].Match.Package.Name)
		})
	}
}

func TestProductIdentifiersFromContext(t *testing.T) {
	tests := []struct {
		name       string
		pkgContext *pkg.Context
		want       []string
	}{
		{
			name: "image metadata with tags and digests",
			pkgContext: &pkg.Context{
				Source: &source.Description{
					Name: "alpine",
					Metadata: source.ImageMetadata{
						Tags: []string{"alpine:3.18", "alpine:latest"},
						RepoDigests: []string{
							"alpine@sha256:124c7d2707904eea7431fffe91522a01e5a861a624ee31d03372cc1d138a3126",
						},
					},
				},
			},
			want: []string{
				"alpine:3.18",
				"pkg:oci/alpine?tag=3.18",
				"pkg:oci/alpine?repository_url=index.docker.io%2Flibrary%2Falpine&tag=3.18",
				"pkg:oci/alpine?repository_url=docker.io%2Flibrary%2Falpine&tag=3.18",
				"pkg:oci/alpine?repository_url=docker.io%2Falpine&tag=3.18",
				"alpine:latest",
				"pkg:oci/alpine?tag=latest",
				"pkg:oci/alpine?repository_url=index.docker.io%2Flibrary%2Falpine&tag=latest",
				"pkg:oci/alpine?repository_url=docker.io%2Flibrary%2Falpine&tag=latest",
				"pkg:oci/alpine?repository_url=docker.io%2Falpine&tag=latest",
				"alpine@sha256:124c7d2707904eea7431fffe91522a01e5a861a624ee31d03372cc1d138a3126",
				"pkg:oci/alpine@sha256%3A124c7d2707904eea7431fffe91522a01e5a861a624ee31d03372cc1d138a3126",
				"pkg:oci/alpine@sha256%3A124c7d2707904eea7431fffe91522a01e5a861a624ee31d03372cc1d138a3126?repository_url=index.docker.io%2Flibrary%2Falpine",
				"pkg:oci/alpine@sha256%3A124c7d2707904eea7431fffe91522a01e5a861a624ee31d03372cc1d138a3126?repository_url=docker.io%2Flibrary%2Falpine",
				"pkg:oci/alpine@sha256%3A124c7d2707904eea7431fffe91522a01e5a861a624ee31d03372cc1d138a3126?repository_url=docker.io%2Falpine",
				"124c7d2707904eea7431fffe91522a01e5a861a624ee31d03372cc1d138a3126",
			},
		},
		{
			name: "image metadata with only tags",
			pkgContext: &pkg.Context{
				Source: &source.Description{
					Name: "ubuntu",
					Metadata: source.ImageMetadata{
						Tags:        []string{"ubuntu:22.04"},
						RepoDigests: []string{},
					},
				},
			},
			want: []string{
				"ubuntu:22.04",
				"pkg:oci/ubuntu?tag=22.04",
				"pkg:oci/ubuntu?repository_url=index.docker.io%2Flibrary%2Fubuntu&tag=22.04",
				"pkg:oci/ubuntu?repository_url=docker.io%2Flibrary%2Fubuntu&tag=22.04",
				"pkg:oci/ubuntu?repository_url=docker.io%2Fubuntu&tag=22.04",
			},
		},
		{
			name: "image metadata with only digests",
			pkgContext: &pkg.Context{
				Source: &source.Description{
					Name: "nginx",
					Metadata: source.ImageMetadata{
						Tags: []string{},
						RepoDigests: []string{
							"nginx@sha256:abc123",
						},
					},
				},
			},
			want: []string{
				"nginx@sha256:abc123",
			},
		},
		{
			name: "image metadata with no tags or digests",
			pkgContext: &pkg.Context{
				Source: &source.Description{
					Name: "busybox",
					Metadata: source.ImageMetadata{
						Tags:        []string{},
						RepoDigests: []string{},
					},
				},
			},
			want: nil,
		},
		{
			name: "generic source with name and version",
			pkgContext: &pkg.Context{
				Source: &source.Description{
					Name:    "MyApp",
					Version: "1.2.3",
					Metadata: source.DirectoryMetadata{
						Path: "/some/path",
					},
				},
			},
			want: []string{"pkg:generic/myapp@1.2.3"},
		},
		{
			name: "generic source with lowercase name",
			pkgContext: &pkg.Context{
				Source: &source.Description{
					Name:    "my-service",
					Version: "2.0.0",
					Metadata: source.FileMetadata{
						Path: "/path/to/file",
					},
				},
			},
			want: []string{"pkg:generic/my-service@2.0.0"},
		},
		{
			name: "generic source with only name",
			pkgContext: &pkg.Context{
				Source: &source.Description{
					Name:    "MyApp",
					Version: "",
					Metadata: source.DirectoryMetadata{
						Path: "/some/path",
					},
				},
			},
			want: []string{},
		},
		{
			name: "generic source with only version",
			pkgContext: &pkg.Context{
				Source: &source.Description{
					Name:    "",
					Version: "1.0.0",
					Metadata: source.DirectoryMetadata{
						Path: "/some/path",
					},
				},
			},
			want: []string{},
		},
		{
			name: "generic source with neither name nor version",
			pkgContext: &pkg.Context{
				Source: &source.Description{
					Name:    "",
					Version: "",
					Metadata: source.DirectoryMetadata{
						Path: "/some/path",
					},
				},
			},
			want: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := productIdentifiersFromContext(tt.pkgContext)

			require.Equal(t, tt.want, got)
		})
	}
}

func TestIdentifiersFromDigests_NormalizesDockerHubRepositoryURL(t *testing.T) {
	const hash = "124c7d2707904eea7431fffe91522a01e5a861a624ee31d03372cc1d138a3126"
	const digest = "docker.io/library/alpine@sha256:" + hash

	ids := identifiersFromDigests([]string{digest})

	var repoURLs []string
	for _, id := range ids {
		if !strings.HasPrefix(id, "pkg:oci/") {
			continue
		}

		p, err := packageurl.FromString(id)
		require.NoError(t, err)

		if p.Name == "alpine" && p.Version == "sha256:"+hash {
			repoURLs = append(repoURLs, p.Qualifiers.Map()["repository_url"])
		}
	}

	// purl-spec-conformant form: the full registry+repository path, in every
	// spelling of Docker Hub a document may use
	// see https://github.com/anchore/grype/issues/3657
	require.Equal(t, []string{
		"",
		"index.docker.io/library/alpine",
		"docker.io/library/alpine",
		"docker.io/alpine",
	}, repoURLs)
}

func TestOCIRepositoryIdentity(t *testing.T) {
	tests := []struct {
		input            string
		expectedBaseName string
		expectedRepoURLs []string
	}{
		{"alpine", "alpine", []string{"index.docker.io/library/alpine", "docker.io/library/alpine", "docker.io/alpine"}},
		{"myorg/myimage", "myimage", []string{"index.docker.io/myorg/myimage", "docker.io/myorg/myimage"}},
		{"docker.io/alpine", "alpine", []string{"index.docker.io/library/alpine", "docker.io/library/alpine", "docker.io/alpine"}},
		{"docker.io/library/alpine", "alpine", []string{"index.docker.io/library/alpine", "docker.io/library/alpine", "docker.io/alpine"}},
		{"registry.access.redhat.com/ubi10/podman", "podman", []string{"registry.access.redhat.com/ubi10/podman"}},
		{"gcr.io/myorg/image", "image", []string{"gcr.io/myorg/image"}},
		{"DOCKER.IO/alpine", "alpine", []string{"index.docker.io/library/alpine", "docker.io/library/alpine", "docker.io/alpine"}},
		{"registry-1.docker.io/alpine", "alpine", []string{"index.docker.io/library/alpine", "docker.io/library/alpine", "docker.io/alpine"}},
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			repo, err := name.NewRepository(tc.input)
			require.NoError(t, err)
			baseName, repoURLs := ociRepositoryIdentity(repo)
			require.Equal(t, tc.expectedBaseName, baseName)
			require.Equal(t, tc.expectedRepoURLs, repoURLs)
		})
	}
}

func TestTagSuffix(t *testing.T) {
	tests := []struct {
		input       string
		expectedTag string
		expectedOK  bool
	}{
		{"alpine:v1.2.3", "v1.2.3", true},
		{"alpine", "", false},
		{"registry.access.redhat.com/ubi10/podman:10.2", "10.2", true},
		{"localhost:5000/myimage:1.0", "1.0", true},
		{"localhost:5000/myimage", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			tag, ok := tagSuffix(tc.input)
			require.Equal(t, tc.expectedOK, ok)
			require.Equal(t, tc.expectedTag, tag)
		})
	}
}

func TestFilterMatches_OCIProductWithFullRepositoryURL(t *testing.T) {
	processor := New()

	pkgCtx := &pkg.Context{
		Source: &source.Description{
			Name: "registry.access.redhat.com/ubi10/podman",
			Metadata: source.ImageMetadata{
				Tags: []string{
					"registry.access.redhat.com/ubi10/podman:10.2",
				},
				RepoDigests: []string{
					"registry.access.redhat.com/ubi10/podman@sha256:0dbb10bb65e5df8a6d6aecb69f130441dc941e306ce89844c2870a25152c44a2",
				},
			},
		},
	}

	vexDoc := &openvex.VEX{
		Statements: []openvex.Statement{
			{
				Vulnerability: openvex.Vulnerability{Name: "GHSA-fhqq-8f65-5xfc"},
				Products: []openvex.Product{
					{
						Component: openvex.Component{
							ID: "pkg:oci/podman?repository_url=registry.access.redhat.com/ubi10/podman",
						},
					},
				},
				Status: openvex.StatusFixed,
			},
		},
	}

	matches := match.NewMatches(match.Match{
		Vulnerability: vulnerability.Vulnerability{
			Reference: vulnerability.Reference{ID: "GHSA-fhqq-8f65-5xfc"},
		},
		Package: pkg.Package{
			Name: "github.com/containers/podman/v5",
			PURL: "pkg:golang/github.com/containers/podman/v5@v5.0.0-20260710060113-6178304ed448+dirty",
		},
	})

	remaining, ignored, err := processor.FilterMatches(vexDoc, nil, pkgCtx, &matches, nil)
	require.NoError(t, err)

	require.Empty(t, remaining.Sorted(), "match should be suppressed by the repository_url-qualified oci product")
	require.Len(t, ignored, 1)
}
