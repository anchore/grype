package openvex

import (
	"testing"

	openvex "github.com/openvex/go-vex/pkg/vex"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/source"
)

func TestIdentifiersFromTags(t *testing.T) {
	for _, tc := range []struct {
		sut      string
		name     string
		expected []string
	}{
		{
			"alpine:v1.2.3",
			"alpine",
			[]string{"alpine:v1.2.3", "pkg:oci/alpine?tag=v1.2.3"},
		},
		{
			"alpine",
			"alpine",
			[]string{"alpine"},
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
			"alpine@sha256:124c7d2707904eea7431fffe91522a01e5a861a624ee31d03372cc1d138a3126",
			[]string{
				"alpine@sha256:124c7d2707904eea7431fffe91522a01e5a861a624ee31d03372cc1d138a3126",
				"pkg:oci/alpine@sha256%3A124c7d2707904eea7431fffe91522a01e5a861a624ee31d03372cc1d138a3126?repository_url=index.docker.io%2Flibrary",
				"124c7d2707904eea7431fffe91522a01e5a861a624ee31d03372cc1d138a3126",
			},
		},
		{
			"cgr.dev/chainguard/curl@sha256:9543ed09a38605c25c75486573cf530bd886615b993d5e1d1aa58fe5491287bc",
			[]string{
				"cgr.dev/chainguard/curl@sha256:9543ed09a38605c25c75486573cf530bd886615b993d5e1d1aa58fe5491287bc",
				"pkg:oci/curl@sha256%3A9543ed09a38605c25c75486573cf530bd886615b993d5e1d1aa58fe5491287bc?repository_url=cgr.dev%2Fchainguard",
				"9543ed09a38605c25c75486573cf530bd886615b993d5e1d1aa58fe5491287bc",
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
				"alpine:latest",
				"pkg:oci/alpine?tag=latest",
				"alpine@sha256:124c7d2707904eea7431fffe91522a01e5a861a624ee31d03372cc1d138a3126",
				"pkg:oci/alpine@sha256%3A124c7d2707904eea7431fffe91522a01e5a861a624ee31d03372cc1d138a3126?repository_url=index.docker.io%2Flibrary",
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
