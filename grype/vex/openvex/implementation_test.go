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

func TestProductIdentifierFromVEX(t *testing.T) {
	tests := []struct {
		name     string
		doc      *openvex.VEX
		expected []string
	}{
		{
			name: "single product in statement",
			doc: &openvex.VEX{
				Statements: []openvex.Statement{
					{
						Products: []openvex.Product{
							{Component: openvex.Component{ID: "pkg:oci/alpine@sha256:abc123"}},
						},
					},
				},
			},
			expected: []string{"pkg:oci/alpine@sha256:abc123"},
		},
		{
			name: "multiple products in single statement",
			doc: &openvex.VEX{
				Statements: []openvex.Statement{
					{
						Products: []openvex.Product{
							{Component: openvex.Component{ID: "pkg:oci/alpine@sha256:abc123"}},
							{Component: openvex.Component{ID: "pkg:oci/ubuntu@sha256:def456"}},
						},
					},
				},
			},
			expected: []string{"pkg:oci/alpine@sha256:abc123", "pkg:oci/ubuntu@sha256:def456"},
		},
		{
			name: "multiple statements with products",
			doc: &openvex.VEX{
				Statements: []openvex.Statement{
					{
						Products: []openvex.Product{
							{Component: openvex.Component{ID: "pkg:oci/alpine@sha256:abc123"}},
						},
					},
					{
						Products: []openvex.Product{
							{Component: openvex.Component{ID: "pkg:oci/ubuntu@sha256:def456"}},
						},
					},
				},
			},
			expected: []string{"pkg:oci/alpine@sha256:abc123", "pkg:oci/ubuntu@sha256:def456"},
		},
		{
			name: "empty statements",
			doc: &openvex.VEX{
				Statements: []openvex.Statement{},
			},
			expected: nil,
		},
		{
			name: "statement with no products",
			doc: &openvex.VEX{
				Statements: []openvex.Statement{
					{
						Products: []openvex.Product{},
					},
				},
			},
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := productIdentifierFromVEX(tt.doc)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestFilterMatches_FallbackToVEXProducts(t *testing.T) {
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
