package openvex

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/syft/syft/source"
)

func Test_productIdentifiersFromContext(t *testing.T) {

	tests := []struct {
		name       string
		pkgContext pkg.Context
		want       []string
		wantErr    require.ErrorAssertionFunc
	}{
		{
			name:       "no source",
			pkgContext: pkg.Context{},
		},
		{
			name: "source with no metadata",
			pkgContext: pkg.Context{
				Source: &source.Description{},
			},
		},
		{
			name: "source with empty image metadata",
			pkgContext: pkg.Context{
				Source: &source.Description{
					Metadata: source.ImageMetadata{},
				},
			},
		},
		{
			name: "source with unusable image input",
			pkgContext: pkg.Context{
				Source: &source.Description{
					Metadata: source.ImageMetadata{
						UserInput: "some-image:tag",
						RepoDigests: []string{
							"some-other-image:tag", // we shouldn't expect this, but should be resilient to it
						},
					},
				},
			},
		},
		{
			name: "source with usable image input",
			pkgContext: pkg.Context{
				Source: &source.Description{
					Metadata: source.ImageMetadata{
						UserInput: "some-image:tag@sha256:124c7d2707904eea7431fffe91522a01e5a861a624ee31d03372cc1d138a3126",
						RepoDigests: []string{
							"some-other-image@sha256:a01fe91372c2a3126624ee31d0c1de5a861ad2707904eea7431f523f138124c7",
						},
					},
				},
			},
			want: []string{
				"124c7d2707904eea7431fffe91522a01e5a861a624ee31d03372cc1d138a3126",
				"pkg:oci/some-image@sha256%3A124c7d2707904eea7431fffe91522a01e5a861a624ee31d03372cc1d138a3126?repository_url=index.docker.io%2Flibrary",
				"a01fe91372c2a3126624ee31d0c1de5a861ad2707904eea7431f523f138124c7",
				"pkg:oci/some-other-image@sha256%3Aa01fe91372c2a3126624ee31d0c1de5a861ad2707904eea7431f523f138124c7?repository_url=index.docker.io%2Flibrary",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr == nil {
				tt.wantErr = require.NoError
			}
			got, err := productIdentifiersFromContext(tt.pkgContext)
			tt.wantErr(t, err)
			assert.ElementsMatch(t, tt.want, got)
		})
	}
}

func Test_searchableIdentifiers(t *testing.T) {
	type args struct {
	}
	tests := []struct {
		name        string
		identifiers []string
		want        []string
	}{
		{
			name: "no identifiers",
		},
		{
			name: "only keep pacakge urls",
			identifiers: []string{
				"pkg:deb/debian@buster",
				"pkg:deb/debian@buster?repository_url=http://deb.debian.org/debian",
				"pkg:oci/some-other-image@sha256%3Aa01fe91372c2a3126624ee31d0c1de5a861ad2707904eea7431f523f138124c7?repository_url=index.docker.io%2Flibrary",
				"124c7d2707904eea7431fffe91522a01e5a861a624ee31d03372cc1d138a3126",
				"somethingelse",
			},
			want: []string{
				"pkg:deb/debian@buster",
				"pkg:deb/debian@buster?repository_url=http://deb.debian.org/debian",
				"pkg:oci/some-other-image@sha256%3Aa01fe91372c2a3126624ee31d0c1de5a861ad2707904eea7431f523f138124c7?repository_url=index.docker.io%2Flibrary",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, searchableIdentifiers(tt.identifiers))
		})
	}
}

func Test_subcomponentIdentifiersFromMatch(t *testing.T) {

	tests := []struct {
		name  string
		match *match.Match
		want  []string
	}{
		{
			name: "no match",
		},
		{
			name: "no purl",
			match: &match.Match{
				Package: pkg.Package{
					PURL: "",
				},
			},
		},
		{
			name: "keep purl",
			match: &match.Match{
				Package: pkg.Package{
					PURL: "pkg:deb/debian@buster?repository_url=http://deb.debian.org/debian",
				},
			},
			want: []string{
				"pkg:deb/debian@buster?repository_url=http://deb.debian.org/debian",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, subcomponentIdentifiersFromMatch(tt.match))
		})
	}
}
