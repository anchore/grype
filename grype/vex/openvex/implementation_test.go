package openvex

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/pkg"
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

func TestProductIdentifiersFromContext(t *testing.T) {
	tests := []struct {
		name       string
		pkgContext *pkg.Context
		want       []string
		wantErr    require.ErrorAssertionFunc
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
			wantErr: require.Error,
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
			wantErr: require.Error,
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
			wantErr: require.Error,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr == nil {
				tt.wantErr = require.NoError
			}

			got, err := productIdentifiersFromContext(tt.pkgContext)
			tt.wantErr(t, err)

			if err != nil {
				return
			}

			require.Equal(t, tt.want, got)
		})
	}
}
