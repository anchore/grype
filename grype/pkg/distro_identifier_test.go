package pkg

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

func TestApplyDistroIdentifiers(t *testing.T) {
	// newSBOM builds an SBOM shaped the way syft would report it: an image source with config
	// labels, and a file catalog holding whatever marker paths a file cataloger recorded.
	newSBOM := func(src source.Description, paths ...string) *sbom.SBOM {
		fileMetadata := make(map[file.Coordinates]file.Metadata)
		for _, p := range paths {
			coords := file.Coordinates{RealPath: p}
			fileMetadata[coords] = file.Metadata{
				Path: p,
			}
		}

		return &sbom.SBOM{
			Artifacts: sbom.Artifacts{
				Packages:     pkg.NewCollection(),
				FileMetadata: fileMetadata,
			},
			Source: src,
			Descriptor: sbom.Descriptor{
				Name:    "syft",
				Version: "v1.0.0",
			},
		}
	}

	imageSBOM := func(labels map[string]string, paths ...string) *sbom.SBOM {
		return newSBOM(source.Description{
			ID:      "sha256:0123456789abcdef",
			Name:    "docker.io/some/image",
			Version: "sha256:0123456789abcdef",
			Metadata: source.ImageMetadata{
				UserInput:      "some/image:latest",
				ID:             "sha256:0123456789abcdef",
				ManifestDigest: "sha256:0123456789abcdef",
				MediaType:      "application/vnd.docker.distribution.manifest.v2+json",
				Labels:         labels,
			},
		}, paths...)
	}

	dirSBOM := func(path string, paths ...string) *sbom.SBOM {
		return newSBOM(source.Description{
			ID:       "dir-source",
			Name:     path,
			Metadata: source.DirectoryMetadata{Path: path},
		}, paths...)
	}

	tests := []struct {
		name        string
		distro      *distro.Distro
		sbom        *sbom.SBOM
		identifiers []distro.Identifier
		want        func(t *testing.T, got *distro.Distro)
	}{
		{
			name:   "nil distro is a no-op",
			distro: nil,
			sbom:   imageSBOM(map[string]string{"maintainer": "RapidFort Curation Team"}),
			want: func(t *testing.T, got *distro.Distro) {
				assert.Nil(t, got)
			},
		},
		{
			name:   "nil sbom is a no-op",
			distro: distro.New(distro.Ubuntu, "20.04", ""),
			sbom:   nil,
			want: func(t *testing.T, got *distro.Distro) {
				require.NotNil(t, got)
				assert.Equal(t, distro.Ubuntu, got.Type)
			},
		},
		{
			name:   "marker file triggers the identifier without any label",
			distro: distro.New(distro.Ubuntu, "20.04", ""),
			sbom:   dirSBOM("/some/path", "/usr/share/rapidfort/curated.json"),
			want: func(t *testing.T, got *distro.Distro) {
				require.NotNil(t, got)
				assert.Equal(t, distro.RapidFortUbuntu, got.Type)
				assert.Equal(t, "20.04", got.Version)
			},
		},
		{
			name:   "file catalog without the marker file is a no-op",
			distro: distro.New(distro.Ubuntu, "20.04", ""),
			sbom:   dirSBOM("/some/path", "/etc/os-release", "/usr/lib/os-release"),
			want: func(t *testing.T, got *distro.Distro) {
				assert.Equal(t, distro.Ubuntu, got.Type)
			},
		},
		{
			name:   "non-image source is a no-op",
			distro: distro.New(distro.Ubuntu, "20.04", ""),
			sbom:   dirSBOM("/some/path"),
			want: func(t *testing.T, got *distro.Distro) {
				assert.Equal(t, distro.Ubuntu, got.Type)
			},
		},
		{
			name:   "matching label remaps ubuntu and drops the codename",
			distro: distro.New(distro.Ubuntu, "20.04", "focal"),
			sbom:   imageSBOM(map[string]string{"maintainer": "RapidFort Curation Team <rfcurators@rapidfort.com>"}),
			want: func(t *testing.T, got *distro.Distro) {
				require.NotNil(t, got)
				assert.Equal(t, distro.RapidFortUbuntu, got.Type)
				assert.Equal(t, "20.04", got.Version)
				// the codename must be dropped: identified OS records carry no codenames, and a
				// codename on the distro adds an OS row filter that would yield zero rows
				assert.Empty(t, got.Codename)
			},
		},
		{
			name:   "matching label remaps rhel and preserves id-like",
			distro: distro.New(distro.RedHat, "9.4", "", "fedora"),
			sbom:   imageSBOM(map[string]string{"maintainer": "rapidfort"}),
			want: func(t *testing.T, got *distro.Distro) {
				assert.Equal(t, distro.RapidFortRedHat, got.Type)
				assert.Equal(t, "9.4", got.Version)
				assert.Equal(t, []string{"fedora"}, got.IDLike)
			},
		},
		{
			name: "base fix channels are cleared",
			distro: func() *distro.Distro {
				d := distro.New(distro.Ubuntu, "20.04", "")
				d.Channels = []string{"esm"}
				return d
			}(),
			sbom: imageSBOM(map[string]string{"maintainer": "RapidFort"}),
			want: func(t *testing.T, got *distro.Distro) {
				assert.Equal(t, distro.RapidFortUbuntu, got.Type)
				assert.Empty(t, got.Channels)
			},
		},
		{
			name:   "label key is case-insensitive",
			distro: distro.New(distro.Alpine, "3.20", ""),
			sbom:   imageSBOM(map[string]string{"Maintainer": "RAPIDFORT team"}),
			want: func(t *testing.T, got *distro.Distro) {
				assert.Equal(t, distro.RapidFortAlpine, got.Type)
			},
		},
		{
			name:   "other maintainer is a no-op",
			distro: distro.New(distro.Ubuntu, "20.04", ""),
			sbom:   imageSBOM(map[string]string{"maintainer": "Some Other Vendor"}),
			want: func(t *testing.T, got *distro.Distro) {
				assert.Equal(t, distro.Ubuntu, got.Type)
			},
		},
		{
			name:   "unmapped distro is a no-op",
			distro: distro.New(distro.Gentoo, "2.15", ""),
			sbom:   imageSBOM(map[string]string{"maintainer": "rapidfort"}),
			want: func(t *testing.T, got *distro.Distro) {
				assert.Equal(t, distro.Gentoo, got.Type)
			},
		},
		{
			name:   "apply never disables the rule",
			distro: distro.New(distro.Ubuntu, "20.04", ""),
			sbom:   imageSBOM(map[string]string{"maintainer": "rapidfort"}),
			identifiers: func() []distro.Identifier {
				identifiers := distro.DefaultIdentifiers()
				for i := range identifiers {
					identifiers[i].Apply = distro.ChannelNeverEnabled
				}
				return identifiers
			}(),
			want: func(t *testing.T, got *distro.Distro) {
				assert.Equal(t, distro.Ubuntu, got.Type)
			},
		},
		{
			name:   "identifier with channels pins them",
			distro: distro.New(distro.Debian, "12", ""),
			sbom:   imageSBOM(map[string]string{"maintainer": "rapidfort"}),
			identifiers: []distro.Identifier{
				{
					Name:      "rapidfort",
					Label:     distro.LabelMatcher{Key: "maintainer", ValuePrefix: "rapidfort"},
					DistroIDs: map[string]string{"debian": string(distro.RapidFortDebian)},
					Apply:     distro.ChannelConditionallyEnabled,
					Channels:  []string{"rf"},
				},
			},
			want: func(t *testing.T, got *distro.Distro) {
				assert.Equal(t, distro.RapidFortDebian, got.Type)
				assert.Equal(t, []string{"rf"}, got.Channels)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			identifiers := tt.identifiers
			if identifiers == nil {
				identifiers = distro.DefaultIdentifiers()
			}
			got := applyDistroIdentifiers(tt.sbom, tt.distro, identifiers)
			tt.want(t, got)
		})
	}
}
