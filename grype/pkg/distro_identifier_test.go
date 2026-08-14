package pkg

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/syft/syft/source"
)

func TestApplyDistroIdentifiers(t *testing.T) {
	rapidfortImageSource := func(labels map[string]string) *source.Description {
		return &source.Description{
			Metadata: source.ImageMetadata{
				Labels: labels,
			},
		}
	}

	tests := []struct {
		name      string
		distro    *distro.Distro
		src       *source.Description
		hasPath   func(string) bool
		overrides []distro.Identifier
		want      func(t *testing.T, got *distro.Distro)
	}{
		{
			name:   "nil distro is a no-op",
			distro: nil,
			src:    rapidfortImageSource(map[string]string{"maintainer": "RapidFort Curation Team"}),
			want: func(t *testing.T, got *distro.Distro) {
				assert.Nil(t, got)
			},
		},
		{
			name:   "nil source and nil probe is a no-op",
			distro: distro.New(distro.Ubuntu, "20.04", ""),
			src:    nil,
			want: func(t *testing.T, got *distro.Distro) {
				require.NotNil(t, got)
				assert.Equal(t, distro.Ubuntu, got.Type)
			},
		},
		{
			name:    "marker file triggers the override without any label",
			distro:  distro.New(distro.Ubuntu, "20.04", ""),
			src:     nil,
			hasPath: func(path string) bool { return path == "/usr/share/rapidfort/curated.json" },
			want: func(t *testing.T, got *distro.Distro) {
				require.NotNil(t, got)
				assert.Equal(t, distro.RapidFortUbuntu, got.Type)
				assert.Equal(t, "20.04", got.Version)
			},
		},
		{
			name:    "probe without the marker file is a no-op",
			distro:  distro.New(distro.Ubuntu, "20.04", ""),
			src:     nil,
			hasPath: func(string) bool { return false },
			want: func(t *testing.T, got *distro.Distro) {
				assert.Equal(t, distro.Ubuntu, got.Type)
			},
		},
		{
			name:   "non-image source is a no-op",
			distro: distro.New(distro.Ubuntu, "20.04", ""),
			src: &source.Description{
				Metadata: source.DirectoryMetadata{Path: "/some/path"},
			},
			want: func(t *testing.T, got *distro.Distro) {
				assert.Equal(t, distro.Ubuntu, got.Type)
			},
		},
		{
			name:   "matching label remaps ubuntu and drops the codename",
			distro: distro.New(distro.Ubuntu, "20.04", "focal"),
			src:    rapidfortImageSource(map[string]string{"maintainer": "RapidFort Curation Team <rfcurators@rapidfort.com>"}),
			want: func(t *testing.T, got *distro.Distro) {
				require.NotNil(t, got)
				assert.Equal(t, distro.RapidFortUbuntu, got.Type)
				assert.Equal(t, "20.04", got.Version)
				// the codename must be dropped: override OS records carry no codenames, and a
				// codename on the distro adds an OS row filter that would yield zero rows
				assert.Empty(t, got.Codename)
			},
		},
		{
			name:   "matching label remaps rhel and preserves id-like",
			distro: distro.New(distro.RedHat, "9.4", "", "fedora"),
			src:    rapidfortImageSource(map[string]string{"maintainer": "rapidfort"}),
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
			src: rapidfortImageSource(map[string]string{"maintainer": "RapidFort"}),
			want: func(t *testing.T, got *distro.Distro) {
				assert.Equal(t, distro.RapidFortUbuntu, got.Type)
				assert.Empty(t, got.Channels)
			},
		},
		{
			name:   "label key is case-insensitive",
			distro: distro.New(distro.Alpine, "3.20", ""),
			src:    rapidfortImageSource(map[string]string{"Maintainer": "RAPIDFORT team"}),
			want: func(t *testing.T, got *distro.Distro) {
				assert.Equal(t, distro.RapidFortAlpine, got.Type)
			},
		},
		{
			name:   "other maintainer is a no-op",
			distro: distro.New(distro.Ubuntu, "20.04", ""),
			src:    rapidfortImageSource(map[string]string{"maintainer": "Some Other Vendor"}),
			want: func(t *testing.T, got *distro.Distro) {
				assert.Equal(t, distro.Ubuntu, got.Type)
			},
		},
		{
			name:   "unmapped distro is a no-op",
			distro: distro.New(distro.Gentoo, "2.15", ""),
			src:    rapidfortImageSource(map[string]string{"maintainer": "rapidfort"}),
			want: func(t *testing.T, got *distro.Distro) {
				assert.Equal(t, distro.Gentoo, got.Type)
			},
		},
		{
			name:   "apply never disables the rule",
			distro: distro.New(distro.Ubuntu, "20.04", ""),
			src:    rapidfortImageSource(map[string]string{"maintainer": "rapidfort"}),
			overrides: func() []distro.Identifier {
				overrides := distro.DefaultIdentifiers()
				for i := range overrides {
					overrides[i].Apply = distro.ChannelNeverEnabled
				}
				return overrides
			}(),
			want: func(t *testing.T, got *distro.Distro) {
				assert.Equal(t, distro.Ubuntu, got.Type)
			},
		},
		{
			name:   "override with channels pins them",
			distro: distro.New(distro.Debian, "12", ""),
			src:    rapidfortImageSource(map[string]string{"maintainer": "rapidfort"}),
			overrides: []distro.Identifier{
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
			overrides := tt.overrides
			if overrides == nil {
				overrides = distro.DefaultIdentifiers()
			}
			got := ApplyDistroIdentifiers(tt.distro, tt.src, tt.hasPath, overrides)
			tt.want(t, got)
		})
	}
}
