package pkg

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/assert"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/stereoscope/pkg/imagetest"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/file"
)

func TestProviderLocationExcludes(t *testing.T) {
	tests := []struct {
		name     string
		fixture  string
		excludes []string
		expected []string
		wantErr  assert.ErrorAssertionFunc
	}{
		{
			name:     "exclude everything",
			fixture:  "test-fixtures/syft-spring.json",
			excludes: []string{"**"},
			expected: []string{},
		},
		{
			name:     "exclude specific real path match",
			fixture:  "test-fixtures/syft-spring.json",
			excludes: []string{"**/tomcat*.jar"},
			expected: []string{"charsets"},
		},
		{
			name:     "include everything with no match",
			fixture:  "test-fixtures/syft-spring.json",
			excludes: []string{"**/asdf*.jar"},
			expected: []string{"charsets", "tomcat-embed-el"},
		},
		{
			name:     "include everything with no excludes",
			fixture:  "test-fixtures/syft-spring.json",
			excludes: []string{},
			expected: []string{"charsets", "tomcat-embed-el"},
		},
		{
			name:     "exclusions must not hide parsing error",
			fixture:  "test-fixtures/bad-sbom.json",
			excludes: []string{"**/some-glob/*"},
			wantErr:  assert.Error,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := ProviderConfig{
				SyftProviderConfig: SyftProviderConfig{
					Exclusions:  test.excludes,
					SBOMOptions: syft.DefaultCreateSBOMConfig(),
				},
			}
			if test.wantErr == nil {
				test.wantErr = assert.NoError
			}
			pkgs, _, _, err := Provide(test.fixture, cfg)
			test.wantErr(t, err)
			if err != nil {
				return
			}

			var pkgNames []string

			for _, pkg := range pkgs {
				pkgNames = append(pkgNames, pkg.Name)
			}

			assert.ElementsMatch(t, pkgNames, test.expected)
		})
	}
}

func TestSyftLocationExcludes(t *testing.T) {
	tests := []struct {
		name     string
		fixture  string
		excludes []string
		expected []string
	}{
		{
			name:     "exclude everything",
			fixture:  "image-simple",
			excludes: []string{"**"},
			expected: []string{},
		},
		{
			name:     "exclude specific real path match",
			fixture:  "image-simple",
			excludes: []string{"**/nested/package.json"},
			expected: []string{"top-level-package"},
		},
		{
			name:     "include everything with no match",
			fixture:  "image-simple",
			excludes: []string{"**/asdf*.json"},
			expected: []string{"nested-package", "top-level-package"},
		},
		{
			name:     "include everything with no excludes",
			fixture:  "image-simple",
			excludes: []string{},
			expected: []string{"nested-package", "top-level-package"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			userInput := imagetest.GetFixtureImageTarPath(t, test.fixture)
			cfg := ProviderConfig{
				SyftProviderConfig: SyftProviderConfig{
					Exclusions:  test.excludes,
					SBOMOptions: syft.DefaultCreateSBOMConfig(),
				},
			}
			pkgs, _, _, err := Provide(userInput, cfg)

			assert.NoErrorf(t, err, "error calling Provide function")

			var pkgNames []string

			for _, pkg := range pkgs {
				pkgNames = append(pkgNames, pkg.Name)
			}

			assert.ElementsMatch(t, pkgNames, test.expected)
		})
	}
}

func Test_filterPackageExclusions(t *testing.T) {
	tests := []struct {
		name       string
		locations  [][]string
		exclusions []string
		expected   int
	}{
		{
			name:       "exclude nothing",
			locations:  [][]string{{"/foo", "/bar"}, {"/foo", "/bar"}},
			exclusions: []string{"/asdf/**"},
			expected:   2,
		},
		{
			name:       "exclude everything",
			locations:  [][]string{{"/foo", "/bar"}, {"/foo", "/bar"}},
			exclusions: []string{"**"},
			expected:   0,
		},
		{
			name:       "exclude based on all location match",
			locations:  [][]string{{"/foo1", "/bar1"}, {"/foo2", "/bar2"}},
			exclusions: []string{"/foo2", "/bar2"},
			expected:   1,
		},
		{
			name:       "don't exclude with single location match",
			locations:  [][]string{{"/foo1", "/bar1"}, {"/foo2", "/bar2"}},
			exclusions: []string{"/foo1", "/foo2"},
			expected:   2,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var packages []Package
			for _, pkg := range test.locations {
				locations := file.NewLocationSet()
				for _, l := range pkg {
					locations.Add(
						file.NewVirtualLocation(l, l),
					)
				}
				packages = append(packages, Package{Locations: locations})
			}
			filtered, err := filterPackageExclusions(packages, test.exclusions)

			assert.NoError(t, err)
			assert.Len(t, filtered, test.expected)
		})
	}
}

func Test_matchesLocation(t *testing.T) {
	tests := []struct {
		name        string
		realPath    string
		virtualPath string
		match       string
		expected    bool
	}{
		{
			name:        "doesn't match real",
			realPath:    "/asdf",
			virtualPath: "",
			match:       "/usr",
			expected:    false,
		},
		{
			name:        "doesn't match virtual",
			realPath:    "",
			virtualPath: "/asdf",
			match:       "/usr",
			expected:    false,
		},
		{
			name:        "does match real",
			realPath:    "/usr/foo",
			virtualPath: "",
			match:       "/usr/**",
			expected:    true,
		},
		{
			name:        "does match virtual",
			realPath:    "",
			virtualPath: "/usr/bar/oof.txt",
			match:       "/usr/**",
			expected:    true,
		},
		{
			name:        "does match file",
			realPath:    "",
			virtualPath: "/usr/bar/oof.txt",
			match:       "**/*.txt",
			expected:    true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matches, err := locationMatches(file.NewVirtualLocation(test.realPath, test.virtualPath), test.match)
			assert.NoError(t, err)
			assert.Equal(t, test.expected, matches)
		})
	}
}

func Test_getDistroChannelApplier(t *testing.T) {

	defaultOSGen := func() *distro.Distro {
		return distro.NewFromNameVersion("rhel", "8.4")
	}

	tests := []struct {
		name     string
		channels []distro.FixChannel
		distro   func() *distro.Distro
		want     []string
	}{
		{
			name:     "nil distro",
			channels: distro.DefaultFixChannels(),
			distro:   func() *distro.Distro { return nil },
			want:     nil,
		},
		{
			name:     "no matching channel",
			channels: distro.DefaultFixChannels(),
			distro: func() *distro.Distro {
				return distro.NewFromNameVersion("ubuntu", "20.04")
			},
			want: nil,
		},
		{
			name: "channel never enabled",
			channels: []distro.FixChannel{
				{
					Name:  "test-channel",
					IDs:   []string{"rhel"},
					Apply: distro.ChannelNeverEnabled,
				},
			},
			distro: defaultOSGen,
			want:   nil,
		},
		{
			name: "channel always enabled",
			channels: []distro.FixChannel{
				{
					Name:  "eus",
					IDs:   []string{"rhel"},
					Apply: distro.ChannelAlwaysEnabled,
				},
			},
			distro: defaultOSGen,
			want:   []string{"eus"},
		},
		{
			name: "case insensitive matching",
			channels: []distro.FixChannel{
				{
					Name:  "eus",
					IDs:   []string{"RHEL"},
					Apply: distro.ChannelAlwaysEnabled,
				},
			},
			distro: defaultOSGen,
			want:   []string{"eus"},
		},
		{
			name: "multiple IDs in channel",
			channels: []distro.FixChannel{
				{
					Name:  "test-channel",
					IDs:   []string{"centos", "rhel", "fedora"},
					Apply: distro.ChannelAlwaysEnabled,
				},
			},
			distro: defaultOSGen,
			want:   []string{"test-channel"},
		},
		{
			name: "empty channel name skipped",
			channels: []distro.FixChannel{
				{
					Name:  "",
					IDs:   []string{"rhel"},
					Apply: distro.ChannelAlwaysEnabled,
				},
			},
			distro: defaultOSGen,
			want:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			applier := getDistroChannelApplier(tt.channels)
			d := tt.distro()

			applier(d)

			if d != nil {
				assert.Equal(t, tt.want, d.Channels)
			}
		})
	}
}

func Test_applyChannelsToDistro(t *testing.T) {
	tests := []struct {
		name             string
		distro           func() *distro.Distro
		channels         distro.FixChannels
		expectedResult   []string
		expectedModified bool
	}{
		{
			name:   "always enabled channel adds new channel",
			distro: func() *distro.Distro { return distro.NewFromNameVersion("rhel", "8.4") },
			channels: distro.FixChannels{
				{
					Name:  "eus",
					Apply: distro.ChannelAlwaysEnabled,
				},
			},
			expectedResult:   []string{"eus"},
			expectedModified: true,
		},
		{
			name: "always enabled channel keeps existing channel",
			distro: func() *distro.Distro {
				d := distro.NewFromNameVersion("rhel", "8.4")
				d.Channels = []string{"eus"}
				return d
			},
			channels: distro.FixChannels{
				{
					Name:  "eus",
					Apply: distro.ChannelAlwaysEnabled,
				},
			},
			expectedResult:   []string{"eus"},
			expectedModified: false,
		},
		{
			name: "conditionally enabled channel keeps existing channel",
			distro: func() *distro.Distro {
				d := distro.NewFromNameVersion("rhel", "8.4")
				d.Channels = []string{"eus"}
				return d
			},
			channels: distro.FixChannels{
				{
					Name:  "eus",
					Apply: distro.ChannelConditionallyEnabled,
				},
			},
			expectedResult:   []string{"eus"},
			expectedModified: false,
		},
		{
			name:   "conditionally enabled channel does not add missing channel",
			distro: func() *distro.Distro { return distro.NewFromNameVersion("rhel", "8.4") },
			channels: distro.FixChannels{
				{
					Name:  "eus",
					Apply: distro.ChannelConditionallyEnabled,
				},
			},
			expectedResult:   []string{},
			expectedModified: false,
		},
		{
			name: "never enabled channel removes existing channel",
			distro: func() *distro.Distro {
				d := distro.NewFromNameVersion("rhel", "8.4")
				d.Channels = []string{"eus"}
				return d
			},
			channels: distro.FixChannels{
				{
					Name:  "eus",
					Apply: distro.ChannelNeverEnabled,
				},
			},
			expectedResult:   []string{},
			expectedModified: true,
		},
		{
			name:   "never enabled channel with no existing channel",
			distro: func() *distro.Distro { return distro.NewFromNameVersion("rhel", "8.4") },
			channels: distro.FixChannels{
				{
					Name:  "eus",
					Apply: distro.ChannelNeverEnabled,
				},
			},
			expectedResult:   []string{},
			expectedModified: false,
		},
		{
			name:   "empty channel name is skipped",
			distro: func() *distro.Distro { return distro.NewFromNameVersion("rhel", "8.4") },
			channels: distro.FixChannels{
				{
					Name:  "",
					Apply: distro.ChannelAlwaysEnabled,
				},
				{
					Name:  "eus",
					Apply: distro.ChannelAlwaysEnabled,
				},
			},
			expectedResult:   []string{"eus"},
			expectedModified: true,
		},
		{
			name:   "version constraint allows channel",
			distro: func() *distro.Distro { return distro.NewFromNameVersion("rhel", "8.4") },
			channels: distro.FixChannels{
				{
					Name:     "eus",
					Apply:    distro.ChannelAlwaysEnabled,
					Versions: version.MustGetConstraint(">= 8.0", version.SemanticFormat),
				},
			},
			expectedResult:   []string{"eus"},
			expectedModified: true,
		},
		{
			name:   "version constraint blocks channel",
			distro: func() *distro.Distro { return distro.NewFromNameVersion("rhel", "7.9") },
			channels: distro.FixChannels{
				{
					Name:     "eus",
					Apply:    distro.ChannelAlwaysEnabled,
					Versions: version.MustGetConstraint(">= 8.0", version.SemanticFormat),
				},
			},
			expectedResult:   []string{},
			expectedModified: false,
		},
		{
			name: "multiple channels with different behaviors",
			distro: func() *distro.Distro {
				d := distro.NewFromNameVersion("rhel", "8.4")
				d.Channels = []string{"eus", "optional"}
				return d
			},
			channels: distro.FixChannels{
				{
					Name:  "eus",
					Apply: distro.ChannelConditionallyEnabled,
				},
				{
					Name:  "main",
					Apply: distro.ChannelAlwaysEnabled,
				},
				{
					Name:  "optional",
					Apply: distro.ChannelNeverEnabled,
				},
			},
			expectedResult:   []string{"eus", "main"},
			expectedModified: true,
		},
		{
			name:   "invalid version string defaults to allowing channel",
			distro: func() *distro.Distro { return distro.NewFromNameVersion("rhel", "invalid-version") },
			channels: distro.FixChannels{
				{
					Name:     "eus",
					Apply:    distro.ChannelAlwaysEnabled,
					Versions: version.MustGetConstraint(">= 8.0", version.SemanticFormat),
				},
			},
			expectedResult:   []string{"eus"},
			expectedModified: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := tt.distro()

			modified := applyChannelsToDistro(d, tt.channels)

			if d := cmp.Diff(tt.expectedResult, d.Channels, cmpopts.EquateEmpty()); d != "" {
				t.Errorf("applyChannelsToDistro() mismatch (-want +got):\n%s", d)
			}
			assert.Equal(t, tt.expectedModified, modified)
		})
	}
}
