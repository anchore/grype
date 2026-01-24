package distro

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/internal/stringutil"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/source"
	"github.com/anchore/syft/syft/source/directorysource"
)

func testFixChannels() []FixChannel {
	return DefaultFixChannels()
}

func Test_NewDistroFromRelease(t *testing.T) {
	tests := []struct {
		name      string
		release   linux.Release
		channels  []FixChannel
		expected  *Distro
		minor     string
		major     string
		expectErr require.ErrorAssertionFunc
	}{
		{
			name: "go case: derive version from version-id",
			release: linux.Release{
				ID:        "centos",
				VersionID: "8",
				Version:   "7",
				IDLike:    []string{"rhel"},
			},
			channels: testFixChannels(),
			expected: &Distro{
				Type:    CentOS,
				Version: "8",
				IDLike:  []string{"redhat"},
			},
			major: "8",
			minor: "",
		},
		{
			name: "fallback to release name when release id is missing",
			release: linux.Release{
				Name:      "windows",
				VersionID: "8",
			},
			channels: testFixChannels(),
			expected: &Distro{
				Type:    Windows,
				Version: "8",
			},
			major: "8",
			minor: "",
		},
		{
			name: "fallback to version when version-id missing",
			release: linux.Release{
				ID:      "centos",
				Version: "8",
			},
			channels: testFixChannels(),
			expected: &Distro{
				Type:    CentOS,
				Version: "8",
			},
			major: "8",
			minor: "",
		},
		{
			// this enables matching on multiple OS versions at once
			name: "missing version or label version is allowed",
			release: linux.Release{
				ID: "centos",
			},
			channels: testFixChannels(),
			expected: &Distro{
				Type: CentOS,
			},
		},
		{
			name: "bogus distro type results in error",
			release: linux.Release{
				ID:        "bogosity",
				VersionID: "8",
			},
			channels:  testFixChannels(),
			expectErr: require.Error,
		},
		{
			// syft -o json debian:testing | jq .distro
			name: "unstable debian",
			release: linux.Release{
				ID:              "debian",
				VersionID:       "",
				Version:         "",
				PrettyName:      "Debian GNU/Linux trixie/sid",
				VersionCodename: "trixie",
				Name:            "Debian GNU/Linux",
			},
			channels: testFixChannels(),
			expected: &Distro{
				Type:     Debian,
				Codename: "trixie",
			},
			major: "",
			minor: "",
		},
		{
			name: "azure linux 3",
			release: linux.Release{
				ID:        "azurelinux",
				Version:   "3.0.20240417",
				VersionID: "3.0",
			},
			channels: testFixChannels(),
			expected: &Distro{
				Type:    Azure,
				Version: "3.0",
			},
			major: "3",
			minor: "0",
		},
		{
			name: "eus hint ignored when configured to never apply",
			release: linux.Release{
				ID:              "rhel",
				Version:         "9.4",
				ExtendedSupport: true,
			},
			channels: testFixChannels(),
			expected: &Distro{
				Type:     RedHat,
				Version:  "9.4",
				Channels: names("eus"),
			},
			major: "9",
			minor: "4",
		},
		{
			name: "eus hinted at as attribute",
			release: linux.Release{
				ID:              "rhel",
				Version:         "9.4",
				ExtendedSupport: true,
			},
			channels: []FixChannel{
				{
					Name:  "eus",
					IDs:   []string{"rhel"},
					Apply: ChannelConditionallyEnabled,
				},
			},
			expected: &Distro{
				Type:     RedHat,
				Version:  "9.4",
				Channels: names("eus"),
			},
			major: "9",
			minor: "4",
		},
		{
			name: "eus embedded in the version",
			release: linux.Release{
				ID:      "rhel",
				Version: "9.4+eus",
			},
			channels: []FixChannel{
				{
					Name:  "eus",
					IDs:   []string{"rhel"},
					Apply: ChannelConditionallyEnabled,
				},
			},
			expected: &Distro{
				Type:     RedHat,
				Version:  "9.4",
				Channels: names("eus"),
			},
			major: "9",
			minor: "4",
		},
		{
			name: "eus hinted at as attribute (always apply)",
			release: linux.Release{
				ID:              "rhel",
				Version:         "9.4",
				ExtendedSupport: true,
			},
			channels: []FixChannel{
				{
					Name:  "eus",
					IDs:   []string{"rhel"},
					Apply: ChannelAlwaysEnabled, // important!
				},
			},
			expected: &Distro{
				Type:     RedHat,
				Version:  "9.4",
				Channels: names("eus"),
			},
			major: "9",
			minor: "4",
		},
		{
			name: "eus embedded in the version (always apply)",
			release: linux.Release{
				ID:      "rhel",
				Version: "9.4+eus",
			},
			channels: []FixChannel{
				{
					Name:  "eus",
					IDs:   []string{"rhel"},
					Apply: ChannelAlwaysEnabled, // important!
				},
			},
			expected: &Distro{
				Type:     RedHat,
				Version:  "9.4",
				Channels: names("eus"),
			},
			major: "9",
			minor: "4",
		},
		{
			name: "eus hinted at as attribute (never apply)",
			release: linux.Release{
				ID:              "rhel",
				Version:         "9.4",
				ExtendedSupport: true,
			},
			channels: []FixChannel{
				{
					Name:  "eus",
					IDs:   []string{"rhel"},
					Apply: ChannelNeverEnabled, // important!
				},
			},
			expected: &Distro{
				Type:    RedHat,
				Version: "9.4",
			},
			major: "9",
			minor: "4",
		},
		{
			name: "eus embedded in the version (never apply)",
			release: linux.Release{
				ID:      "rhel",
				Version: "9.4+eus",
			},
			channels: []FixChannel{
				{
					Name:  "eus",
					IDs:   []string{"rhel"},
					Apply: ChannelNeverEnabled, // important!
				},
			},
			expected: &Distro{
				Type:    RedHat,
				Version: "9.4",
			},
			major: "9",
			minor: "4",
		},
		{
			name: "v versionID prefix postmarketos",
			release: linux.Release{
				ID:        "postmarketos",
				VersionID: "v24.06",
			},
			expected: &Distro{
				Type:    PostmarketOS,
				Version: "v24.06",
			},
			major: "24",
			minor: "06",
		},
		{
			name: "edge as versionID prefix postmarketos",
			release: linux.Release{
				ID:        "postmarketos",
				VersionID: "edge",
			},
			expected: &Distro{
				Type:    PostmarketOS,
				Version: "edge",
			},
			major: "",
			minor: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.expectErr == nil {
				tt.expectErr = require.NoError
			}

			distro, err := NewFromRelease(tt.release, tt.channels)
			tt.expectErr(t, err)
			if err != nil {
				return
			}

			if d := cmp.Diff(tt.expected, distro, cmpopts.IgnoreUnexported(Distro{})); d != "" {
				t.Errorf("unexpected result: %s", d)
			}
			assert.Equal(t, tt.major, distro.MajorVersion(), "unexpected major version")
			assert.Equal(t, tt.minor, distro.MinorVersion(), "unexpected minor version")
		})
	}

}

func Test_NewDistroFromRelease_Coverage(t *testing.T) {
	observedDistros := stringutil.NewStringSet()
	definedDistros := stringutil.NewStringSet()

	for _, distroType := range All {
		definedDistros.Add(string(distroType))
	}

	// Somewhat cheating with Windows. There is no support for detecting/parsing a Windows OS, so it is not
	// possible to comply with this test unless it is added manually to the "observed distros"
	definedDistros.Remove(string(Windows))

	tests := []struct {
		Name         string
		Type         Type
		Version      string
		LabelVersion string
	}{
		{
			Name:    "test-fixtures/os/alpine",
			Type:    Alpine,
			Version: "3.11.6",
		},
		{
			Name:    "test-fixtures/os/alpine-edge",
			Type:    Alpine,
			Version: "3.22.0_alpha20250108",
		},
		{
			Name:    "test-fixtures/os/amazon",
			Type:    AmazonLinux,
			Version: "2",
		},
		{
			Name:    "test-fixtures/os/busybox",
			Type:    Busybox,
			Version: "1.31.1",
		},
		{
			Name:    "test-fixtures/os/centos",
			Type:    CentOS,
			Version: "8",
		},
		{
			Name:    "test-fixtures/os/debian",
			Type:    Debian,
			Version: "8",
		},
		{
			Name:         "test-fixtures/os/debian-sid",
			Type:         Debian,
			LabelVersion: "trixie",
		},
		{
			Name:    "test-fixtures/os/fedora",
			Type:    Fedora,
			Version: "31",
		},
		{
			Name:    "test-fixtures/os/redhat",
			Type:    RedHat,
			Version: "7.3",
		},
		{
			Name:         "test-fixtures/os/ubuntu",
			Type:         Ubuntu,
			Version:      "20.04",
			LabelVersion: "focal",
		},
		{
			Name:    "test-fixtures/os/oraclelinux",
			Type:    OracleLinux,
			Version: "8.3",
		},
		{
			Name:    "test-fixtures/os/custom",
			Type:    Scientific,
			Version: "8",
		},
		{
			Name:    "test-fixtures/os/opensuse-leap",
			Type:    OpenSuseLeap,
			Version: "15.2",
		},
		{
			Name:    "test-fixtures/os/sles",
			Type:    SLES,
			Version: "15.2",
		},
		{
			Name:    "test-fixtures/os/photon",
			Type:    Photon,
			Version: "2.0",
		},
		{
			Name: "test-fixtures/os/arch",
			Type: ArchLinux,
		},
		{
			Name:    "test-fixtures/partial-fields/missing-id",
			Type:    Debian,
			Version: "8",
		},
		{
			Name:    "test-fixtures/partial-fields/unknown-id",
			Type:    Debian,
			Version: "8",
		},
		{
			Name:    "test-fixtures/os/centos6",
			Type:    CentOS,
			Version: "6",
		},
		{
			Name:    "test-fixtures/os/centos5",
			Type:    CentOS,
			Version: "5.7",
		},
		{
			Name:    "test-fixtures/os/mariner",
			Type:    Mariner,
			Version: "1.0",
		},
		{
			Name:    "test-fixtures/os/azurelinux",
			Type:    Azure,
			Version: "3.0",
		},
		{
			Name:    "test-fixtures/os/rockylinux",
			Type:    RockyLinux,
			Version: "8.4",
		},
		{
			Name:    "test-fixtures/os/almalinux",
			Type:    AlmaLinux,
			Version: "8.4",
		},
		{
			Name:    "test-fixtures/os/echo",
			Type:    Echo,
			Version: "1",
		},
		{
			Name: "test-fixtures/os/gentoo",
			Type: Gentoo,
		},
		{
			Name:    "test-fixtures/os/wolfi",
			Type:    Wolfi,
			Version: "20220914",
		},
		{
			Name:    "test-fixtures/os/chainguard",
			Type:    Chainguard,
			Version: "20230214",
		},
		{
			Name:    "test-fixtures/os/minimos",
			Type:    MinimOS,
			Version: "20241031",
		},
		{
			Name:    "test-fixtures/os/raspbian",
			Type:    Raspbian,
			Version: "9",
		},
		{
			Name:    "test-fixtures/os/scientific",
			Type:    Scientific,
			Version: "7.5",
		},
		{
			Name:    "test-fixtures/os/scientific6",
			Type:    Scientific,
			Version: "6.10",
		},
		{
			Name:    "test-fixtures/os/secureos",
			Type:    SecureOS,
			Version: "2025.09.09",
		},
		{
			Name:    "test-fixtures/os/postmarketos",
			Type:    PostmarketOS,
			Version: "v25.06",
		},
		{
			Name:    "test-fixtures/os/postmarketos-edge",
			Type:    PostmarketOS,
			Version: "edge",
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			s, err := directorysource.NewFromPath(tt.Name)
			require.NoError(t, err)

			resolver, err := s.FileResolver(source.SquashedScope)
			require.NoError(t, err)

			// make certain syft and pick up on the raw information we need
			release := linux.IdentifyRelease(resolver)
			require.NotNil(t, release, "empty linux release info")

			// craft a new distro from the syft raw info
			d, err := NewFromRelease(*release, testFixChannels())
			require.NoError(t, err)

			observedDistros.Add(d.Type.String())

			assert.Equal(t, tt.Type, d.Type, "unexpected distro type")
			assert.Equal(t, tt.LabelVersion, d.Codename, "unexpected label version")
			assert.Equal(t, tt.Version, d.Version, "unexpected version")
		})
	}

	// ensure that test cases stay in sync with the distros that can be identified
	if len(observedDistros) < len(definedDistros) {
		for _, d := range definedDistros.ToSlice() {
			t.Logf("   defined: %s", d)
		}
		for _, d := range observedDistros.ToSlice() {
			t.Logf("   observed: %s", d)
		}
		t.Errorf("distro coverage incomplete (defined=%d, coverage=%d)", len(definedDistros), len(observedDistros))
	}
}

func TestDistro_FullVersion(t *testing.T) {

	tests := []struct {
		version  string
		expected string
	}{
		{
			version:  "8",
			expected: "8",
		},
		{
			version:  "18.04",
			expected: "18.04",
		},
		{
			version:  "0",
			expected: "0",
		},
		{
			version:  "18.1.2",
			expected: "18.1.2",
		},
	}

	for _, test := range tests {
		t.Run(test.version, func(t *testing.T) {
			d, err := NewFromRelease(linux.Release{
				ID:      "centos",
				Version: test.version,
			}, testFixChannels())
			require.NoError(t, err)
			assert.Equal(t, test.expected, d.Version)
		})
	}

}

func TestDistro_MajorVersion(t *testing.T) {

	tests := []struct {
		version  string
		expected string
	}{
		{
			version:  "8",
			expected: "8",
		},
		{
			version:  "18.04",
			expected: "18",
		},
		{
			version:  "0",
			expected: "0",
		},
		{
			version:  "18.1.2",
			expected: "18",
		},
	}

	for _, test := range tests {
		t.Run(test.version, func(t *testing.T) {
			d, err := NewFromRelease(linux.Release{
				ID:      "centos",
				Version: test.version,
			}, testFixChannels())
			require.NoError(t, err)
			assert.Equal(t, test.expected, d.MajorVersion())

		})
	}

}

func names(ns ...string) []string {
	return ns
}

func TestParseDistroString(t *testing.T) {
	tests := []struct {
		name            string
		input           string
		expectedName    string
		expectedVersion string
	}{
		{
			name:            "hyphen separator",
			input:           "debian-11",
			expectedName:    "debian",
			expectedVersion: "11",
		},
		{
			name:            "colon separator",
			input:           "debian:11",
			expectedName:    "debian",
			expectedVersion: "11",
		},
		{
			name:            "at separator",
			input:           "debian@11",
			expectedName:    "debian",
			expectedVersion: "11",
		},
		{
			name:            "no separator",
			input:           "debian",
			expectedName:    "debian",
			expectedVersion: "",
		},
		{
			name:            "with major.minor version",
			input:           "ubuntu-20.04",
			expectedName:    "ubuntu",
			expectedVersion: "20.04",
		},
		{
			name:            "with codename",
			input:           "ubuntu@focal",
			expectedName:    "ubuntu",
			expectedVersion: "focal",
		},
		{
			name:            "with channels",
			input:           "rhel:9.4+eus",
			expectedName:    "rhel",
			expectedVersion: "9.4+eus",
		},
		{
			name:            "opensuse-leap with hyphen separator",
			input:           "opensuse-leap-15.2",
			expectedName:    "opensuse-leap",
			expectedVersion: "15.2",
		},
		{
			name:            "opensuse-leap with colon separator",
			input:           "opensuse-leap:15.2",
			expectedName:    "opensuse-leap",
			expectedVersion: "15.2",
		},
		{
			name:            "opensuse-leap with at separator",
			input:           "opensuse-leap@15.2",
			expectedName:    "opensuse-leap",
			expectedVersion: "15.2",
		},
		{
			name:            "opensuse-leap without version",
			input:           "opensuse-leap",
			expectedName:    "opensuse-leap",
			expectedVersion: "",
		},
		{
			name:            "opensuse-leap with mixed case",
			input:           "OpenSUSE-Leap-15.2",
			expectedName:    "opensuse-leap",
			expectedVersion: "15.2",
		},
		{
			name:            "empty string",
			input:           "",
			expectedName:    "",
			expectedVersion: "",
		},
		{
			name:            "with whitespace",
			input:           "  debian : 11  ",
			expectedName:    "debian",
			expectedVersion: "11",
		},
		{
			name:            "multiple separators uses first",
			input:           "debian-11:test",
			expectedName:    "debian",
			expectedVersion: "11:test",
		},
		{
			name:            "rhel with hyphen",
			input:           "rhel-8",
			expectedName:    "rhel",
			expectedVersion: "8",
		},
		{
			name:            "centos with colon",
			input:           "centos:7",
			expectedName:    "centos",
			expectedVersion: "7",
		},
		{
			name:            "alpine with at",
			input:           "alpine@3.11",
			expectedName:    "alpine",
			expectedVersion: "3.11",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name, version := ParseDistroString(tt.input)
			assert.Equal(t, tt.expectedName, name, "unexpected name")
			assert.Equal(t, tt.expectedVersion, version, "unexpected version")
		})
	}
}
