package distro

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/internal"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/source"
)

func Test_NewDistroFromRelease(t *testing.T) {
	tests := []struct {
		name               string
		release            linux.Release
		expectedVersion    string
		expectedRawVersion string
		expectedType       Type
		expectErr          bool
	}{
		{
			name: "go case: derive version from version-id",
			release: linux.Release{
				ID:        "centos",
				VersionID: "8",
				Version:   "7",
			},
			expectedType:       CentOS,
			expectedRawVersion: "8",
			expectedVersion:    "8.0.0",
		},
		{
			name: "fallback to release name when release id is missing",
			release: linux.Release{
				Name:      "windows",
				VersionID: "8",
			},
			expectedType:       Windows,
			expectedRawVersion: "8",
			expectedVersion:    "8.0.0",
		},
		{
			name: "fallback to version when version-id missing",
			release: linux.Release{
				ID:      "centos",
				Version: "8",
			},
			expectedType:       CentOS,
			expectedRawVersion: "8",
			expectedVersion:    "8.0.0",
		},
		{
			name: "missing version results in error",
			release: linux.Release{
				ID: "centos",
			},
			expectedType: CentOS,
		},
		{
			name: "bogus distro type results in error",
			release: linux.Release{
				ID:        "bogosity",
				VersionID: "8",
			},
			expectErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			d, err := NewFromRelease(test.release)
			if test.expectErr {
				require.Error(t, err)
				return
			} else {
				require.NoError(t, err)
			}

			assert.Equal(t, test.expectedType, d.Type)
			if test.expectedVersion != "" {
				assert.Equal(t, test.expectedVersion, d.Version.String())
			}
			if test.expectedRawVersion != "" {
				assert.Equal(t, test.expectedRawVersion, d.FullVersion())
			}
		})
	}

}

func Test_NewDistroFromRelease_Coverage(t *testing.T) {
	tests := []struct {
		fixture string
		Type    Type
		Version string
	}{
		{
			fixture: "test-fixtures/os/alpine",
			Type:    Alpine,
			Version: "3.11.6",
		},
		{
			fixture: "test-fixtures/os/amazon",
			Type:    AmazonLinux,
			Version: "2.0.0",
		},
		{
			fixture: "test-fixtures/os/busybox",
			Type:    Busybox,
			Version: "1.31.1",
		},
		{
			fixture: "test-fixtures/os/centos",
			Type:    CentOS,
			Version: "8.0.0",
		},
		{
			fixture: "test-fixtures/os/debian",
			Type:    Debian,
			Version: "8.0.0",
		},
		{
			fixture: "test-fixtures/os/fedora",
			Type:    Fedora,
			Version: "31.0.0",
		},
		{
			fixture: "test-fixtures/os/redhat",
			Type:    RedHat,
			Version: "7.3.0",
		},
		{
			fixture: "test-fixtures/os/ubuntu",
			Type:    Ubuntu,
			Version: "20.4.0",
		},
		{
			fixture: "test-fixtures/os/oraclelinux",
			Type:    OracleLinux,
			Version: "8.3.0",
		},
		{
			fixture: "test-fixtures/os/custom",
			Type:    RedHat,
			Version: "8.0.0",
		},
		{
			fixture: "test-fixtures/os/opensuse-leap",
			Type:    OpenSuseLeap,
			Version: "15.2.0",
		},
		{
			fixture: "test-fixtures/os/sles",
			Type:    SLES,
			Version: "15.2.0",
		},
		{
			fixture: "test-fixtures/os/photon",
			Type:    Photon,
			Version: "2.0.0",
		},
		{
			fixture: "test-fixtures/os/arch",
			Type:    ArchLinux,
		},
		{
			fixture: "test-fixtures/partial-fields/missing-id",
			Type:    Debian,
			Version: "8.0.0",
		},
		{
			fixture: "test-fixtures/partial-fields/unknown-id",
			Type:    Debian,
			Version: "8.0.0",
		},
		{
			fixture: "test-fixtures/os/centos6",
			Type:    CentOS,
			Version: "6.0.0",
		},
		{
			fixture: "test-fixtures/os/centos5",
			Type:    CentOS,
			Version: "5.7.0",
		},
		{
			fixture: "test-fixtures/os/mariner",
			Type:    Mariner,
			Version: "1.0.0",
		},
		{
			fixture: "test-fixtures/os/rockylinux",
			Type:    RockyLinux,
			Version: "8.4.0",
		},
		{
			fixture: "test-fixtures/os/almalinux",
			Type:    AlmaLinux,
			Version: "8.4.0",
		},
		{
			fixture: "test-fixtures/os/gentoo",
			Type:    Gentoo,
		},
		{
			fixture: "test-fixtures/os/wolfi",
			Type:    Wolfi,
		},
		{
			fixture: "test-fixtures/os/chainguard",
			Type:    Chainguard,
		},
	}

	observedDistros := internal.NewStringSet()
	definedDistros := internal.NewStringSet()

	for _, distroType := range All {
		definedDistros.Add(string(distroType))
	}

	// Somewhat cheating with Windows. There is no support for detecting/parsing a Windows OS, so it is not
	// possible to comply with this test unless it is added manually to the "observed distros"
	definedDistros.Remove(string(Windows))

	for _, test := range tests {
		t.Run(test.fixture, func(t *testing.T) {
			s, err := source.NewFromDirectory(test.fixture)
			require.NoError(t, err)

			resolver, err := s.FileResolver(source.SquashedScope)
			require.NoError(t, err)

			// make certain syft and pick up on the raw information we need
			release := linux.IdentifyRelease(resolver)
			require.NotNil(t, release, "empty linux release info")

			// craft a new distro from the syft raw info
			d, err := NewFromRelease(*release)
			require.NoError(t, err)

			observedDistros.Add(d.Type.String())

			assert.Equal(t, test.Type, d.Type)
			if test.Version != "" {
				assert.Equal(t, d.Version.String(), test.Version)
			}
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
			})
			require.NoError(t, err)
			assert.Equal(t, test.expected, d.FullVersion())
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
			})
			require.NoError(t, err)
			assert.Equal(t, test.expected, d.MajorVersion())

		})
	}

}
