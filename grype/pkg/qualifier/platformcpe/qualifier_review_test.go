package platformcpe

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/pkg"
)

// R43 (review of #3751): the ubuntu and debian platform CPE checks compare the package's distro type
// exactly, so once the identifier remaps the context distro to rapidfort-ubuntu or rapidfort-debian,
// every NVD record qualified as running on ubuntu_linux or debian_linux is dropped for every package
// on the image, language packages included.
func TestReview_R43_PlatformCPEOnRapidFortDistros(t *testing.T) {
	tests := []struct {
		name        string
		platformCPE string
		d           distro.Type
	}{
		{name: "control: ubuntu_linux on ubuntu", platformCPE: "cpe:2.3:o:canonical:ubuntu_linux:-:*:*:*:*:*:*:*", d: distro.Ubuntu},
		{name: "control: debian_linux on debian", platformCPE: "cpe:2.3:o:debian:debian_linux:-:*:*:*:*:*:*:*", d: distro.Debian},
		{name: "ubuntu_linux on rapidfort-ubuntu", platformCPE: "cpe:2.3:o:canonical:ubuntu_linux:-:*:*:*:*:*:*:*", d: distro.RapidFortUbuntu},
		{name: "debian_linux on rapidfort-debian", platformCPE: "cpe:2.3:o:debian:debian_linux:-:*:*:*:*:*:*:*", d: distro.RapidFortDebian},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := New(tt.platformCPE).Satisfied(pkg.Package{Distro: &distro.Distro{Type: tt.d}})
			require.NoError(t, err)
			assert.True(t, s, "the record should apply to a %s package", tt.d)
		})
	}
}
