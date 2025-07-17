package platformcpe

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/pkg/qualifier"
)

func TestPlatformCPE_Satisfied(t *testing.T) {
	tests := []struct {
		name        string
		platformCPE qualifier.Qualifier
		pkg         pkg.Package
		satisfied   bool
		hasError    bool
	}{
		{
			name:        "no filter on nil distro",
			platformCPE: New("cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*"),
			pkg:         pkg.Package{},
			satisfied:   true,
			hasError:    false,
		},
		{
			name:        "no filter when platform CPE is empty",
			platformCPE: New(""),
			pkg: pkg.Package{
				Distro: &distro.Distro{Type: distro.Windows},
			},
			satisfied: true,
			hasError:  false,
		},
		{
			name:        "no filter when platform CPE is invalid",
			platformCPE: New(";;;"),
			pkg: pkg.Package{
				Distro: &distro.Distro{Type: distro.Windows},
			},
			satisfied: true,
			hasError:  true,
		},
		// Windows
		{
			name:        "filter windows platform vuln when distro is not windows",
			platformCPE: New("cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*"),
			pkg: pkg.Package{
				Distro: &distro.Distro{Type: distro.Debian},
			},
			satisfied: false,
			hasError:  false,
		},
		{
			name:        "filter windows server platform vuln when distro is not windows",
			platformCPE: New("cpe:2.3:o:microsoft:windows_server_2022:-:*:*:*:*:*:*:*"),
			pkg: pkg.Package{
				Distro: &distro.Distro{Type: distro.Debian},
			},
			satisfied: false,
			hasError:  false,
		},
		{
			name:        "no filter windows platform vuln when distro is windows",
			platformCPE: New("cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*"),
			pkg: pkg.Package{
				Distro: &distro.Distro{Type: distro.Windows},
			},
			satisfied: true,
			hasError:  false,
		},
		{
			name:        "no filter windows server platform vuln when distro is windows",
			platformCPE: New("cpe:2.3:o:microsoft:windows_server_2022:-:*:*:*:*:*:*:*"),
			pkg: pkg.Package{
				Distro: &distro.Distro{Type: distro.Windows},
			},
			satisfied: true,
			hasError:  false,
		},
		// Debian
		{
			name:        "filter debian platform vuln when distro is not debian",
			platformCPE: New("cpe:2.3:o:debian:debian_linux:-:*:*:*:*:*:*:*"),
			pkg: pkg.Package{
				Distro: &distro.Distro{Type: distro.Ubuntu},
			},
			satisfied: false,
			hasError:  false,
		},
		{
			name:        "filter debian platform vuln when distro is not debian (alternate encountered cpe)",
			platformCPE: New("cpe:2.3:o:debian:linux:-:*:*:*:*:*:*:*"),
			pkg: pkg.Package{
				Distro: &distro.Distro{Type: distro.SLES},
			},
			satisfied: false,
			hasError:  false,
		},
		{
			name:        "no filter debian platform vuln when distro is debian",
			platformCPE: New("cpe:2.3:o:debian:debian_linux:-:*:*:*:*:*:*:*"),
			pkg: pkg.Package{
				Distro: &distro.Distro{Type: distro.Debian},
			},
			satisfied: true,
			hasError:  false,
		},
		{
			name:        "no filter debian platform vuln when distro is debian (alternate encountered cpe)",
			platformCPE: New("cpe:2.3:o:debian:linux:-:*:*:*:*:*:*:*"),
			pkg: pkg.Package{
				Distro: &distro.Distro{Type: distro.Debian},
			},
			satisfied: true,
			hasError:  false,
		},
		// Ubuntu
		{
			name:        "filter ubuntu platform vuln when distro is not ubuntu",
			platformCPE: New("cpe:2.3:o:canonical:ubuntu_linux:-:*:*:*:*:*:*:*"),
			pkg: pkg.Package{
				Distro: &distro.Distro{Type: distro.SLES},
			},
			satisfied: false,
			hasError:  false,
		},
		{
			name:        "filter ubuntu platform vuln when distro is not ubuntu (alternate encountered cpe)",
			platformCPE: New("cpe:2.3:o:ubuntu:vivid:-:*:*:*:*:*:*:*"),
			pkg: pkg.Package{
				Distro: &distro.Distro{Type: distro.Alpine},
			},
			satisfied: false,
			hasError:  false,
		},
		{
			name:        "no filter ubuntu platform vuln when distro is ubuntu",
			platformCPE: New("cpe:2.3:o:canonical:ubuntu_linux:-:*:*:*:*:*:*:*"),
			pkg: pkg.Package{
				Distro: &distro.Distro{Type: distro.Ubuntu},
			},
			satisfied: true,
			hasError:  false,
		},
		{
			name:        "no filter ubuntu platform vuln when distro is ubuntu (alternate encountered cpe)",
			platformCPE: New("cpe:2.3:o:ubuntu:vivid:-:*:*:*:*:*:*:*"),
			pkg: pkg.Package{
				Distro: &distro.Distro{Type: distro.Ubuntu},
			},
			satisfied: true,
			hasError:  false,
		},
		// Wordpress
		{
			name:        "always filter wordpress platform vulns (no known distro)",
			platformCPE: New("cpe:2.3:o:wordpress:wordpress:-:*:*:*:*:*:*:*"),
			pkg:         pkg.Package{},
			satisfied:   false,
			hasError:    false,
		},
		{
			name:        "always filter wordpress platform vulns (known distro)",
			platformCPE: New("cpe:2.3:o:ubuntu:vivid:-:*:*:*:*:*:*:*"),
			pkg: pkg.Package{
				Distro: &distro.Distro{Type: distro.Alpine},
			},
			satisfied: false,
			hasError:  false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s, err := test.platformCPE.Satisfied(test.pkg)

			if test.hasError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			assert.Equal(t, test.satisfied, s)
		})
	}
}
