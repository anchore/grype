package platformcpe

import (
	"strings"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/pkg/qualifier"
	"github.com/anchore/syft/syft/cpe"
)

type platformCPE struct {
	cpe string
}

func New(cpe string) qualifier.Qualifier {
	return &platformCPE{cpe: cpe}
}

func isWindowsPlatformCPE(c cpe.CPE) bool {
	return c.Vendor == "microsoft" && strings.HasPrefix(c.Product, "windows")
}

func isUbuntuPlatformCPE(c cpe.CPE) bool {
	if c.Vendor == "canonical" && c.Product == "ubuntu_linux" {
		return true
	}

	if c.Vendor == "ubuntu" {
		return true
	}

	return false
}

func isDebianPlatformCPE(c cpe.CPE) bool {
	return c.Vendor == "debian" && (c.Product == "debian_linux" || c.Product == "linux")
}

func isWordpressPlatformCPE(c cpe.CPE) bool {
	return c.Vendor == "wordpress" && c.Product == "wordpress"
}

func (p platformCPE) Satisfied(d *distro.Distro, _ pkg.Package) (bool, error) {
	if p.cpe == "" {
		return true, nil
	}

	c, err := cpe.New(p.cpe)

	if err != nil {
		return true, err
	}

	// NOTE: if syft ever supports cataloging wordpress plugins there will need to be a
	// package type condition check added here
	if isWordpressPlatformCPE(c) {
		return false, nil
	}

	// The remaining checks are on distro, so if the distro is unknown the condition should
	// be considered to be satisified and avoid filtering matches
	if d == nil {
		return true, nil
	}

	if isWindowsPlatformCPE(c) {
		return d.Type == distro.Windows, nil
	}

	if isUbuntuPlatformCPE(c) {
		return d.Type == distro.Ubuntu, nil
	}

	if isDebianPlatformCPE(c) {
		return d.Type == distro.Debian, nil
	}

	return true, err
}
