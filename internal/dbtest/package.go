package dbtest

import (
	"github.com/google/uuid"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/syft/syft/cpe"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// common distro constants for tests
var (
	Debian8  = distro.New(distro.Debian, "8", "")
	Debian9  = distro.New(distro.Debian, "9", "")
	Debian10 = distro.New(distro.Debian, "10", "")
	Debian11 = distro.New(distro.Debian, "11", "")
	Debian12 = distro.New(distro.Debian, "12", "")

	Ubuntu1804 = distro.New(distro.Ubuntu, "18.04", "")
	Ubuntu2004 = distro.New(distro.Ubuntu, "20.04", "")
	Ubuntu2204 = distro.New(distro.Ubuntu, "22.04", "")
	Ubuntu2404 = distro.New(distro.Ubuntu, "24.04", "")

	Alpine316 = distro.New(distro.Alpine, "3.16", "")
	Alpine317 = distro.New(distro.Alpine, "3.17", "")
	Alpine318 = distro.New(distro.Alpine, "3.18", "")
	Alpine319 = distro.New(distro.Alpine, "3.19", "")

	RHEL7 = distro.New(distro.RedHat, "7", "")
	RHEL8 = distro.New(distro.RedHat, "8", "")
	RHEL9 = distro.New(distro.RedHat, "9", "")
)

// PackageBuilder provides a fluent API for building test packages.
type PackageBuilder struct {
	pkg pkg.Package
}

// NewPackage creates a new PackageBuilder with the given name, version, and type.
// An ID is auto-generated.
func NewPackage(name, version string, t syftPkg.Type) *PackageBuilder {
	return &PackageBuilder{
		pkg: pkg.Package{
			ID:      pkg.ID(uuid.New().String()),
			Name:    name,
			Version: version,
			Type:    t,
		},
	}
}

// WithType sets the package type (e.g., syftPkg.ApkPkg, syftPkg.RpmPkg).
func (b *PackageBuilder) WithType(t syftPkg.Type) *PackageBuilder {
	b.pkg.Type = t
	return b
}

// WithDistro sets the package's distro.
func (b *PackageBuilder) WithDistro(d *distro.Distro) *PackageBuilder {
	b.pkg.Distro = d
	return b
}

// WithLanguage sets the package's language ecosystem.
func (b *PackageBuilder) WithLanguage(lang syftPkg.Language) *PackageBuilder {
	b.pkg.Language = lang
	return b
}

// WithCPE adds a CPE to the package.
// The cpeStr should be in CPE 2.3 format (e.g., "cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*").
func (b *PackageBuilder) WithCPE(cpeStr string) *PackageBuilder {
	c := cpe.Must(cpeStr, "")
	b.pkg.CPEs = append(b.pkg.CPEs, c)
	return b
}

// WithCPEs adds multiple CPEs to the package.
func (b *PackageBuilder) WithCPEs(cpeStrs ...string) *PackageBuilder {
	for _, cpeStr := range cpeStrs {
		b.WithCPE(cpeStr)
	}
	return b
}

// WithPURL sets the Package URL.
func (b *PackageBuilder) WithPURL(purl string) *PackageBuilder {
	b.pkg.PURL = purl
	return b
}

// WithUpstream adds an upstream package.
func (b *PackageBuilder) WithUpstream(name, version string) *PackageBuilder {
	b.pkg.Upstreams = append(b.pkg.Upstreams, pkg.UpstreamPackage{
		Name:    name,
		Version: version,
	})
	return b
}

// WithMetadata sets package-specific metadata.
func (b *PackageBuilder) WithMetadata(metadata interface{}) *PackageBuilder {
	b.pkg.Metadata = metadata
	return b
}

// WithLicenses sets the package licenses.
func (b *PackageBuilder) WithLicenses(licenses ...string) *PackageBuilder {
	b.pkg.Licenses = licenses
	return b
}

// Build returns the constructed package.
func (b *PackageBuilder) Build() pkg.Package {
	return b.pkg
}
