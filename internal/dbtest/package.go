package dbtest

import (
	"github.com/google/uuid"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/file"
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

	RHEL7  = distro.New(distro.RedHat, "7", "")
	RHEL8  = distro.New(distro.RedHat, "8", "")
	RHEL9  = distro.New(distro.RedHat, "9", "")
	RHEL10 = distro.New(distro.RedHat, "10", "")

	AlmaLinux8 = distro.New(distro.AlmaLinux, "8", "")
	AlmaLinux9 = distro.New(distro.AlmaLinux, "9", "")

	SLES156 = distro.New(distro.SLES, "15.6", "")
	SLES157 = distro.New(distro.SLES, "15.7", "")
	Hummingbird1 = distro.New(distro.Hummingbird, "1", "")
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

// WithID overrides the auto-generated package ID. Use this when a test needs
// a stable, comparable ID (e.g., to assert against an IgnoreFilter that
// references the package by ID).
func (b *PackageBuilder) WithID(id pkg.ID) *PackageBuilder {
	b.pkg.ID = id
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

// WithLocation adds a file location to the package.
func (b *PackageBuilder) WithLocation(path string) *PackageBuilder {
	b.pkg.Locations = file.NewLocationSet(
		append(b.pkg.Locations.ToSlice(), file.NewLocation(path))...,
	)
	return b
}

// WithRelatedPackage adds a related package via the given relationship type.
func (b *PackageBuilder) WithRelatedPackage(relationshipType artifact.RelationshipType, related *pkg.Package) *PackageBuilder {
	if b.pkg.RelatedPackages == nil {
		b.pkg.RelatedPackages = make(map[artifact.RelationshipType][]*pkg.Package)
	}
	b.pkg.RelatedPackages[relationshipType] = append(b.pkg.RelatedPackages[relationshipType], related)
	return b
}

// Build returns the constructed package.
func (b *PackageBuilder) Build() pkg.Package {
	if b.pkg.ID == "" {
		b.pkg.ID = pkg.ID(uuid.New().String())
	}
	return b.pkg
}
