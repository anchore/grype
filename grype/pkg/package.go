package pkg

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/anchore/grype/internal/log"
	"github.com/anchore/grype/internal/stringutil"
	packageurl "github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg"

	cpes "github.com/anchore/syft/syft/pkg/cataloger/common/cpe"
)

// the source-rpm field has something akin to "util-linux-ng-2.17.2-12.28.el6_9.2.src.rpm"
// in which case the pattern will extract out the following values for the named capture groups:
//
//	name = "util-linux-ng"
//	version = "2.17.2" (or, if there's an epoch, we'd expect a value like "4:2.17.2")
//	release = "12.28.el6_9.2"
//	arch = "src"
var rpmPackageNamePattern = regexp.MustCompile(`^(?P<name>.*)-(?P<version>.*)-(?P<release>.*)\.(?P<arch>[a-zA-Z][^.]+)(\.rpm)$`)

// ID represents a unique value for each package added to a package collection.
type ID string

// Package represents an application or library that has been bundled into a distributable format.
type Package struct {
	ID           ID
	Name         string           // the package name
	Version      string           // the version of the package
	Locations    file.LocationSet // the locations that lead to the discovery of this package (note: this is not necessarily the locations that make up this package)
	Language     pkg.Language     // the language ecosystem this package belongs to (e.g. JavaScript, Python, etc)
	Licenses     []string
	Type         pkg.Type  // the package type (e.g. Npm, Yarn, Python, Rpm, Deb, etc)
	CPEs         []cpe.CPE // all possible Common Platform Enumerators
	PURL         string    // the Package URL (see https://github.com/package-url/purl-spec)
	Upstreams    []UpstreamPackage
	MetadataType MetadataType
	Metadata     interface{} // This is NOT 1-for-1 the syft metadata! Only the select data needed for vulnerability matching
}

func New(p pkg.Package) Package {
	metadataType, metadata, upstreams := dataFromPkg(p)

	licenseObjs := p.Licenses.ToSlice()
	// note: this is used for presentation downstream and is a collection, thus should always be allocated
	licenses := make([]string, 0, len(licenseObjs))
	for _, l := range licenseObjs {
		licenses = append(licenses, l.Value)
	}
	if licenses == nil {
		licenses = []string{}
	}

	return Package{
		ID:           ID(p.ID()),
		Name:         p.Name,
		Version:      p.Version,
		Locations:    p.Locations,
		Licenses:     licenses,
		Language:     p.Language,
		Type:         p.Type,
		CPEs:         p.CPEs,
		PURL:         p.PURL,
		Upstreams:    upstreams,
		MetadataType: metadataType,
		Metadata:     metadata,
	}
}

func FromCollection(catalog *pkg.Collection, config SynthesisConfig) []Package {
	return FromPackages(catalog.Sorted(), config)
}

func FromPackages(syftpkgs []pkg.Package, config SynthesisConfig) []Package {
	var pkgs []Package
	var missingCPEs bool
	for _, p := range syftpkgs {
		if len(p.CPEs) == 0 {
			// For SPDX (or any format, really) we may have no CPEs
			if config.GenerateMissingCPEs {
				p.CPEs = cpes.Generate(p)
			} else {
				log.Debugf("no CPEs for package: %s", p)
				missingCPEs = true
			}
		}
		pkgs = append(pkgs, New(p))
	}
	if missingCPEs {
		log.Warnf("some package(s) are missing CPEs. This may result in missing vulnerabilities. You may autogenerate these using: --add-cpes-if-none")
	}
	return pkgs
}

// Stringer to represent a package.
func (p Package) String() string {
	return fmt.Sprintf("Pkg(type=%s, name=%s, version=%s, upstreams=%d)", p.Type, p.Name, p.Version, len(p.Upstreams))
}

func (p Package) DistroFragmentFromPURL() string {
	if p.PURL == "" {
		return ""
	}
	purl, err := packageurl.FromString(p.PURL)
	if err != nil {
		return ""
	}
	for k, v := range purl.Qualifiers.Map() {
		if k == "distro" && v != "" {
			return v
		}
	}
	return ""
}

func removePackagesByOverlap(catalog *pkg.Collection, relationships []artifact.Relationship, distro *linux.Release) *pkg.Collection {
	byOverlap := map[artifact.ID]artifact.Relationship{}
	for _, r := range relationships {
		if r.Type == artifact.OwnershipByFileOverlapRelationship {
			byOverlap[r.To.ID()] = r
		}
	}

	out := pkg.NewCollection()
	comprehensiveDistroFeed := distroFeedIsComprehensive(distro)
	for p := range catalog.Enumerate() {
		r, ok := byOverlap[p.ID()]
		if ok {
			from, ok := r.From.(pkg.Package)
			if ok && excludePackage(comprehensiveDistroFeed, p, from) {
				continue
			}
		}
		out.Add(p)
	}

	return out
}

func excludePackage(comprehensiveDistroFeed bool, p pkg.Package, parent pkg.Package) bool {
	// NOTE: we are not checking the name because we have mismatches like:
	// python      3.9.2      binary
	// python3.9   3.9.2-1    deb

	// If the version is not effectively the same, keep both
	if !strings.HasPrefix(parent.Version, p.Version) {
		return false
	}

	// If the parent is an OS package and the child is not, exclude the child
	// for distros that have a comprehensive feed. That is, distros that list
	// vulnerabilities that aren't fixed. Otherwise, the child package might
	// be needed for matching.
	if comprehensiveDistroFeed && isOSPackage(parent) && !isOSPackage(p) {
		return true
	}

	// filter out binary packages, even for non-comprehensive distros
	if p.Type != pkg.BinaryPkg {
		return false
	}

	return true
}

// distroFeedIsComprehensive returns true if the distro feed
// is comprehensive enough that we can drop packages owned by distro packages
// before matching.
func distroFeedIsComprehensive(distro *linux.Release) bool {
	// TODO: this mechanism should be re-examined once https://github.com/anchore/grype/issues/1426
	// is addressed
	if distro == nil {
		return false
	}
	if distro.ID == "amzn" {
		// AmazonLinux shows "like rhel" but is not an rhel clone
		// and does not have an exhaustive vulnerability feed.
		return false
	}
	for _, d := range comprehensiveDistros {
		if strings.EqualFold(d, distro.ID) {
			return true
		}
		for _, n := range distro.IDLike {
			if strings.EqualFold(d, n) {
				return true
			}
		}
	}
	return false
}

// computed by:
// sqlite3 vulnerability.db 'select distinct namespace from vulnerability where fix_state in ("wont-fix", "not-fixed") order by namespace;' | cut -d ':' -f 1 | sort | uniq
// then removing 'github' and replacing 'redhat' with 'rhel'
var comprehensiveDistros = []string{
	"debian",
	"mariner",
	"rhel",
	"ubuntu",
}

func isOSPackage(p pkg.Package) bool {
	switch p.Type {
	case pkg.DebPkg, pkg.RpmPkg, pkg.PortagePkg, pkg.AlpmPkg, pkg.ApkPkg:
		return true
	default:
		return false
	}
}

func dataFromPkg(p pkg.Package) (MetadataType, interface{}, []UpstreamPackage) {
	var metadata interface{}
	var upstreams []UpstreamPackage
	var metadataType MetadataType

	switch p.MetadataType {
	case pkg.GolangBinMetadataType, pkg.GolangModMetadataType:
		metadataType, metadata = golangMetadataFromPkg(p)
	case pkg.DpkgMetadataType:
		upstreams = dpkgDataFromPkg(p)
	case pkg.RpmMetadataType:
		m, u := rpmDataFromPkg(p)
		upstreams = u
		if m != nil {
			metadata = *m
			metadataType = RpmMetadataType
		}
	case pkg.JavaMetadataType:
		if m := javaDataFromPkg(p); m != nil {
			metadata = *m
			metadataType = JavaMetadataType
		}
	case pkg.ApkMetadataType:
		upstreams = apkDataFromPkg(p)
	}
	return metadataType, metadata, upstreams
}

func golangMetadataFromPkg(p pkg.Package) (MetadataType, interface{}) {
	switch value := p.Metadata.(type) {
	case pkg.GolangBinMetadata:
		metadata := GolangBinMetadata{}
		if value.BuildSettings != nil {
			metadata.BuildSettings = value.BuildSettings
		}
		metadata.GoCompiledVersion = value.GoCompiledVersion
		metadata.Architecture = value.Architecture
		metadata.H1Digest = value.H1Digest
		metadata.MainModule = value.MainModule
		return GolangBinMetadataType, metadata
	case pkg.GolangModMetadata:
		metadata := GolangModMetadata{}
		metadata.H1Digest = value.H1Digest
		return GolangModMetadataType, metadata
	}
	return "", nil
}

func dpkgDataFromPkg(p pkg.Package) (upstreams []UpstreamPackage) {
	if value, ok := p.Metadata.(pkg.DpkgMetadata); ok {
		if value.Source != "" {
			upstreams = append(upstreams, UpstreamPackage{
				Name:    value.Source,
				Version: value.SourceVersion,
			})
		}
	} else {
		log.Warnf("unable to extract DPKG metadata for %s", p)
	}
	return upstreams
}

func rpmDataFromPkg(p pkg.Package) (metadata *RpmMetadata, upstreams []UpstreamPackage) {
	if value, ok := p.Metadata.(pkg.RpmMetadata); ok {
		if value.SourceRpm != "" {
			name, version := getNameAndELVersion(value.SourceRpm)
			if name == "" && version == "" {
				log.Warnf("unable to extract name and version from SourceRPM=%q ", value.SourceRpm)
			} else if name != p.Name {
				// don't include matches if the source package name matches the current package name
				upstreams = append(upstreams, UpstreamPackage{
					Name:    name,
					Version: version,
				})
			}
		}

		metadata = &RpmMetadata{
			Epoch:           value.Epoch,
			ModularityLabel: value.ModularityLabel,
		}
	} else {
		log.Warnf("unable to extract RPM metadata for %s", p)
	}
	return metadata, upstreams
}

func getNameAndELVersion(sourceRpm string) (string, string) {
	groupMatches := stringutil.MatchCaptureGroups(rpmPackageNamePattern, sourceRpm)
	version := groupMatches["version"] + "-" + groupMatches["release"]
	return groupMatches["name"], version
}

func javaDataFromPkg(p pkg.Package) (metadata *JavaMetadata) {
	if value, ok := p.Metadata.(pkg.JavaMetadata); ok {
		var artifact, group, name string
		if value.PomProperties != nil {
			artifact = value.PomProperties.ArtifactID
			group = value.PomProperties.GroupID
		}
		if value.Manifest != nil {
			if n, ok := value.Manifest.Main["Name"]; ok {
				name = n
			}
		}

		var archiveDigests []Digest
		if len(value.ArchiveDigests) > 0 {
			for _, d := range value.ArchiveDigests {
				archiveDigests = append(archiveDigests, Digest{
					Algorithm: d.Algorithm,
					Value:     d.Value,
				})
			}
		}

		metadata = &JavaMetadata{
			VirtualPath:    value.VirtualPath,
			PomArtifactID:  artifact,
			PomGroupID:     group,
			ManifestName:   name,
			ArchiveDigests: archiveDigests,
		}
	} else {
		log.Warnf("unable to extract Java metadata for %s", p)
	}
	return metadata
}

func apkDataFromPkg(p pkg.Package) (upstreams []UpstreamPackage) {
	if value, ok := p.Metadata.(pkg.ApkMetadata); ok {
		if value.OriginPackage != "" {
			upstreams = append(upstreams, UpstreamPackage{
				Name: value.OriginPackage,
			})
		}
	} else {
		log.Warnf("unable to extract APK metadata for %s", p)
	}
	return upstreams
}

func ByID(id ID, pkgs []Package) *Package {
	for _, p := range pkgs {
		if p.ID == id {
			return &p
		}
	}
	return nil
}
