package pkg

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/internal/log"
	"github.com/anchore/grype/internal/stringutil"
	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/file"
	syftPkg "github.com/anchore/syft/syft/pkg"
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
	ID        ID
	Name      string           // the package name
	Version   string           // the version of the package
	Locations file.LocationSet // the locations that lead to the discovery of this package (note: this is not necessarily the locations that make up this package)
	Language  syftPkg.Language // the language ecosystem this package belongs to (e.g. JavaScript, Python, etc)
	Distro    *distro.Distro   // a specific distro this package originated from
	Licenses  []string
	Type      syftPkg.Type // the package type (e.g. Npm, Yarn, Python, Rpm, Deb, etc)
	CPEs      []cpe.CPE    // all possible Common Platform Enumerators
	PURL      string       // the Package URL (see https://github.com/package-url/purl-spec)
	Upstreams []UpstreamPackage
	Metadata  interface{} // This is NOT 1-for-1 the syft metadata! Only the select data needed for vulnerability matching
}

func New(p syftPkg.Package) Package {
	d, metadata, upstreams := dataFromPkg(p)

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
		ID:        ID(p.ID()),
		Name:      p.Name,
		Version:   p.Version,
		Distro:    d,
		Locations: p.Locations,
		Licenses:  licenses,
		Language:  p.Language,
		Type:      p.Type,
		CPEs:      p.CPEs,
		PURL:      p.PURL,
		Upstreams: upstreams,
		Metadata:  metadata,
	}
}

func FromCollection(catalog *syftPkg.Collection, config SynthesisConfig) []Package {
	return FromPackages(catalog.Sorted(), config)
}

func FromPackages(syftpkgs []syftPkg.Package, config SynthesisConfig) []Package {
	var pkgs []Package
	for _, p := range syftpkgs {
		if len(p.CPEs) == 0 {
			// For SPDX (or any format, really) we may have no CPEs
			if config.GenerateMissingCPEs {
				p.CPEs = cpes.Generate(p)
			} else {
				log.Debugf("no CPEs for package: %s", p)
			}
		}
		pkgs = append(pkgs, New(p))
	}

	return pkgs
}

// Stringer to represent a package.
func (p Package) String() string {
	return fmt.Sprintf("Pkg(type=%s, name=%s, version=%s, upstreams=%d)", p.Type, p.Name, p.Version, len(p.Upstreams))
}

func removePackagesByOverlap(catalog *syftPkg.Collection, relationships []artifact.Relationship, distro *distro.Distro) *syftPkg.Collection {
	byOverlap := map[artifact.ID]artifact.Relationship{}
	for _, r := range relationships {
		if r.Type == artifact.OwnershipByFileOverlapRelationship {
			byOverlap[r.To.ID()] = r
		}
	}

	out := syftPkg.NewCollection()
	comprehensiveDistroFeed := distroFeedIsComprehensive(distro)
	for p := range catalog.Enumerate() {
		r, ok := byOverlap[p.ID()]
		if ok {
			from := catalog.Package(r.From.ID())
			if from != nil && excludePackage(comprehensiveDistroFeed, p, *from) {
				continue
			}
		}
		out.Add(p)
	}

	return out
}

func excludePackage(comprehensiveDistroFeed bool, p syftPkg.Package, parent syftPkg.Package) bool {
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
	if p.Type != syftPkg.BinaryPkg {
		return false
	}

	return true
}

// distroFeedIsComprehensive returns true if the distro feed
// is comprehensive enough that we can drop packages owned by distro packages
// before matching.
func distroFeedIsComprehensive(dst *distro.Distro) bool {
	// TODO: this mechanism should be re-examined once https://github.com/anchore/grype/issues/1426
	// is addressed
	if dst == nil {
		return false
	}
	if dst.Type == distro.AmazonLinux {
		// AmazonLinux shows "like rhel" but is not an rhel clone
		// and does not have an exhaustive vulnerability feed.
		return false
	}
	for _, d := range comprehensiveDistros {
		if strings.EqualFold(string(d), dst.Name()) {
			return true
		}
		for _, n := range dst.IDLike {
			if strings.EqualFold(string(d), n) {
				return true
			}
		}
	}
	return false
}

// computed by:
// sqlite3 vulnerability.db 'select distinct namespace from vulnerability where fix_state in ("wont-fix", "not-fixed") order by namespace;' | cut -d ':' -f 1 | sort | uniq
// then removing 'github'
var comprehensiveDistros = []distro.Type{
	distro.Azure,
	distro.Debian,
	distro.Mariner,
	distro.RedHat,
	distro.Ubuntu,
}

func isOSPackage(p syftPkg.Package) bool {
	switch p.Type {
	case syftPkg.DebPkg, syftPkg.RpmPkg, syftPkg.PortagePkg, syftPkg.AlpmPkg, syftPkg.ApkPkg:
		return true
	default:
		return false
	}
}

func dataFromPkg(p syftPkg.Package) (*distro.Distro, any, []UpstreamPackage) {
	var metadata interface{}
	var upstreams []UpstreamPackage

	switch p.Metadata.(type) {
	case syftPkg.GolangModuleEntry, syftPkg.GolangBinaryBuildinfoEntry:
		metadata = golangMetadataFromPkg(p)
	case syftPkg.DpkgDBEntry:
		upstreams = dpkgDataFromPkg(p)
	case syftPkg.DpkgArchiveEntry:
		upstreams = dpkgDataFromPkg(p)
	case syftPkg.RpmArchive, syftPkg.RpmDBEntry:
		m, u := rpmDataFromPkg(p)
		upstreams = u
		if m != nil {
			metadata = *m
		}
	case syftPkg.JavaArchive:
		if m := javaDataFromPkg(p); m != nil {
			metadata = *m
		}
	case syftPkg.ApkDBEntry:
		metadata = apkMetadataFromPkg(p)
		upstreams = apkDataFromPkg(p)
	case syftPkg.JavaVMInstallation:
		metadata = javaVMDataFromPkg(p)
	}

	var d *distro.Distro
	if p.PURL != "" {
		if len(upstreams) == 0 {
			d, upstreams = readPURL(&p)
		} else {
			d, _ = readPURL(&p)
		}
	}

	return d, metadata, upstreams
}

// readPURL reads any additional data Grype can use, which is ignored by Syft's PURL conversion
func readPURL(p *syftPkg.Package) (*distro.Distro, []UpstreamPackage) {
	var upstreams []UpstreamPackage
	var distroName, distroVersion string

	purl, err := packageurl.FromString(p.PURL)
	if err != nil {
		log.Debugf("unable to parse PURL: %v", err)
	} else {
		for _, qualifier := range purl.Qualifiers {
			switch qualifier.Key {
			case syftPkg.PURLQualifierUpstream:
				for _, newUpstream := range parseUpstream(purl.Name, qualifier.Value, p.Type) {
					if slices.Contains(upstreams, newUpstream) {
						continue
					}
					upstreams = append(upstreams, newUpstream)
				}
			case syftPkg.PURLQualifierDistro:
				fields := strings.SplitN(qualifier.Value, "-", 2)
				distroName = fields[0]
				if len(fields) > 1 {
					distroVersion = fields[1]
				}
			}
		}
	}

	var d *distro.Distro
	if distroName != "" {
		d, err = distro.NewFromNameVersion(distroName, distroVersion)
		if err != nil {
			log.Trace("Unable to create Distro from a release: %s", err)
			d = nil
		}
	}

	return d, upstreams
}

func javaVMDataFromPkg(p syftPkg.Package) any {
	if value, ok := p.Metadata.(syftPkg.JavaVMInstallation); ok {
		return JavaVMInstallationMetadata{
			Release: JavaVMReleaseMetadata{
				JavaRuntimeVersion: value.Release.JavaRuntimeVersion,
				JavaVersion:        value.Release.JavaVersion,
				FullVersion:        value.Release.FullVersion,
				SemanticVersion:    value.Release.SemanticVersion,
			},
		}
	}

	return nil
}

func apkMetadataFromPkg(p syftPkg.Package) interface{} {
	if m, ok := p.Metadata.(syftPkg.ApkDBEntry); ok {
		metadata := ApkMetadata{}

		fileRecords := make([]ApkFileRecord, 0, len(m.Files))
		for _, record := range m.Files {
			r := ApkFileRecord{Path: record.Path}
			fileRecords = append(fileRecords, r)
		}

		metadata.Files = fileRecords

		return metadata
	}

	return nil
}

func golangMetadataFromPkg(p syftPkg.Package) interface{} {
	switch value := p.Metadata.(type) {
	case syftPkg.GolangBinaryBuildinfoEntry:
		metadata := GolangBinMetadata{}
		if value.BuildSettings != nil {
			metadata.BuildSettings = value.BuildSettings
		}
		metadata.GoCompiledVersion = value.GoCompiledVersion
		metadata.Architecture = value.Architecture
		metadata.H1Digest = value.H1Digest
		metadata.MainModule = value.MainModule
		return metadata
	case syftPkg.GolangModuleEntry:
		metadata := GolangModMetadata{}
		metadata.H1Digest = value.H1Digest
		return metadata
	}
	return nil
}

func dpkgDataFromPkg(p syftPkg.Package) (upstreams []UpstreamPackage) {
	switch value := p.Metadata.(type) {
	case syftPkg.DpkgDBEntry:
		if value.Source != "" {
			upstreams = append(upstreams, UpstreamPackage{
				Name:    value.Source,
				Version: value.SourceVersion,
			})
		}
	case syftPkg.DpkgArchiveEntry:
		if value.Source != "" {
			upstreams = append(upstreams, UpstreamPackage{
				Name:    value.Source,
				Version: value.SourceVersion,
			})
		}
	default:
		log.Warnf("unable to extract DPKG metadata for %s", p)
	}

	return upstreams
}

func rpmDataFromPkg(p syftPkg.Package) (metadata *RpmMetadata, upstreams []UpstreamPackage) {
	switch m := p.Metadata.(type) {
	case syftPkg.RpmDBEntry:
		if m.SourceRpm != "" {
			upstreams = handleSourceRPM(p.Name, m.SourceRpm)
		}

		metadata = &RpmMetadata{
			Epoch:           m.Epoch,
			ModularityLabel: m.ModularityLabel,
		}
	case syftPkg.RpmArchive:
		if m.SourceRpm != "" {
			upstreams = handleSourceRPM(p.Name, m.SourceRpm)
		}

		metadata = &RpmMetadata{
			Epoch:           m.Epoch,
			ModularityLabel: m.ModularityLabel,
		}
	}
	return metadata, upstreams
}

func handleSourceRPM(pkgName, sourceRpm string) []UpstreamPackage {
	var upstreams []UpstreamPackage
	name, version := getNameAndELVersion(sourceRpm)
	if name == "" && version == "" {
		log.Warnf("unable to extract name and version from SourceRPM=%q ", sourceRpm)
	} else if name != pkgName {
		// don't include matches if the source package name matches the current package name
		if name != "" && version != "" {
			upstreams = append(upstreams,
				UpstreamPackage{
					Name:    name,
					Version: version,
				},
			)
		}
	}
	return upstreams
}

func getNameAndELVersion(sourceRpm string) (string, string) {
	groupMatches := stringutil.MatchCaptureGroups(rpmPackageNamePattern, sourceRpm)
	version := groupMatches["version"] + "-" + groupMatches["release"]
	return groupMatches["name"], version
}

func javaDataFromPkg(p syftPkg.Package) (metadata *JavaMetadata) {
	if value, ok := p.Metadata.(syftPkg.JavaArchive); ok {
		var artifactID, groupID, name string
		if value.PomProperties != nil {
			artifactID = value.PomProperties.ArtifactID
			groupID = value.PomProperties.GroupID
		}
		if value.Manifest != nil {
			for _, kv := range value.Manifest.Main {
				if kv.Key == "Name" {
					name = kv.Value
				}
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
			PomArtifactID:  artifactID,
			PomGroupID:     groupID,
			ManifestName:   name,
			ArchiveDigests: archiveDigests,
		}
	} else {
		log.Warnf("unable to extract Java metadata for %s", p)
	}
	return metadata
}

func apkDataFromPkg(p syftPkg.Package) (upstreams []UpstreamPackage) {
	if value, ok := p.Metadata.(syftPkg.ApkDBEntry); ok {
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

func parseUpstream(pkgName string, value string, pkgType syftPkg.Type) []UpstreamPackage {
	if pkgType == syftPkg.RpmPkg {
		return handleSourceRPM(pkgName, value)
	}
	return handleDefaultUpstream(pkgName, value)
}

func handleDefaultUpstream(pkgName string, value string) []UpstreamPackage {
	fields := strings.Split(value, "@")
	switch len(fields) {
	case 2:
		if fields[0] == pkgName {
			return nil
		}
		return []UpstreamPackage{
			{
				Name:    fields[0],
				Version: fields[1],
			},
		}
	case 1:
		if fields[0] == pkgName {
			return nil
		}
		return []UpstreamPackage{
			{
				Name: fields[0],
			},
		}
	}
	return nil
}
