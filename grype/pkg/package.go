package pkg

import (
	"fmt"
	"regexp"
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

type Enhancer func(out *Package, purl packageurl.PackageURL, pkg syftPkg.Package)

func New(p syftPkg.Package, enhancers ...Enhancer) Package {
	metadata, upstreams := dataFromPkg(p)

	licenseObjs := p.Licenses.ToSlice()
	// note: this is used for presentation downstream and is a collection, thus should always be allocated
	licenses := make([]string, 0, len(licenseObjs))
	for _, l := range licenseObjs {
		licenses = append(licenses, l.Value)
	}
	if licenses == nil {
		licenses = []string{}
	}

	out := Package{
		ID:        ID(p.ID()),
		Name:      p.Name,
		Version:   p.Version,
		Locations: p.Locations,
		Licenses:  licenses,
		Language:  p.Language,
		Type:      p.Type,
		CPEs:      p.CPEs,
		PURL:      p.PURL,
		Upstreams: upstreams,
		Metadata:  metadata,
	}

	if len(enhancers) > 0 {
		purl, err := packageurl.FromString(p.PURL)
		if err != nil {
			log.WithFields("purl", purl, "error", err).Debug("unable to parse PURL")
		}
		for _, e := range enhancers {
			e(&out, purl, p)
		}
	}

	return out
}

func FromCollection(catalog *syftPkg.Collection, config SynthesisConfig, enhancers ...Enhancer) []Package {
	return FromPackages(catalog.Sorted(), config, enhancers...)
}

func FromPackages(syftPkgs []syftPkg.Package, config SynthesisConfig, enhancers ...Enhancer) []Package {
	var pkgs []Package

	// if the user provided a distro explicitly, then use that over any distro that may be inferred from a package url
	enhancers = append([]Enhancer{applyDistroOverride(config.Distro.Override)}, enhancers...)

	for _, p := range syftPkgs {
		if len(p.CPEs) == 0 {
			// for SPDX (or any format, really) we may have no CPEs
			if config.GenerateMissingCPEs {
				p.CPEs = cpes.Generate(p)
			} else {
				log.Debugf("no CPEs for package: %s", p)
			}
		}

		pkgs = append(pkgs, New(p, enhancers...))
	}

	return pkgs
}

func (p Package) String() string {
	var d string
	if p.Distro != nil {
		d = fmt.Sprintf(", distro=%s", p.Distro.String())
	}
	var u string
	if len(p.Upstreams) > 0 {
		u = fmt.Sprintf(", upstreams=%d", len(p.Upstreams))
	}
	return fmt.Sprintf("Pkg(type=%s, name=%s, version=%s%s%s)", p.Type, p.Name, p.Version, u, d)
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

	// If the version is not approximately the same, keep both
	if !strings.HasPrefix(parent.Version, p.Version) && !strings.HasPrefix(p.Version, parent.Version) {
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

func dataFromPkg(p syftPkg.Package) (any, []UpstreamPackage) {
	var metadata interface{}
	var upstreams []UpstreamPackage

	// use the metadata to determine the type of package
	switch p.Metadata.(type) {
	case syftPkg.GolangModuleEntry, syftPkg.GolangBinaryBuildinfoEntry, syftPkg.GolangSourceEntry:
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
		if m := javaDataFromPkgMetadata(p); m != nil {
			metadata = *m
		}
	case syftPkg.ApkDBEntry:
		metadata = apkMetadataFromPkg(p)
		upstreams = apkDataFromPkg(p)
	case syftPkg.JavaVMInstallation:
		metadata = javaVMDataFromPkg(p)
	}

	// there are still cases where we could still fill the metadata from other info (such as the PURL)
	if metadata == nil {
		if p.Type == syftPkg.JavaPkg {
			metadata = javaDataFromPkgData(p)
		}
	}

	return metadata, upstreams
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
	case syftPkg.GolangSourceEntry:
		metadata := GolangSourceMetadata{}
		metadata.H1Digest = value.H1Digest
		metadata.OperatingSystem = value.OperatingSystem
		metadata.Architecture = value.Architecture
		metadata.BuildTags = value.BuildTags
		metadata.CgoEnabled = value.CgoEnabled
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
		log.Debugf("unable to extract DPKG metadata for %s", p)
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
		log.Debugf("unable to extract name and version from SourceRPM=%q", sourceRpm)
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

func javaDataFromPkgMetadata(p syftPkg.Package) (metadata *JavaMetadata) {
	if value, ok := p.Metadata.(syftPkg.JavaArchive); ok {
		var artifactID, groupID, name string
		if value.PomProperties != nil {
			artifactID = value.PomProperties.ArtifactID
			groupID = value.PomProperties.GroupID
		} else {
			// get the group ID / artifact ID from the PURL
			artifactID, groupID = javaGroupArtifactIDFromPurl(p.PURL)
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
	}
	return metadata
}

func javaDataFromPkgData(p syftPkg.Package) (metadata *JavaMetadata) {
	switch p.Type {
	case syftPkg.JavaPkg:
		artifactID, groupID := javaGroupArtifactIDFromPurl(p.PURL)
		if artifactID != "" && groupID != "" {
			metadata = &JavaMetadata{
				PomArtifactID: artifactID,
				PomGroupID:    groupID,
			}
		}
	default:
		log.Debugf("unable to extract metadata for %s", p)
	}

	return metadata
}

func javaGroupArtifactIDFromPurl(p string) (string, string) {
	purl, err := packageurl.FromString(p)
	if err != nil {
		log.WithFields("purl", purl, "error", err).Debug("unable to parse java PURL")
		return "", ""
	}
	return purl.Name, purl.Namespace
}

func apkDataFromPkg(p syftPkg.Package) (upstreams []UpstreamPackage) {
	if value, ok := p.Metadata.(syftPkg.ApkDBEntry); ok {
		if value.OriginPackage != "" {
			upstreams = append(upstreams, UpstreamPackage{
				Name: value.OriginPackage,
			})
		}
	} else {
		log.Debugf("unable to extract APK metadata for %s", p)
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

func applyDistroOverride(override *distro.Distro) Enhancer {
	// the override here comes from either the --distro flag, which already has a channel indication applied
	return func(out *Package, _ packageurl.PackageURL, _ syftPkg.Package) {
		if override == nil {
			return
		}
		// allow downstream matchers to always consider the given user distro
		out.Distro = override
	}
}
