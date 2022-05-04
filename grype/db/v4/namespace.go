package v4

import (
	"fmt"
	"strings"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/internal"
	"github.com/anchore/grype/internal/log"
	packageurl "github.com/anchore/packageurl-go"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

const (
	NVDNamespace        = "nvd"
	MSRCNamespacePrefix = "msrc"
	VulnDBNamespace     = "vulndb"
)

func RecordSource(feed, group string) string {
	return fmt.Sprintf("%s:%s", feed, group)
}

func NamespaceForFeedGroup(feed, group string) (string, error) {
	switch {
	case feed == "vulnerabilities":
		return group, nil
	case feed == "github":
		return group, nil
	case feed == "nvdv2" && group == "nvdv2:cves":
		return NVDNamespace, nil
	case feed == "vulndb" && group == "vulndb:vulnerabilities":
		return VulnDBNamespace, nil
	case feed == "microsoft" && strings.HasPrefix(group, MSRCNamespacePrefix+":"):
		return group, nil
	}
	return "", fmt.Errorf("feed=%q group=%q has no namespace mappings", feed, group)
}

// NamespaceFromDistro returns the correct Feed Service namespace for the given
// distro. A namespace is a distinct identifier from the Feed Service, and it
// can be a combination of distro name and version(s), for example "amzn:8".
// This is critical to query the database and correlate the distro version with
// feed contents. Namespaces have to exist in the Feed Service, otherwise,
// this causes no results to be returned when the database is queried.
func NamespaceForDistro(d *distro.Distro) string {
	if d == nil {
		return ""
	}

	var versionSegments []int
	if d.Version != nil {
		versionSegments = d.Version.Segments()
	}

	if len(versionSegments) > 0 {
		switch d.Type {
		// derived from https://github.com/anchore/anchore-engine/blob/5bbbe6b9744f2fb806198ae5d6f0cfe3b367fd9d/anchore_engine/services/policy_engine/__init__.py#L149-L159
		case distro.CentOS, distro.RedHat, distro.Fedora, distro.RockyLinux, distro.AlmaLinux:
			// TODO: there is no mapping of fedora version to RHEL latest version (only the name)
			return fmt.Sprintf("rhel:%d", versionSegments[0])
		case distro.AmazonLinux:
			return fmt.Sprintf("amzn:%d", versionSegments[0])
		case distro.OracleLinux:
			return fmt.Sprintf("ol:%d", versionSegments[0])
		case distro.Alpine:
			// XXX this assumes that a major and minor versions will always exist in Segments
			return fmt.Sprintf("alpine:%d.%d", versionSegments[0], versionSegments[1])
		case distro.SLES:
			return fmt.Sprintf("sles:%d.%d", versionSegments[0], versionSegments[1])
		case distro.Windows:
			return fmt.Sprintf("%s:%d", MSRCNamespacePrefix, versionSegments[0])
		}
	}
	return fmt.Sprintf("%s:%s", strings.ToLower(d.Type.String()), d.FullVersion())
}

func NamespacesIndexedByCPE() []string {
	return []string{NVDNamespace, VulnDBNamespace}
}

func NamespacePackageNamersForLanguage(l syftPkg.Language) map[string]NamerByPackage {
	namespaces := make(map[string]NamerByPackage)
	switch l {
	case syftPkg.Ruby:
		namespaces["github:gem"] = defaultPackageNamer
	case syftPkg.Java:
		namespaces["github:java"] = githubJavaPackageNamer
	case syftPkg.JavaScript:
		namespaces["github:npm"] = defaultPackageNamer
	case syftPkg.Python:
		namespaces["github:python"] = defaultPackageNamer
	default:
		namespaces[fmt.Sprintf("github:%s", l)] = defaultPackageNamer
	}
	return namespaces
}

type NamerByPackage func(p pkg.Package) []string

func defaultPackageNamer(p pkg.Package) []string {
	return []string{p.Name}
}

func githubJavaPackageNamer(p pkg.Package) []string {
	names := internal.NewStringSet()

	// all github advisories are stored by "<group-name>:<artifact-name>"
	if metadata, ok := p.Metadata.(pkg.JavaMetadata); ok {
		if metadata.PomGroupID != "" {
			if metadata.PomArtifactID != "" {
				names.Add(fmt.Sprintf("%s:%s", metadata.PomGroupID, metadata.PomArtifactID))
			}
			if metadata.ManifestName != "" {
				names.Add(fmt.Sprintf("%s:%s", metadata.PomGroupID, metadata.ManifestName))
			}
		}
	}

	if p.PURL != "" {
		purl, err := packageurl.FromString(p.PURL)
		if err != nil {
			log.Warnf("unable to extract GHSA java package information from purl=%q: %+v", p.PURL, err)
		} else {
			names.Add(fmt.Sprintf("%s:%s", purl.Namespace, purl.Name))
		}
	}

	return names.ToSlice()
}
