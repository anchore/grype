package pkg

import (
	"github.com/scylladb/go-set/strset"

	syftPkg "github.com/anchore/syft/syft/pkg"
)

type JavaMetadata struct {
	VirtualPath    string   `json:"virtualPath"`
	PomArtifactID  string   `json:"pomArtifactID"`
	PomGroupID     string   `json:"pomGroupID"`
	ManifestName   string   `json:"manifestName"`
	ArchiveDigests []Digest `json:"archiveDigests"`
}

type Digest struct {
	Algorithm string `json:"algorithm"`
	Value     string `json:"value"`
}

type JavaVMInstallationMetadata struct {
	Release JavaVMReleaseMetadata `json:"release,omitempty"`
}

type JavaVMReleaseMetadata struct {
	JavaRuntimeVersion string `json:"javaRuntimeVersion,omitempty"`
	JavaVersion        string `json:"javaVersion,omitempty"`
	FullVersion        string `json:"fullVersion,omitempty"`
	SemanticVersion    string `json:"semanticVersion,omitempty"`
}

func IsJvmPackage(p Package) bool {
	if _, ok := p.Metadata.(JavaVMInstallationMetadata); ok {
		return true
	}

	if p.Type == syftPkg.BinaryPkg {
		if HasJvmPackageName(p.Name) {
			return true
		}
	}

	return false
}

var jvmIndications = strset.New("java_se", "jre", "jdk", "zulu", "openjdk", "java", "java/jre", "java/jdk")

func HasJvmPackageName(name string) bool {
	return jvmIndications.Has(name)
}
