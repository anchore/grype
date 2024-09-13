package pkg

import (
	"strings"

	"github.com/anchore/syft/syft/pkg"
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
	if p.Type == pkg.BinaryPkg {
		if strings.Contains(p.Name, "jdk") || strings.Contains(p.Name, "jre") || strings.Contains(p.Name, "java") {
			return true
		}
	}

	if _, ok := p.Metadata.(JavaVMInstallationMetadata); ok {
		return true
	}

	return false
}
