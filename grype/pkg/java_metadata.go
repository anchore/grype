package pkg

type JavaMetadata struct {
	VirtualPath   string `json:"virtualPath"`
	PomArtifactID string `json:"pomArtifactId"`
	PomGroupID    string `json:"pomGroupId"`
	ManifestName  string `json:"manifestName"`
}
