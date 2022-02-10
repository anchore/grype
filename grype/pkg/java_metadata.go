package pkg

type JavaMetadata struct {
	VirtualPath   string `json:"virtualPath"`
	PomArtifactID string `json:"pomArtifactID"`
	PomGroupID    string `json:"pomGroupID"`
	ManifestName  string `json:"manifestName"`
}
