package pkg

type JavaMetadata struct {
	VirtualPath    string   `json:"virtualPath"`
	PomArtifactID  string   `json:"pomArtifactID"`
	PomGroupID     string   `json:"pomGroupID"`
	PomScope       string   `json:"pomScope"`
	ManifestName   string   `json:"manifestName"`
	ArchiveDigests []Digest `json:"archiveDigests"`
}

type Digest struct {
	Algorithm string `json:"algorithm"`
	Value     string `json:"value"`
}
