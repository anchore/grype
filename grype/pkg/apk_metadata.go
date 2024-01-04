package pkg

type ApkMetadata struct {
	Files []ApkFileRecord `json:"files"`
}

// ApkFileRecord represents a single file listing and metadata from a APK DB entry (which may have many of these file records).
type ApkFileRecord struct {
	Path string `json:"path"`
}
