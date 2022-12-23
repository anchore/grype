package pkg

type GolangMetadata struct {
	BuildSettings     map[string]string `json:"goBuildSettings,omitempty"`
	GoCompiledVersion string            `json:"goCompiledVersion"`
	Architecture      string            `json:"architecture"`
	H1Digest          string            `json:"h1Digest,omitempty"`
	MainModule        string            `json:"mainModule,omitempty"`
}
