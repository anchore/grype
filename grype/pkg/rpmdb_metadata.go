package pkg

type RpmdbMetadata struct {
	SourceRpm string `json:"sourceRpm"`
	Epoch     *int   `json:"epoch"`
}
