package pkg

type RpmdbMetadata struct {
	// TODO: do we need to parse with json struct tags? (caps)
	SourceRpm string
	Epoch     *int
}
