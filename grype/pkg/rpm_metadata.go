package pkg

type RpmMetadata struct {
	Epoch           *int    `json:"epoch" cyclonedx:"epoch"`
	ModularityLabel *string `json:"modularityLabel" cyclonedx:"modularityLabel"`
}
