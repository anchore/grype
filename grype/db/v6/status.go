package v6

type Status struct {
	Built         Time   `json:"built"`
	SchemaVersion string `json:"schemaVersion"`
	Location      string `json:"location"`
	Checksum      string `json:"checksum"`
	Err           error  `json:"error"`
}
