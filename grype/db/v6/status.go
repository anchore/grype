package v6

import "encoding/json"

type Status struct {
	SchemaVersion string `json:"schemaVersion"`
	Built         Time   `json:"built"`
	Path          string `json:"path"`
	Checksum      string `json:"checksum"`
	Err           error  `json:"error"`
}

func (s Status) Status() string {
	if s.Err != nil {
		return "invalid"
	}
	return "valid"
}

func (s Status) MarshalJSON() ([]byte, error) {
	errStr := ""
	if s.Err != nil {
		errStr = s.Err.Error()
	}

	return json.Marshal(&struct {
		SchemaVersion string `json:"schemaVersion"`
		Built         Time   `json:"built"`
		Path          string `json:"path"`
		Checksum      string `json:"checksum"`
		Err           string `json:"error"`
	}{
		SchemaVersion: s.SchemaVersion,
		Built:         s.Built,
		Path:          s.Path,
		Checksum:      s.Checksum,
		Err:           errStr,
	})
}
