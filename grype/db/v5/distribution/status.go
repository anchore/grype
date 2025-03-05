package distribution

import "time"

type Status struct {
	Built         time.Time `json:"built"`
	SchemaVersion int       `json:"schemaVersion"`
	Location      string    `json:"location"`
	Checksum      string    `json:"checksum"`
	Err           error     `json:"error"`
}

func (s Status) Status() string {
	if s.Err != nil {
		return "invalid"
	}
	return "valid"
}
