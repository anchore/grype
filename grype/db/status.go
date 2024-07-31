package db

import "time"

type Status struct {
	Built         time.Time `json:"built"`
	Updated       time.Time `json:"updated"`
	SchemaVersion int       `json:"schemaVersion"`
	Location      string    `json:"location"`
	Checksum      string    `json:"checksum"`
	Err           error     `json:"error"`
}
