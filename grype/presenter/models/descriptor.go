package models

// descriptor describes what created the document as well as surrounding metadata
type descriptor struct {
	Name                  string      `json:"name"`
	Version               string      `json:"version"`
	Configuration         interface{} `json:"configuration,omitempty"`
	VulnerabilityDBStatus interface{} `json:"db,omitempty"`
	Timestamp             string      `json:"timestamp"`
}
