package models

// descriptor describes what created the document as well as surrounding metadata
type descriptor struct {
	Name          string `json:"name"`
	Version       string `json:"version"`
	Configuration any    `json:"configuration,omitempty"`
	DB            any    `json:"db,omitempty"`
	Timestamp     string `json:"timestamp"`
}
