package json

// Descriptor describes what created the document as well as surrounding metadata
type Descriptor struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}
