package unmarshal

import (
	"encoding/json"
	"fmt"
	"io"
)

type ItemsEnvelope struct {
	Schema     string          `yaml:"schema" json:"schema" mapstructure:"schema"`
	Identifier string          `yaml:"identifier" json:"identifier" mapstructure:"identifier"`
	Item       json.RawMessage `yaml:"item" json:"item" mapstructure:"item"`
}

func Envelope(reader io.Reader) (*ItemsEnvelope, error) {
	var envelope ItemsEnvelope
	dec := json.NewDecoder(reader)
	err := dec.Decode(&envelope)
	if err != nil {
		return nil, fmt.Errorf("unable to open envelope: %w", err)
	}
	return &envelope, nil
}
