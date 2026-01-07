package unmarshal

import (
	"io"
)

type MatchExclusion struct {
	ID          string `json:"id"`
	Constraints []struct {
		Vulnerability struct {
			Namespace string `json:"namespace,omitempty"`
			FixState  string `json:"fix_state,omitempty"`
		} `json:"vulnerability,omitempty"`
		Package struct {
			Language string `json:"language,omitempty"`
			Type     string `json:"type,omitempty"`
			Name     string `json:"name,omitempty"`
			Version  string `json:"version,omitempty"`
			Location string `json:"location,omitempty"`
		} `json:"package,omitempty"`
	} `json:"constraints,omitempty"`
	Justification string `json:"justification"`
}

func (m MatchExclusion) IsEmpty() bool {
	return m.ID == ""
}

func MatchExclusions(reader io.Reader) ([]MatchExclusion, error) {
	return unmarshalSingleOrMulti[MatchExclusion](reader)
}
