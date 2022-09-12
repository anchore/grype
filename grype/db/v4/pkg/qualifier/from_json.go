package qualifier

import (
	"encoding/json"
	"github.com/anchore/grype/grype/db/v4/pkg/qualifier/rpmmodularity"
	"github.com/anchore/grype/internal/log"
	"github.com/mitchellh/mapstructure"
)

func FromJSON(data []byte) ([]Qualifier, error) {
	var records []map[string]interface{}
	if err := json.Unmarshal(data, &records); err != nil {
		return nil, err
	}

	var qualifiers []Qualifier

	for _, r := range records {
		if k, ok := r["kind"]; ok {
			// create the specific kind of Qualifier
			switch k {
			case "rpm-modularity":
				var q rpmmodularity.Qualifier
				if err := mapstructure.Decode(r, &q); err != nil {
					log.Warn("Error decoding rpm-modularity package qualifier:  (%v)", err)
					continue
				}
				qualifiers = append(qualifiers, q)
			default:
				log.Warn("Skipping unsupported package qualifier: %s", k)
				continue
			}
		}
	}

	return qualifiers, nil
}
