package qualifier

import (
	"encoding/json"

	"github.com/mitchellh/mapstructure"

	"github.com/anchore/grype/grype/db/v5/pkg/qualifier/platformcpe"
	"github.com/anchore/grype/grype/db/v5/pkg/qualifier/rpmmodularity"
	"github.com/anchore/grype/internal/log"
)

func FromJSON(data []byte) ([]Qualifier, error) {
	var records []map[string]interface{}
	if err := json.Unmarshal(data, &records); err != nil {
		return nil, err
	}

	var qualifiers []Qualifier

	for _, r := range records {
		k, ok := r["kind"]

		if !ok {
			log.Warn("Skipping qualifier with no kind specified")
			continue
		}

		// create the specific kind of Qualifier
		switch k {
		case "rpm-modularity":
			var q rpmmodularity.Qualifier
			if err := mapstructure.Decode(r, &q); err != nil {
				log.Warn("Error decoding rpm-modularity package qualifier:  (%v)", err)
				continue
			}
			qualifiers = append(qualifiers, q)
		case "platform-cpe":
			var q platformcpe.Qualifier
			if err := mapstructure.Decode(r, &q); err != nil {
				log.Warn("Error decoding platform-cpe package qualifier:  (%v)", err)
				continue
			}
			qualifiers = append(qualifiers, q)
		default:
			log.Debug("Skipping unsupported package qualifier: %s", k)
			continue
		}
	}

	return qualifiers, nil
}
