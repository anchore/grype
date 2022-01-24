package pkg

import (
	"github.com/anchore/grype/internal/log"
	"strconv"
)

type RpmdbMetadata struct {
	SourceRpm string
	Epoch     *int
}

func rpmdbMetadataFromPURL(p string) *RpmdbMetadata {
	qualifiers := getPURLQualifiers(p)
	upstream := qualifiers[purlUpstreamQualifier]
	epoch := qualifiers[purlEpochQualifier]

	var epochInt *int
	if epoch != "" {
		value, err := strconv.Atoi(epoch)
		if err != nil {
			log.Warnf("unable to parse rpm epoch=%q: %+v")
		} else {
			epochInt = &value
		}
	}

	if upstream == "" && epochInt == nil {
		return nil
	}

	return &RpmdbMetadata{
		SourceRpm: upstream,
		Epoch:     epochInt,
	}
}
