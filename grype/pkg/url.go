package pkg

import (
	"github.com/anchore/grype/internal/log"
	"github.com/anchore/packageurl-go"
)

const (
	purlEpochQualifier = "epoch"

	// this qualifier is not in the pURL spec, but is encoded by syft to inform indirect matching based on source information in grype
	purlUpstreamQualifier = "upstream"
)

func getPURLQualifiers(p string) map[string]string {
	if p == "" {
		return make(map[string]string, 0)
	}

	purl, err := packageurl.FromString(p)
	if err != nil {
		log.Warnf("unable to decode pURL: %+v", err)
		return make(map[string]string, 0)
	}

	return purl.Qualifiers.Map()
}
