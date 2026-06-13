package rapidfort

import (
	"strings"

	"github.com/anchore/syft/syft/source"
)

const maintainerLabel = "maintainer"

// rapidFortMaintainerPrefix is the case-insensitive prefix used by all RapidFort
// maintainer label values (e.g. "RapidFort Curation Team <rfcurators@rapidfort.com>").
const rapidFortMaintainerPrefix = "rapidfort"

// IsRapidFortImage returns true when the source is a container image whose
// "maintainer" label starts with "RapidFort" (case-insensitive) — the indicator
// that it is a RapidFort-curated image and should be scanned against RF advisories.
func IsRapidFortImage(src *source.Description) bool {
	if src == nil {
		return false
	}
	meta, ok := src.Metadata.(source.ImageMetadata)
	if !ok {
		return false
	}
	for k, v := range meta.Labels {
		if strings.EqualFold(k, maintainerLabel) && strings.HasPrefix(strings.ToLower(v), rapidFortMaintainerPrefix) {
			return true
		}
	}
	return false
}
