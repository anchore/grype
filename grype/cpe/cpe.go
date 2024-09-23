package cpe

import (
	"github.com/facebookincubator/nvdtools/wfn"

	"github.com/anchore/grype/internal/log"
	"github.com/anchore/syft/syft/cpe"
)

func NewSlice(cpeStrs ...string) ([]cpe.CPE, error) {
	var cpes []cpe.CPE
	for _, c := range cpeStrs {
		value, err := cpe.New(c, "")
		if err != nil {
			log.Warnf("excluding invalid CPE %q: %v", c, err)
			continue
		}

		cpes = append(cpes, value)
	}
	return cpes, nil
}

func MatchWithoutVersion(c cpe.CPE, candidates []cpe.CPE) []cpe.CPE {
	matches := make([]cpe.CPE, 0)
	a := wfn.Attributes(c.Attributes)
	a.Update = wfn.Any
	for _, candidate := range candidates {
		canCopy := wfn.Attributes(candidate.Attributes)
		canCopy.Update = wfn.Any
		if a.MatchWithoutVersion(&canCopy) {
			matches = append(matches, candidate)
		}
	}
	return matches
}
