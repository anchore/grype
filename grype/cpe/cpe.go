package cpe

import (
	"github.com/anchore/grype/internal/log"
	"github.com/anchore/syft/syft/pkg"
)

func NewSlice(cpeStrs ...string) ([]pkg.CPE, error) {
	var cpes []pkg.CPE
	for _, c := range cpeStrs {
		value, err := pkg.NewCPE(c)
		if err != nil {
			log.Warnf("unable to hydrate CPE for string %q, omitting from result CPE slice: %v", c, err)
			continue
		}

		cpes = append(cpes, value)
	}
	return cpes, nil
}

func MatchWithoutVersion(c pkg.CPE, candidates []pkg.CPE) []pkg.CPE {
	matches := make([]pkg.CPE, 0)
	for _, candidate := range candidates {
		canCopy := candidate
		if c.MatchWithoutVersion(&canCopy) {
			matches = append(matches, candidate)
		}
	}
	return matches
}
