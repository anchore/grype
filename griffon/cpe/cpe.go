package cpe

import (
	"github.com/anchore/syft/syft/cpe"
	"github.com/nextlinux/griffon/internal/log"
)

func NewSlice(cpeStrs ...string) ([]cpe.CPE, error) {
	var cpes []cpe.CPE
	for _, c := range cpeStrs {
		value, err := cpe.New(c)
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
	for _, candidate := range candidates {
		canCopy := candidate
		if c.MatchWithoutVersion(&canCopy) {
			matches = append(matches, candidate)
		}
	}
	return matches
}
