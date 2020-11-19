package cpe

import (
	"github.com/anchore/syft/syft/pkg"
)

func NewSlice(cpeStrs ...string) ([]pkg.CPE, error) {
	ret := make([]pkg.CPE, len(cpeStrs))
	for idx, c := range cpeStrs {
		value, err := pkg.NewCPE(c)
		if err != nil {
			return nil, err
		}
		ret[idx] = value
	}
	return ret, nil
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
