package match

import (
	"github.com/nextlinux/griffon/griffon/pkg"
)

const (
	ExactDirectMatch   Type = "exact-direct-match"
	ExactIndirectMatch Type = "exact-indirect-match"
	CPEMatch           Type = "cpe-match"
)

type Type string

func ConvertToIndirectMatches(matches []Match, p pkg.Package) {
	for idx := range matches {
		for dIdx := range matches[idx].Details {
			// only override the match details to "indirect" if the match details are explicitly indicate a "direct" match
			if matches[idx].Details[dIdx].Type == ExactDirectMatch {
				matches[idx].Details[dIdx].Type = ExactIndirectMatch
			}
		}
		// we always override the package to the direct package
		matches[idx].Package = p
	}
}
