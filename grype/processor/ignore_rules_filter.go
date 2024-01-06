package processor

import (
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/internal/log"
)

var _ match.Processor = (*ignoreRuleAugmenter)(nil)

type ignoreRuleAugmenter struct {
	IgnoreRules []match.IgnoreRule
}

func NewIgnoreRuleAugmenter(ignoreRules []match.IgnoreRule) match.Processor {
	return ignoreRuleAugmenter{
		IgnoreRules: ignoreRules,
	}
}

func (a ignoreRuleAugmenter) ProcessMatches(_ pkg.Context, matches match.Matches, ignoredMatches []match.IgnoredMatch) (match.Matches, []match.IgnoredMatch, error) {
	if len(a.IgnoreRules) == 0 {
		return matches, ignoredMatches, nil
	}

	matches, ignoredMatches = match.ApplyIgnoreRules(matches, a.IgnoreRules)

	if count := len(ignoredMatches); count > 0 {
		log.Infof("ignoring %d matches due to user-provided ignore rules", count)
	}
	return matches, ignoredMatches, nil
}
