package processor

import (
	"fmt"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/store"
	"github.com/anchore/grype/grype/vex"
	"github.com/anchore/grype/internal/log"
)

var _ match.Processor = (*VexProcessor)(nil)

type VexProcessor struct {
	store store.Store
	proc  *vex.Processor
}

func NewVexProcessor(s store.Store, options vex.ProcessorOptions) match.Processor {
	if len(options.Documents) == 0 {
		return nil
	}

	return VexProcessor{
		store: s,
		proc:  vex.NewProcessor(options),
	}
}

func (v VexProcessor) ProcessMatches(context pkg.Context, matches match.Matches, ignoredMatches []match.IgnoredMatch) (match.Matches, []match.IgnoredMatch, error) {
	if v.proc == nil {
		return matches, ignoredMatches, nil
	}

	if v.proc == nil {
		log.Trace("no VEX documents provided, skipping VEX matching")
		return matches, ignoredMatches, nil
	}

	log.Trace("finding matches against available VEX documents")
	matchesAfterVex, ignoredMatchesAfterVex, err := v.proc.ApplyVEX(&context, &matches, ignoredMatches)
	if err != nil {
		return matches, ignoredMatches, fmt.Errorf("unable to find matches against VEX documents: %w", err)
	}

	// TODO: restore in caller
	//diffMatches := matchesAfterVex.Diff(matches)
	//// note: this assumes that the diff can only be additive
	//diffIgnoredMatches := ignoredMatchesDiff(ignoredMatchesAfterVex, ignoredMatches)
	//
	//updateVulnerabilityList(progressMonitor, diffMatches.Sorted(), diffIgnoredMatches, nil, v.store)

	return *matchesAfterVex, ignoredMatchesAfterVex, nil
}

//func ignoredMatchesDiff(subject []match.IgnoredMatch, other []match.IgnoredMatch) []match.IgnoredMatch {
//	// TODO(alex): the downside with this implementation is that it does not account for the same ignored match being
//	// ignored for different reasons (the appliedIgnoreRules field).
//
//	otherMap := make(map[match.Fingerprint]struct{})
//	for _, a := range other {
//		otherMap[a.Match.Fingerprint()] = struct{}{}
//	}
//
//	var diff []match.IgnoredMatch
//	for _, b := range subject {
//		if _, ok := otherMap[b.Match.Fingerprint()]; !ok {
//			diff = append(diff, b)
//		}
//	}
//
//	return diff
//}
