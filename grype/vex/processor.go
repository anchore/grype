package vex

import (
	"fmt"

	gopenvex "github.com/openvex/go-vex/pkg/vex"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vex/openvex"
)

type Status string

const (
	StatusNotAffected        Status = Status(gopenvex.StatusNotAffected)
	StatusAffected           Status = Status(gopenvex.StatusAffected)
	StatusFixed              Status = Status(gopenvex.StatusFixed)
	StatusUnderInvestigation Status = Status(gopenvex.StatusUnderInvestigation)
)

type Processor struct {
	Options ProcessorOptions
	impl    vexProcessorImplementation
}

type vexProcessorImplementation interface {
	// ReadVexDocuments takes a list of vex filenames and returns a single
	// value representing the VEX information in the underlying implementation's
	// format. Returns an error if the files cannot be processed.
	ReadVexDocuments(docs []string) (interface{}, error)

	// FilterMatches matches receives the underlying VEX implementation VEX data and
	// the scanning context and matching results and filters the fixed and
	// not_affected results,moving them to the list of ignored matches.
	FilterMatches(interface{}, []match.IgnoreRule, *pkg.Context, *match.Matches, []match.IgnoredMatch) (*match.Matches, []match.IgnoredMatch, error)

	// AugmentMatches reads known affected VEX products from loaded documents and
	// adds new results to the scanner results when the product is marked as
	// affected in the VEX data.
	AugmentMatches(interface{}, []match.IgnoreRule, *pkg.Context, *match.Matches, []match.IgnoredMatch) (*match.Matches, []match.IgnoredMatch, error)
}

// getVexImplementation this function returns the vex processor implementation
// at some point it can read the options and choose a user configured implementation.
func getVexImplementation() vexProcessorImplementation {
	return openvex.New()
}

// NewProcessor returns a new VEX processor. For now, it defaults to the only vex
// implementation: OpenVEX
func NewProcessor(opts ProcessorOptions) *Processor {
	return &Processor{
		Options: opts,
		impl:    getVexImplementation(),
	}
}

// ProcessorOptions captures the optiones of the VEX processor.
type ProcessorOptions struct {
	Documents   []string
	IgnoreRules []match.IgnoreRule
}

// ApplyVEX receives the results from a scan run and applies any VEX information
// in the files specified in the grype invocation. Any filtered results will
// be moved to the ignored matches slice.
func (vm *Processor) ApplyVEX(pkgContext *pkg.Context, remainingMatches *match.Matches, ignoredMatches []match.IgnoredMatch) (*match.Matches, []match.IgnoredMatch, error) {
	var err error

	// If no VEX documents are loaded, just pass through the matches, effectivle NOOP
	if len(vm.Options.Documents) == 0 {
		return remainingMatches, ignoredMatches, nil
	}

	// Read VEX data from all passed documents
	rawVexData, err := vm.impl.ReadVexDocuments(vm.Options.Documents)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing vex document: %w", err)
	}

	vexRules := extractVexRules(vm.Options.IgnoreRules)

	remainingMatches, ignoredMatches, err = vm.impl.FilterMatches(
		rawVexData, vexRules, pkgContext, remainingMatches, ignoredMatches,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("checking matches against VEX data: %w", err)
	}

	remainingMatches, ignoredMatches, err = vm.impl.AugmentMatches(
		rawVexData, vexRules, pkgContext, remainingMatches, ignoredMatches,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("checking matches to augment from VEX data: %w", err)
	}

	return remainingMatches, ignoredMatches, nil
}

// extractVexRules is a utility function that takes a set of ignore rules and
// extracts those that act on VEX statuses.
func extractVexRules(rules []match.IgnoreRule) []match.IgnoreRule {
	newRules := []match.IgnoreRule{}
	for _, r := range rules {
		if r.VexStatus != "" {
			newRules = append(newRules, r)
			newRules[len(newRules)-1].Namespace = "vex"
		}
	}
	return newRules
}
