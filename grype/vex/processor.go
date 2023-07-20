package vex

import (
	"fmt"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vex/openvex"
)

type Processor struct {
	Options ProcessorOptions
	impl    vexProcessorImplementation
}

type vexProcessorImplementation interface {
	// Read ReadVexDocuments takes a list of vex filenames and returns a single
	// value representing the VEX information in the underlying implementation's
	// format. Returns an error if the files cannot be processed.
	ReadVexDocuments(docs []string) (interface{}, error)

	// Filter matches receives the underlying VEX implementation VEX data and
	// the scanning context and matching results and filters the fixed and
	// not_affected results,moving them to the list of ignored matches.
	FilterMatches(interface{}, *pkg.Context, *match.Matches, []match.IgnoredMatch) (*match.Matches, []match.IgnoredMatch, error)
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
	Documents []string
	Context   pkg.Context
}

// ApplyVEX receives the results from a scan run and applies any VEX information
// in the files specified in the grype invocation. Any filtered results will
// be moved to the ignored matches slice.
func (vm *Processor) ApplyVEX(pkgContext pkg.Context, remainingMatches *match.Matches, ignoredMatches []match.IgnoredMatch) (*match.Matches, []match.IgnoredMatch, error) {
	var err error

	// If no VEX documents are loaded, just pass through the matches, effectivle NOOP
	if len(vm.Options.Documents) == 0 {
		return remainingMatches, ignoredMatches, nil
	}

	// Merge all files into a single OpenVEX doc
	doc, err := vm.impl.ReadVexDocuments(vm.Options.Documents)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing vex document: %w", err)
	}

	remainingMatches, ignoredMatches, err = vm.impl.FilterMatches(
		doc, &vm.Options.Context, remainingMatches, ignoredMatches,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("checking matches against VEX data: %w", err)
	}

	return remainingMatches, ignoredMatches, nil
}
