package vex

import (
	"context"
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
	loaded  bool
}

type vexProcessorImplementation interface {
	// ReadVexDocuments takes a list of vex filenames and returns a single
	// value representing the VEX information in the underlying implementation's
	// format. Returns an error if the files cannot be processed.
	ReadVexDocuments(docs []string) error

	// DiscoverVexDocuments calls asks vex driver to find documents associated
	// to the scanned object. Autodiscovered documents are added to any that
	// are specified in the command line
	DiscoverVexDocuments(context.Context, pkg.Context) error

	// FilterMatches matches receives the underlying VEX implementation VEX data and
	// the scanning context and matching results and filters the fixed and
	// not_affected results,moving them to the list of ignored matches.
	FilterMatches([]match.IgnoreRule, pkg.Context, *match.Matches, []match.IgnoredMatch) (*match.Matches, []match.IgnoredMatch, error)

	// AugmentMatches reads known affected VEX products from loaded documents and
	// adds new results to the scanner results when the product is marked as
	// affected in the VEX data.
	AugmentMatches([]match.IgnoreRule, pkg.Context, *match.Matches, []match.IgnoredMatch) (*match.Matches, []match.IgnoredMatch, error)
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
	// Documents is a list of paths of VEX documents to consider when computing matches
	Documents []string

	// Autodiscover will attempt to autodetect VEX documents when set to true
	Autodiscover bool

	// Configured ignore rules
	IgnoreRules []match.IgnoreRule
}

func (vm *Processor) LoadVEXDocuments(ctx context.Context, pkgContext pkg.Context) error {
	if vm == nil {
		return nil
	}

	defer func() {
		vm.loaded = true
	}()

	// read VEX data from all passed documents
	if len(vm.Options.Documents) > 0 {
		err := vm.impl.ReadVexDocuments(vm.Options.Documents)
		if err != nil {
			return fmt.Errorf("parsing vex document: %w", err)
		}
	}

	// if VEX autodiscover is enabled, run call the implementation's discovery
	// function to augment the known VEX data
	if vm.Options.Autodiscover {
		err := vm.impl.DiscoverVexDocuments(ctx, pkgContext)
		if err != nil {
			return fmt.Errorf("probing for VEX data: %w", err)
		}
	}

	return nil
}

// ApplyVEX receives the results from a scan run and applies any VEX information
// in the files specified in the grype invocation. Any filtered results will
// be moved to the ignored matches slice.
func (vm *Processor) ApplyVEX(pkgContext pkg.Context, remainingMatches *match.Matches, ignoredMatches []match.IgnoredMatch) (*match.Matches, []match.IgnoredMatch, error) {
	var err error

	if !vm.loaded {
		return nil, nil, fmt.Errorf("never attempted to load VEX data")
	}

	// If no VEX documents are loaded, just pass through the matches, effectively NOOP
	if len(vm.Options.Documents) == 0 && !vm.Options.Autodiscover {
		return remainingMatches, ignoredMatches, nil
	}

	vexRules := extractVexRules(vm.Options.IgnoreRules)

	remainingMatches, ignoredMatches, err = vm.impl.FilterMatches(
		vexRules, pkgContext, remainingMatches, ignoredMatches,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to filter matches against VEX data: %w", err)
	}

	remainingMatches, ignoredMatches, err = vm.impl.AugmentMatches(
		vexRules, pkgContext, remainingMatches, ignoredMatches,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to augment matches with VEX data: %w", err)
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
