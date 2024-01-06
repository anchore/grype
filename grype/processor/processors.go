package processor

import (
	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/store"
	"github.com/anchore/grype/grype/vex"
	"github.com/hashicorp/go-multierror"
)

type Config struct {
	NormalizeByCVE bool
	IgnoreRules    []match.IgnoreRule
	VexDocuments   []string
}

func DefaultProcessors(cfg Config, s store.Store, d *distro.Distro, pkgs []pkg.Package) ([]match.Processor, error) {
	var err error

	addWithError := func(p match.Processor, e error) match.Processor {
		if e != nil {
			err = multierror.Append(err, e)
		}
		return p
	}

	procs := []match.Processor{
		NewMatchLogger(),
		NewIDNormalizer(s, cfg.NormalizeByCVE),
		NewMatchExclusionFilter(s),
		NewIgnoreRuleAugmenter(cfg.IgnoreRules),
		addWithError(NewAPKNakFilter(s, d, pkgs)),
		NewVexProcessor(s, vex.ProcessorOptions{
			Documents:   cfg.VexDocuments,
			IgnoreRules: cfg.IgnoreRules,
		}),
	}

	if err != nil {
		return nil, err
	}

	return procs, nil
}
