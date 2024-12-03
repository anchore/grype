package options

import (
	"fmt"
	"time"

	"github.com/araddon/dateparse"

	"github.com/anchore/clio"
	v6 "github.com/anchore/grype/grype/db/v6"
)

type DBSearchVulnerabilities struct {
	VulnerabilityIDs []string `yaml:"vulnerability-ids" json:"vulnerability-ids" mapstructure:"vulnerability-ids"`
	UseVulnIDFlag    bool     `yaml:"-" json:"-" mapstructure:"-"`

	PublishedAfter string `yaml:"published-after" json:"published-after" mapstructure:"published-after"`
	ModifiedAfter  string `yaml:"modified-after" json:"modified-after" mapstructure:"modified-after"`

	Providers []string `yaml:"providers" json:"providers" mapstructure:"providers"`

	Specs v6.VulnerabilitySpecifiers `yaml:"-" json:"-" mapstructure:"-"`
}

func (c *DBSearchVulnerabilities) AddFlags(flags clio.FlagSet) {
	if c.UseVulnIDFlag {
		flags.StringArrayVarP(&c.VulnerabilityIDs, "vuln", "", "only show results for the given vulnerability ID (supports DB schema v6+ only)")
	}
	flags.StringVarP(&c.PublishedAfter, "published-after", "", "only show vulnerabilities originally published after the given date (format: YYYY-MM-DD) (supports DB schema v6+ only)")
	flags.StringVarP(&c.ModifiedAfter, "modified-after", "", "only show vulnerabilities originally published or modified since the given date (format: YYYY-MM-DD) (supports DB schema v6+ only)")
	flags.StringArrayVarP(&c.Providers, "provider", "", "only show vulnerabilities from the given provider (supports DB schema v6+ only)")
}

func (c *DBSearchVulnerabilities) PostLoad() error {
	// note: this may be called multiple times, so we need to reset the specs each time
	c.Specs = nil

	handleTimeOption := func(val string, flag string) (*time.Time, error) {
		if val == "" {
			return nil, nil
		}
		parsed, err := dateparse.ParseIn(val, time.UTC)
		if err != nil {
			return nil, fmt.Errorf("invalid date format for %s=%q: %w", flag, val, err)
		}
		return &parsed, nil
	}

	if c.PublishedAfter != "" && c.ModifiedAfter != "" {
		return fmt.Errorf("only one of --published-after or --modified-after can be set")
	}

	var publishedAfter, modifiedAfter *time.Time
	var err error
	publishedAfter, err = handleTimeOption(c.PublishedAfter, "published-after")
	if err != nil {
		return fmt.Errorf("invalid date format for published-after field: %w", err)
	}
	modifiedAfter, err = handleTimeOption(c.ModifiedAfter, "modified-after")
	if err != nil {
		return fmt.Errorf("invalid date format for modified-after field: %w", err)
	}

	var specs []v6.VulnerabilitySpecifier
	for _, vulnID := range c.VulnerabilityIDs {
		specs = append(specs, v6.VulnerabilitySpecifier{
			Name:           vulnID,
			PublishedAfter: publishedAfter,
			ModifiedAfter:  modifiedAfter,
			Providers:      c.Providers,
		})
	}

	if len(specs) == 0 {
		if c.PublishedAfter != "" || c.ModifiedAfter != "" || len(c.Providers) > 0 {
			specs = append(specs, v6.VulnerabilitySpecifier{
				PublishedAfter: publishedAfter,
				ModifiedAfter:  modifiedAfter,
				Providers:      c.Providers,
			})
		}
	}

	c.Specs = specs

	return nil
}
