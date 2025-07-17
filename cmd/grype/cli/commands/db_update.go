package commands

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/grype/cmd/grype/cli/options"
	"github.com/anchore/grype/grype/db/v6/distribution"
	"github.com/anchore/grype/grype/db/v6/installation"
	"github.com/anchore/grype/internal/bus"
	"github.com/anchore/grype/internal/log"
)

func DBUpdate(app clio.Application) *cobra.Command {
	opts := options.DefaultDatabaseCommand(app.ID())

	cmd := &cobra.Command{
		Use:   "update",
		Short: "Download and install the latest vulnerability database",
		Args:  cobra.ExactArgs(0),
		PreRunE: func(_ *cobra.Command, _ []string) error {
			// DB commands should not opt into the low-pass check filter
			opts.DB.MaxUpdateCheckFrequency = 0
			return nil
		},
		RunE: func(_ *cobra.Command, _ []string) error {
			return runDBUpdate(*opts)
		},
	}

	// prevent from being shown in the grype config
	type configWrapper struct {
		*options.DatabaseCommand `yaml:",inline" mapstructure:",squash"`
	}

	return app.SetupCommand(cmd, &configWrapper{opts})
}

func runDBUpdate(opts options.DatabaseCommand) error {
	cfg := opts.ToClientConfig()
	// we need to have this set to true to force the update call to try to update
	// regardless of what the user provided in order for update checks to fail
	if !cfg.RequireUpdateCheck {
		log.Warn("overriding db update check")
		cfg.RequireUpdateCheck = true
	}
	client, err := distribution.NewClient(cfg)
	if err != nil {
		return fmt.Errorf("unable to create distribution client: %w", err)
	}
	c, err := installation.NewCurator(opts.ToCuratorConfig(), client)
	if err != nil {
		return fmt.Errorf("unable to create curator: %w", err)
	}

	updated, err := c.Update()
	if err != nil {
		return fmt.Errorf("unable to update vulnerability database: %w", err)
	}

	result := "No vulnerability database update available\n"
	if updated {
		result = "Vulnerability database updated to latest version!\n"
	}

	log.Debugf("completed db update check with result: %s", result)

	bus.Report(result)

	return nil
}
