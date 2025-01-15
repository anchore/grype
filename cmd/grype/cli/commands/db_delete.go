package commands

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/grype/cmd/grype/cli/options"
	legacyDistribution "github.com/anchore/grype/grype/db/legacy/distribution"
	"github.com/anchore/grype/grype/db/v6/distribution"
	"github.com/anchore/grype/grype/db/v6/installation"
)

func DBDelete(app clio.Application) *cobra.Command {
	opts := dbOptionsDefault(app.ID())

	cmd := &cobra.Command{
		Use:     "delete",
		Short:   "Delete the vulnerability database",
		Args:    cobra.ExactArgs(0),
		PreRunE: disableUI(app),
		RunE: func(_ *cobra.Command, _ []string) error {
			return runDBDelete(*opts)
		},
	}

	// prevent from being shown in the grype config
	type configWrapper struct {
		*DBOptions `yaml:",inline" mapstructure:",squash"`
	}

	return app.SetupCommand(cmd, &configWrapper{opts})
}

func runDBDelete(opts DBOptions) error {
	if opts.Experimental.DBv6 {
		return newDBDelete(opts.DB)
	}
	return legacyDBDelete(opts.DB)
}

func newDBDelete(opts options.Database) error {
	client, err := distribution.NewClient(opts.ToClientConfig())
	if err != nil {
		return fmt.Errorf("unable to create distribution client: %w", err)
	}
	c, err := installation.NewCurator(opts.ToCuratorConfig(), client)
	if err != nil {
		return fmt.Errorf("unable to create curator: %w", err)
	}

	if err := c.Delete(); err != nil {
		return fmt.Errorf("unable to delete vulnerability database: %+v", err)
	}

	return stderrPrintLnf("Vulnerability database deleted")
}

func legacyDBDelete(opts options.Database) error {
	dbCurator, err := legacyDistribution.NewCurator(opts.ToLegacyCuratorConfig())
	if err != nil {
		return err
	}
	if err := dbCurator.Delete(); err != nil {
		return fmt.Errorf("unable to delete vulnerability database: %+v", err)
	}

	return stderrPrintLnf("Vulnerability database deleted")
}
