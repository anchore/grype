package commands

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/grype/cmd/grype/cli/options"
	"github.com/anchore/grype/grype/db/build/pull"
	dbprovider "github.com/anchore/grype/grype/db/provider"
)

// DBBuilderPull runs vulnerability providers (via the vunnel runner, by
// default) to refresh on-disk workspace data. This is the per-provider step
// in the CI scatter flow — it does not touch the SQLite DB.
func DBBuilderPull(app clio.Application) *cobra.Command {
	opts := options.DefaultDatabaseBuild()

	cmd := &cobra.Command{
		Use:   "pull",
		Short: "Refresh vulnerability provider workspace data",
		Long: `Run one or more vulnerability providers (vunnel by default) to refresh the
on-disk workspace under provider.root. This is the per-provider step that
fans out across the data-sync matrix; it does not produce or modify a
database.

Examples:

  grype db-builder pull -p alpine          # refresh just the alpine provider
  grype db-builder pull -p alpine,alma     # refresh two providers
  grype db-builder pull -g                 # enumerate providers via 'vunnel list'`,
		Args: cobra.NoArgs,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return disableUI(app)(cmd, args)
		},
		RunE: func(_ *cobra.Command, _ []string) error {
			return runDBBuilderPull(opts)
		},
	}

	return app.SetupCommand(cmd, &dbBuilderConfigWrapper{DBBuilder: opts})
}

func runDBBuilderPull(opts *options.DatabaseBuild) error {
	pvdrs, err := buildProviders(opts)
	if err != nil {
		return err
	}

	if err := pull.Pull(pull.Config{
		Parallelism: opts.Pull.Parallelism,
		Collection: dbprovider.Collection{
			Root:      opts.Provider.Root,
			Providers: pvdrs,
		},
	}); err != nil {
		return fmt.Errorf("pull failed: %w", err)
	}
	return nil
}
