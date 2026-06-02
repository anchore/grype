package commands

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/grype/cmd/grype/cli/options"
	"github.com/anchore/grype/grype/db"
	dbprovider "github.com/anchore/grype/grype/db/provider"
)

// DBBuilderBuild writes a SQLite vulnerability database from on-disk
// provider workspace data. It assumes 'db-builder pull' has already
// populated the workspace; no vunnel processes are spawned by this command.
func DBBuilderBuild(app clio.Application) *cobra.Command {
	opts := options.DefaultDatabaseBuild()

	cmd := &cobra.Command{
		Use:   "build",
		Short: "Write a vulnerability database from provider workspace data",
		Long: `Read on-disk provider workspace data (typically populated by
'grype db-builder pull') and write a SQLite vulnerability database into
--dir. Does not produce an archive; use 'grype db-builder package' for that.`,
		Args: cobra.NoArgs,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return disableUI(app)(cmd, args)
		},
		RunE: func(_ *cobra.Command, _ []string) error {
			return runDBBuilderBuild(opts)
		},
	}

	return app.SetupCommand(cmd, &dbBuilderConfigWrapper{DBBuilder: opts})
}

func runDBBuilderBuild(opts *options.DatabaseBuild) error {
	if err := validateCPEParts(opts.IncludeCPEParts); err != nil {
		return err
	}

	pvdrs, err := buildProviders(opts)
	if err != nil {
		return err
	}

	if _, err := os.Stat(opts.Dir); os.IsNotExist(err) {
		if err := os.MkdirAll(opts.Dir, 0755); err != nil {
			return fmt.Errorf("unable to make db build dir: %w", err)
		}
	}

	states, err := providerStates(opts.SkipValidation, pvdrs)
	if err != nil {
		return fmt.Errorf("unable to get provider states: %w", err)
	}

	earliest, err := dbprovider.States(states).EarliestTimestamp()
	if err != nil {
		return fmt.Errorf("unable to get earliest timestamp: %w", err)
	}

	return db.Build(db.BuildConfig{
		SchemaVersion:        opts.SchemaVersion,
		Directory:            opts.Dir,
		States:               states,
		Timestamp:            earliest,
		IncludeCPEParts:      opts.IncludeCPEParts,
		InferNVDFixVersions:  opts.InferNVDFixVersions,
		Hydrate:              opts.Hydrate,
		FailOnMissingFixDate: opts.FailOnMissingFixDate,
		BatchSize:            opts.BatchSize,
	})
}
