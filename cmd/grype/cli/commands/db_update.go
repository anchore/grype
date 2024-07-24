package commands

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/grype/cmd/grype/cli/options"
	"github.com/anchore/grype/grype/db"
	"github.com/anchore/grype/internal/bus"
	"github.com/anchore/grype/internal/log"
)

func DBUpdate(app clio.Application) *cobra.Command {
	opts := dbOptionsDefault(app.ID())

	return app.SetupCommand(&cobra.Command{
		Use:   "update",
		Short: "download the latest vulnerability database",
		Args:  cobra.ExactArgs(0),
		PreRunE: func(_ *cobra.Command, _ []string) error {
			// `grype db update` should _always_ check for updates, regardless of config
			opts.DB.MinAgeToCheckForUpdate = 0
			return nil
		},
		RunE: func(_ *cobra.Command, _ []string) error {
			return runDBUpdate(opts.DB)
		},
	}, opts)
}

func runDBUpdate(opts options.Database) error {
	dbCurator, err := db.NewCurator(opts.ToCuratorConfig())
	if err != nil {
		return err
	}
	updated, err := dbCurator.Update()
	if err != nil {
		return fmt.Errorf("unable to update vulnerability database: %+v", err)
	}

	result := "No vulnerability database update available\n"
	if updated {
		result = "Vulnerability database updated to latest version!\n"
	}

	log.Debugf("completed db update check with result: %s", result)

	bus.Report(result)

	return nil
}
