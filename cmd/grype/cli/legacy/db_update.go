package legacy

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/anchore/grype/cmd/grype/internal/ui"
	"github.com/anchore/grype/grype/db"
	"github.com/anchore/grype/internal/bus"
	"github.com/anchore/stereoscope"
)

var dbUpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "download the latest vulnerability database",
	Args:  cobra.ExactArgs(0),
	RunE:  runDBUpdateCmd,
}

func init() {
	dbCmd.AddCommand(dbUpdateCmd)
}

func startDBUpdateCmd() <-chan error {
	errs := make(chan error)
	go func() {
		defer close(errs)
		defer bus.Exit()

		dbCurator, err := db.NewCurator(appConfig.DB.ToCuratorConfig())
		if err != nil {
			errs <- err
			return
		}
		updated, err := dbCurator.Update()
		if err != nil {
			errs <- fmt.Errorf("unable to update vulnerability database: %+v", err)
		}

		result := "No vulnerability database update available\n"
		if updated {
			result = "Vulnerability database updated to latest version!\n"
		}

		bus.Report(result)
	}()
	return errs
}

func runDBUpdateCmd(_ *cobra.Command, _ []string) error {
	return eventLoop(
		startDBUpdateCmd(),
		setupSignals(),
		eventSubscription,
		stereoscope.Cleanup,
		ui.Select(isVerbose(), appConfig.Quiet)...,
	)
}
