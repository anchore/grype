package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/anchore/grype/grype/db"
	"github.com/anchore/grype/grype/differ"
	"github.com/anchore/grype/internal/bus"
	"github.com/anchore/grype/internal/log"
	"github.com/anchore/grype/internal/ui"
	"github.com/anchore/stereoscope"
)

var dbDiffOutputFormat string

const deleteFlag string = "delete"

var dbDiffCmd = &cobra.Command{
	Use:   "diff [flags] base_db_url target_db_url",
	Short: "diff two DBs and display the result",
	Args:  cobra.MaximumNArgs(2),
	RunE:  runDBDiffCmd,
}

func init() {
	dbDiffCmd.Flags().StringVarP(&dbDiffOutputFormat, "output", "o", "table", "format to display results (available=[table, json])")
	dbDiffCmd.Flags().BoolP(deleteFlag, "d", false, "delete downloaded databases after diff occurs")

	dbCmd.AddCommand(dbDiffCmd)
}

func startDBDiffCmd(base string, target string, deleteDatabases bool) <-chan error {
	errs := make(chan error)
	go func() {
		defer close(errs)
		defer bus.Exit()
		d, err := differ.NewDiffer(appConfig.DB.ToCuratorConfig())
		if err != nil {
			errs <- err
			return
		}

		if err := d.SetBaseDB(base); err != nil {
			errs <- err
			return
		}

		if err := d.SetTargetDB(target); err != nil {
			errs <- err
			return
		}

		diff, err := d.DiffDatabases()
		if err != nil {
			errs <- err
			return
		}

		if len(*diff) == 0 {
			fmt.Println("Databases are identical!")
		} else {
			err := d.Present(dbDiffOutputFormat, diff, os.Stdout)
			if err != nil {
				errs <- err
			}
		}

		if deleteDatabases {
			errs <- d.DeleteDatabases()
		}
	}()
	return errs
}

func runDBDiffCmd(cmd *cobra.Command, args []string) error {
	reporter, closer, err := reportWriter()
	defer func() {
		if err := closer(); err != nil {
			log.Warnf("unable to write to report destination: %+v", err)
		}
	}()
	if err != nil {
		return err
	}

	deleteDatabases, err := cmd.Flags().GetBool(deleteFlag)
	if err != nil {
		return err
	}

	var base, target string

	switch len(args) {
	case 0:
		log.Info("base_db_url and target_db_url not provided; fetching most recent")
		base, target, err = getDefaultURLs()
		if err != nil {
			return err
		}
	case 1:
		log.Info("target_db_url not provided; fetching most recent")
		base = args[0]
		_, target, err = getDefaultURLs()
		if err != nil {
			return err
		}
	default:
		base = args[0]
		target = args[1]
	}

	return eventLoop(
		startDBDiffCmd(base, target, deleteDatabases),
		setupSignals(),
		eventSubscription,
		stereoscope.Cleanup,
		ui.Select(isVerbose(), appConfig.Quiet, reporter)...,
	)
}

func getDefaultURLs() (baseURL string, targetURL string, err error) {
	dbCurator, err := db.NewCurator(appConfig.DB.ToCuratorConfig())
	if err != nil {
		return "", "", err
	}

	listing, err := dbCurator.ListingFromURL()
	if err != nil {
		return "", "", err
	}

	supportedSchema := dbCurator.SupportedSchema()
	available, exists := listing.Available[supportedSchema]
	if len(available) < 2 || !exists {
		return "", "", stderrPrintLnf("Not enough databases available for the current schema to diff (%d)", supportedSchema)
	}

	targetURL = available[0].URL.String()
	baseURL = available[1].URL.String()

	return baseURL, targetURL, nil
}
