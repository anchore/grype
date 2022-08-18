package cmd

import (
	"fmt"
	"net/url"
	"os"

	"github.com/spf13/cobra"
	"github.com/wagoodman/go-partybus"

	"github.com/anchore/grype/grype/db"
	"github.com/anchore/grype/grype/differ"
	"github.com/anchore/grype/grype/event"
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

func startDBDiffCmd(dbURL []*url.URL, deleteDatabases bool) <-chan error {
	errs := make(chan error)
	go func() {
		defer close(errs)
		d, err := differ.NewDiffer(appConfig.DB.ToCuratorConfig())
		if err != nil {
			errs <- err
			return
		}

		baseURL := dbURL[0]
		targetURL := dbURL[1]

		if err := d.DownloadDatabases(baseURL, targetURL); err != nil {
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

		bus.Publish(partybus.Event{
			Type:  event.NonRootCommandFinished,
			Value: "",
		})
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

	var dbURL []*url.URL

	if len(args) < 2 {
		log.Info("base_db_url and target_db_url not provided; fetching most recent")
		dbURL, err = getDefaultURL()
		if err != nil {
			return fmt.Errorf("could not fetch most recent database URL: %w", err)
		}
	} else {
		for _, arg := range args {
			u, err := url.Parse(arg)
			if err != nil {
				return fmt.Errorf("url argument is malformed: %w", err)
			}

			dbURL = append(dbURL, u)
		}
	}

	return eventLoop(
		startDBDiffCmd(dbURL, deleteDatabases),
		setupSignals(),
		eventSubscription,
		stereoscope.Cleanup,
		ui.Select(isVerbose(), appConfig.Quiet, reporter)...,
	)
}

func getDefaultURL() (defaultURL []*url.URL, err error) {
	dbCurator, err := db.NewCurator(appConfig.DB.ToCuratorConfig())
	if err != nil {
		return nil, err
	}

	listing, err := dbCurator.ListingFromURL()
	if err != nil {
		return nil, err
	}

	supportedSchema := dbCurator.SupportedSchema()
	available, exists := listing.Available[supportedSchema]
	if len(available) < 2 || !exists {
		return nil, stderrPrintLnf("Not enough databases available for the current schema to diff (%d)", supportedSchema)
	}

	recent := available[:2]
	for _, entry := range recent {
		defaultURL = append([]*url.URL{entry.URL}, defaultURL...)
	}

	return defaultURL, nil
}
