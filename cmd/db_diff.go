package cmd

import (
	"fmt"
	"net/url"
	"os"

	"github.com/spf13/cobra"
	"github.com/wagoodman/go-partybus"

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
	Args:  cobra.ExactArgs(2),
	RunE:  runDBDiffCmd,
}

func init() {
	dbDiffCmd.Flags().StringVarP(&dbDiffOutputFormat, "output", "o", "table", "format to display results (available=[table, json])")
	dbDiffCmd.Flags().BoolP(deleteFlag, "d", false, "delete downloaded databases after diff occurs")

	dbCmd.AddCommand(dbDiffCmd)
}

func startDBDiffCmd(baseURL, targetURL string, deleteDatabases bool) <-chan error {
	errs := make(chan error)
	go func() {
		defer close(errs)
		d, err := differ.NewDiffer(appConfig.DB.ToCuratorConfig())
		if err != nil {
			errs <- err
			return
		}

		baseURL, err := url.Parse(baseURL)
		if err != nil {
			errs <- fmt.Errorf("base url is malformed: %w", err)
			return
		}
		targetURL, err := url.Parse(targetURL)
		if err != nil {
			errs <- fmt.Errorf("target url is malformed: %w", err)
			return
		}

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
	return eventLoop(
		startDBDiffCmd(args[0], args[1], deleteDatabases),
		setupSignals(),
		eventSubscription,
		stereoscope.Cleanup,
		ui.Select(isVerbose(), appConfig.Quiet, reporter)...,
	)
}
