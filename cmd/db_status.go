package cmd

import (
	"fmt"
	"os"

	"github.com/anchore/grype/grype/db"

	"github.com/spf13/cobra"
)

var showSupportedDbSchema bool

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "display database status",
	Args:  cobra.ExactArgs(0),
	Run: func(cmd *cobra.Command, args []string) {
		err := runDbStatusCmd(cmd, args)
		if err != nil {
			log.Errorf(err.Error())
			os.Exit(1)
		}
	},
}

func init() {
	// Note: this option cannot change as it supports the nightly DB generation job
	statusCmd.Flags().BoolVar(&showSupportedDbSchema, "schema", false, "show supported DB schema")

	dbCmd.AddCommand(statusCmd)
}

func runDbStatusCmd(_ *cobra.Command, _ []string) error {
	dbCurator := db.NewCurator(appConfig.Db.ToCuratorConfig())
	status := dbCurator.Status()

	if showSupportedDbSchema {
		// note: the output for this option cannot change as it supports the nightly DB generation job
		fmt.Println(status.RequiredSchemaVersion)
		return nil
	}

	if status.Err != nil {
		return status.Err
	}

	fmt.Println("Location: ", status.Location)
	fmt.Println("Built: ", status.Age.String())
	fmt.Println("Current DB Version: ", status.CurrentSchemaVersion)
	fmt.Println("Require DB Version: ", status.RequiredSchemaVersion)
	fmt.Println("Status: Valid")

	return nil
}
