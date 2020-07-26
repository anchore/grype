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
	Run: func(cmd *cobra.Command, args []string) {
		os.Exit(runDbStatusCmd(cmd, args))
	},
}

func init() {
	// Note: this option cannot change as it supports the nightly DB generation job
	statusCmd.Flags().BoolVar(&showSupportedDbSchema, "schema", false, "show supported DB schema")

	dbCmd.AddCommand(statusCmd)
}

func runDbStatusCmd(_ *cobra.Command, _ []string) int {
	dbCurator, err := db.NewCurator(appConfig.Db.ToCuratorConfig())
	if err != nil {
		log.Errorf("could not curate database: %w", err)
		return 1
	}

	status := dbCurator.Status()

	if showSupportedDbSchema {
		// Note: the output for this option cannot change as it supports the nightly DB generation job
		fmt.Println(status.RequiredSchemeVersion)
		return 0
	}

	fmt.Println("Location: ", status.Location)
	fmt.Println("Built: ", status.Age.String())
	fmt.Println("Current DB Version: ", status.CurrentSchemaVersion)
	fmt.Println("Require DB Version: ", status.RequiredSchemeVersion)
	if status.Err != nil {
		fmt.Printf("Status: INVALID [%+v]\n", status.Err)
	} else {
		fmt.Println("Status: Valid")
	}

	return 0
}
