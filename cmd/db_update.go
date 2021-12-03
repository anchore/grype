package cmd

import (
	"fmt"

	"github.com/anchore/grype/grype/db"
	"github.com/spf13/cobra"
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

func runDBUpdateCmd(_ *cobra.Command, _ []string) error {
	dbCurator, err := db.NewCurator(appConfig.DB.ToCuratorConfig())
	if err != nil {
		return err
	}

	updated, err := dbCurator.Update()
	if err != nil {
		fmt.Println("Unable to update vulnerability database")
		return fmt.Errorf("unable to update vulnerability database: %+v", err)
	}

	if updated {
		return stderrPrintLnf("Vulnerability database updated!")
	}

	return stderrPrintLnf("No vulnerability database update available")
}
