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
	RunE:  runDbUpdateCmd,
}

func init() {
	dbCmd.AddCommand(dbUpdateCmd)
}

func runDbUpdateCmd(_ *cobra.Command, _ []string) error {
	dbCurator := db.NewCurator(appConfig.Db.ToCuratorConfig())

	updated, err := dbCurator.Update()
	if err != nil {
		fmt.Println("Unable to update vulnerability database")
		return fmt.Errorf("unable to update vulnerability database: %+v", err)
	}

	if updated {
		fmt.Println("Vulnerability database updated!")
		return nil
	}

	fmt.Println("No vulnerability database update available")
	return nil
}
