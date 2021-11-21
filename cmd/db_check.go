package cmd

import (
	"fmt"

	"github.com/anchore/grype/grype/db"
	"github.com/spf13/cobra"
)

var dbCheckCmd = &cobra.Command{
	Use:   "check",
	Short: "check to see if there is a database update available",
	Args:  cobra.ExactArgs(0),
	RunE:  runDBCheckCmd,
}

func init() {
	dbCmd.AddCommand(dbCheckCmd)
}

func runDBCheckCmd(_ *cobra.Command, _ []string) error {
	dbCurator, err := db.NewCurator(appConfig.DB.ToCuratorConfig())
	if err != nil {
		return err
	}

	updateAvailable, _, err := dbCurator.IsUpdateAvailable()
	if err != nil {
		return fmt.Errorf("unable to check for vulnerability database update: %+v", err)
	}

	if !updateAvailable {
		fmt.Println("No update available")
		return nil
	}

	fmt.Println("Update available!")
	return nil
}
