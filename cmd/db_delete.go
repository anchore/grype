package cmd

import (
	"fmt"

	"github.com/anchore/grype/grype/db"
	"github.com/spf13/cobra"
)

var dbDeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "delete the vulnerability database",
	Args:  cobra.ExactArgs(0),
	RunE:  runDBDeleteCmd,
}

func init() {
	dbCmd.AddCommand(dbDeleteCmd)
}

func runDBDeleteCmd(_ *cobra.Command, _ []string) error {
	dbCurator, err := db.NewCurator(appConfig.DB.ToCuratorConfig())
	if err != nil {
		return err
	}

	if err := dbCurator.Delete(); err != nil {
		return fmt.Errorf("unable to delete vulnerability database: %+v", err)
	}

	return stderrPrintLnf("Vulnerability database deleted")
}
