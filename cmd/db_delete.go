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
	RunE:  runDbDeleteCmd,
}

func init() {
	dbCmd.AddCommand(dbDeleteCmd)
}

func runDbDeleteCmd(_ *cobra.Command, _ []string) error {
	dbCurator := db.NewCurator(appConfig.Db.ToCuratorConfig())

	if err := dbCurator.Delete(); err != nil {
		return fmt.Errorf("unable to delete vulnerability database: %+v", err)
	}

	fmt.Println("Vulnerability database deleted")
	return nil
}
