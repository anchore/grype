package cmd

import (
	"fmt"
	"os"

	"github.com/anchore/vulnscan/vulnscan/db"
	"github.com/spf13/cobra"
)

var dbDeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "delete the vulnerability database",
	Run: func(cmd *cobra.Command, args []string) {
		ret := runDbDeleteCmd(cmd, args)
		if ret != 0 {
			fmt.Println("Unable to delete vulnerability database")
		}
		os.Exit(ret)
	},
}

func init() {
	dbCmd.AddCommand(dbDeleteCmd)
}

func runDbDeleteCmd(_ *cobra.Command, _ []string) int {
	dbCurator, err := db.NewCurator(appConfig.Db.ToCuratorConfig())
	if err != nil {
		log.Errorf("could not curate database: %w", err)
		return 1
	}

	err = dbCurator.Delete()
	if err != nil {
		log.Errorf("unable to delete vulnerability database: %w", err)
		return 1
	}

	fmt.Println("Vulnerability database deleted")

	return 0
}
