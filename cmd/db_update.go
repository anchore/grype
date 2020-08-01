package cmd

import (
	"fmt"
	"os"

	"github.com/anchore/grype/grype/db"
	"github.com/spf13/cobra"
)

var dbUpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "download the latest vulnerability database",
	Run: func(cmd *cobra.Command, args []string) {
		ret := runDbUpdateCmd(cmd, args)
		if ret != 0 {
			fmt.Println("Unable to update vulnerability database")
		}
		os.Exit(ret)
	},
}

func init() {
	dbCmd.AddCommand(dbUpdateCmd)
}

func runDbUpdateCmd(_ *cobra.Command, _ []string) int {
	dbCurator := db.NewCurator(appConfig.Db.ToCuratorConfig())

	updated, err := dbCurator.Update()
	if err != nil {
		log.Errorf("unable to update vulnerability database: %+v", err)
		return 1
	}

	if updated {
		fmt.Println("Vulnerability database updated!")
		return 0
	}

	fmt.Println("No vulnerability database update available")
	return 0
}
