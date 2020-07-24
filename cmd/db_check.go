package cmd

import (
	"fmt"
	"os"

	"github.com/anchore/grype/grype/db"
	"github.com/spf13/cobra"
)

var dbCheckCmd = &cobra.Command{
	Use:   "check",
	Short: "check to see if there is a database update available",
	Run: func(cmd *cobra.Command, args []string) {
		ret := runDbCheckCmd(cmd, args)
		if ret != 0 {
			fmt.Println("Unable to check for vulnerability database updates")
		}
		os.Exit(ret)
	},
}

func init() {
	dbCmd.AddCommand(dbCheckCmd)
}

func runDbCheckCmd(_ *cobra.Command, _ []string) int {
	dbCurator, err := db.NewCurator(appConfig.Db.ToCuratorConfig())
	if err != nil {
		log.Errorf("could not curate database: %+v", err)
		return 1
	}

	updateAvailable, _, err := dbCurator.IsUpdateAvailable()
	if err != nil {
		// TODO: should this be so fatal? we can certainly continue with a warning...
		log.Errorf("unable to check for vulnerability database update: %+v", err)
		return 1
	}

	if !updateAvailable {
		fmt.Println("No update available")
		return 0
	}

	fmt.Println("Update available!")

	return 0
}
