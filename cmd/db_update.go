package cmd

import (
	"fmt"
	"os"

	"github.com/anchore/vulnscan/vulnscan/db"
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
	dbCurator, err := db.NewCurator(appConfig.Db.ToCuratorConfig())
	if err != nil {
		log.Errorf("could not curate database: %w", err)
		return 1
	}

	updateAvailable, updateEntry, err := dbCurator.IsUpdateAvailable()
	if err != nil {
		// TODO: should this be so fatal? we can certainly continue with a warning...
		log.Errorf("unable to check for vulnerability database update: %+v", err)
		return 1
	}
	if updateAvailable {
		err = dbCurator.UpdateTo(updateEntry)
		if err != nil {
			log.Errorf("unable to update vulnerability database: %+v", err)
			return 1
		}
	} else {
		fmt.Println("No vulnerability database update available")
		return 0
	}

	fmt.Println("Vulnerability database updated!")
	return 0
}
