package cmd

import (
	"fmt"
	"os"

	"github.com/anchore/vulnscan/vulnscan/db"

	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "display database status",
	Run: func(cmd *cobra.Command, args []string) {
		os.Exit(runDbStatusCmd(cmd, args))
	},
}

func init() {
	dbCmd.AddCommand(statusCmd)
}

func runDbStatusCmd(_ *cobra.Command, _ []string) int {
	dbCurator, err := db.NewCurator(appConfig.Db.ToCuratorConfig())
	if err != nil {
		log.Errorf("could not curate database: %w", err)
		return 1
	}

	status := dbCurator.Status()
	fmt.Println("Location: ", status.Location)
	fmt.Println("Built: ", status.Age.String())
	fmt.Println("Version: ", status.SchemaVersion)
	fmt.Println("Constraint: ", status.SchemaConstraint)
	if status.Err != nil {
		fmt.Printf("Status: INVALID [%+v]\n", status.Err)
	} else {
		fmt.Println("Status: Valid")
	}

	return 0
}
