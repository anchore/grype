package cmd

import (
	"fmt"
	"os"

	"github.com/anchore/grype/grype/db"

	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "display database status",
	Args:  cobra.ExactArgs(0),
	Run: func(cmd *cobra.Command, args []string) {
		err := runDbStatusCmd(cmd, args)
		if err != nil {
			log.Errorf(err.Error())
			os.Exit(1)
		}
	},
}

func init() {
	dbCmd.AddCommand(statusCmd)
}

func runDbStatusCmd(_ *cobra.Command, _ []string) error {
	dbCurator := db.NewCurator(appConfig.Db.ToCuratorConfig())
	status := dbCurator.Status()

	statusStr := "valid"
	if status.Err != nil {
		statusStr = "invalid"
	}

	fmt.Println("Location: ", status.Location)
	fmt.Println("Built:    ", status.Built.String())
	fmt.Println("Schema:   ", status.SchemaVersion)
	fmt.Println("Checksum: ", status.Checksum)
	fmt.Println("Status:   ", statusStr)

	return status.Err
}
