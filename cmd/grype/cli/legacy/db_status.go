package legacy

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/anchore/grype/grype/db"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "display database status",
	Args:  cobra.ExactArgs(0),
	RunE:  runDBStatusCmd,
}

func init() {
	dbCmd.AddCommand(statusCmd)
}

func runDBStatusCmd(_ *cobra.Command, _ []string) error {
	dbCurator, err := db.NewCurator(appConfig.DB.ToCuratorConfig())
	if err != nil {
		return err
	}

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
