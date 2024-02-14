package commands

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/grype/cmd/grype/cli/options"
	"github.com/anchore/grype/grype/db"
)

func DBStatus(app clio.Application) *cobra.Command {
	opts := dbOptionsDefault(app.ID())

	return app.SetupCommand(&cobra.Command{
		Use:   "status",
		Short: "display database status",
		Args:  cobra.ExactArgs(0),
		RunE: func(_ *cobra.Command, _ []string) error {
			return runDBStatus(opts.DB)
		},
	}, opts)
}

func runDBStatus(opts options.Database) error {
	dbCurator, err := db.NewCurator(opts.ToCuratorConfig())
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
