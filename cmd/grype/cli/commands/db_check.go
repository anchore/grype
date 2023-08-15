package commands

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/grype/cmd/grype/cli/options"
	"github.com/anchore/grype/grype/db"
)

func DBCheck(app clio.Application) *cobra.Command {
	opts := dbOptionsDefault(app.ID())

	return app.SetupCommand(&cobra.Command{
		Use:   "check",
		Short: "check to see if there is a database update available",
		Args:  cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDBCheckCmd(opts.DB)
		},
	}, opts)
}

func runDBCheckCmd(opts options.Database) error {
	dbCurator, err := db.NewCurator(opts.ToCuratorConfig())
	if err != nil {
		return err
	}

	updateAvailable, currentDBMetadata, updateDBEntry, err := dbCurator.IsUpdateAvailable()
	if err != nil {
		return fmt.Errorf("unable to check for vulnerability database update: %+v", err)
	}

	if !updateAvailable {
		return stderrPrintLnf("No update available")
	}

	fmt.Println("Update available!")

	if currentDBMetadata != nil {
		fmt.Printf("Current DB version %d was built on %s\n", currentDBMetadata.Version, currentDBMetadata.Built.String())
	}

	fmt.Printf("Updated DB version %d was built on %s\n", updateDBEntry.Version, updateDBEntry.Built.String())
	fmt.Printf("Updated DB URL: %s\n", updateDBEntry.URL.String())
	fmt.Println("You can run 'grype db update' to update to the latest db")

	return nil
}
