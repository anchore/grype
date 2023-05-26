package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/nextlinux/griffon/griffon/db"
)

var dbCheckCmd = &cobra.Command{
	Use:   "check",
	Short: "check to see if there is a database update available",
	Args:  cobra.ExactArgs(0),
	RunE:  runDBCheckCmd,
}

func init() {
	dbCmd.AddCommand(dbCheckCmd)
}

func runDBCheckCmd(_ *cobra.Command, _ []string) error {
	dbCurator, err := db.NewCurator(appConfig.DB.ToCuratorConfig())
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
	fmt.Println("You can run 'griffon db update' to update to the latest db")

	return nil
}
