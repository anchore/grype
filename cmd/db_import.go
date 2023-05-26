package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/nextlinux/griffon/griffon/db"
	"github.com/nextlinux/griffon/internal"
)

var dbImportCmd = &cobra.Command{
	Use:   "import FILE",
	Short: "import a vulnerability database archive",
	Long:  fmt.Sprintf("import a vulnerability database archive from a local FILE.\nDB archives can be obtained from %q.", internal.DBUpdateURL),
	Args:  cobra.ExactArgs(1),
	RunE:  runDBImportCmd,
}

func init() {
	dbCmd.AddCommand(dbImportCmd)
}

func runDBImportCmd(_ *cobra.Command, args []string) error {
	dbCurator, err := db.NewCurator(appConfig.DB.ToCuratorConfig())
	if err != nil {
		return err
	}

	if err := dbCurator.ImportFrom(args[0]); err != nil {
		return fmt.Errorf("unable to import vulnerability database: %+v", err)
	}

	return stderrPrintLnf("Vulnerability database imported")
}
