package cmd

import (
	"fmt"

	"github.com/anchore/grype/internal"

	"github.com/anchore/grype/grype/db"
	"github.com/spf13/cobra"
)

var dbImportCmd = &cobra.Command{
	Use:   "import FILE",
	Short: "import a vulnerability database archive",
	Long:  fmt.Sprintf("import a vulnerability database archive from a local FILE.\nDB archives can be obtained from %q.", internal.DBUpdateURL),
	Args:  cobra.ExactArgs(1),
	RunE:  runDbImportCmd,
}

func init() {
	dbCmd.AddCommand(dbImportCmd)
}

func runDbImportCmd(_ *cobra.Command, args []string) error {
	dbCurator := db.NewCurator(appConfig.Db.ToCuratorConfig())

	if err := dbCurator.ImportFrom(args[0]); err != nil {
		return fmt.Errorf("unable to import vulnerability database: %+v", err)
	}

	fmt.Println("Vulnerability database imported")
	return nil
}
