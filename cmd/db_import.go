package cmd

import (
	"fmt"
	"os"

	"github.com/anchore/grype/internal"

	"github.com/anchore/grype/grype/db"
	"github.com/spf13/cobra"
)

var dbImportCmd = &cobra.Command{
	Use:   "import FILE",
	Short: "import a vulnerability database archive",
	Long:  fmt.Sprintf("import a vulnerability database archive from a local FILE.\nDB archives can be obtained from %q.", internal.DBUpdateURL),
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		ret := runDbImportCmd(cmd, args)
		if ret != 0 {
			fmt.Println("Unable to import vulnerability database")
		}
		os.Exit(ret)
	},
}

func init() {
	dbCmd.AddCommand(dbImportCmd)
}

func runDbImportCmd(_ *cobra.Command, args []string) int {
	dbCurator := db.NewCurator(appConfig.Db.ToCuratorConfig())

	if err := dbCurator.ImportFrom(args[0]); err != nil {
		log.Errorf("unable to import vulnerability database: %+v", err)
		return 1
	}

	fmt.Println("Vulnerability database imported")

	return 0
}
