package cmd

import (
	"fmt"
	"os"

	"github.com/anchore/grype/grype/db"
	"github.com/spf13/cobra"
)

var dbImportCmd = &cobra.Command{
	Use:   "import",
	Short: "import a vulnerability database archive",
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
	dbCurator, err := db.NewCurator(appConfig.Db.ToCuratorConfig())
	if err != nil {
		log.Errorf("could not curate database: %w", err)
		return 1
	}

	err = dbCurator.ImportFrom(args[0])
	if err != nil {
		log.Errorf("unable to import vulnerability database: %+v", err)
		return 1
	}

	fmt.Println("Vulnerability database imported")

	return 0
}
