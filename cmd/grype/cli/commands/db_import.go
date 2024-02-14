package commands

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/grype/cmd/grype/cli/options"
	"github.com/anchore/grype/grype/db"
	"github.com/anchore/grype/internal"
)

func DBImport(app clio.Application) *cobra.Command {
	opts := dbOptionsDefault(app.ID())

	return app.SetupCommand(&cobra.Command{
		Use:   "import FILE",
		Short: "import a vulnerability database archive",
		Long:  fmt.Sprintf("import a vulnerability database archive from a local FILE.\nDB archives can be obtained from %q.", internal.DBUpdateURL),
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return runDBImport(opts.DB, args[0])
		},
	}, opts)
}

func runDBImport(opts options.Database, dbArchivePath string) error {
	dbCurator, err := db.NewCurator(opts.ToCuratorConfig())
	if err != nil {
		return err
	}

	if err := dbCurator.ImportFrom(dbArchivePath); err != nil {
		return fmt.Errorf("unable to import vulnerability database: %+v", err)
	}

	return stderrPrintLnf("Vulnerability database imported")
}
