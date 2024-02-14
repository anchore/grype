package commands

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/grype/cmd/grype/cli/options"
	"github.com/anchore/grype/grype/db"
)

func DBDelete(app clio.Application) *cobra.Command {
	opts := dbOptionsDefault(app.ID())

	return app.SetupCommand(&cobra.Command{
		Use:   "delete",
		Short: "delete the vulnerability database",
		Args:  cobra.ExactArgs(0),
		RunE: func(_ *cobra.Command, _ []string) error {
			return runDBDelete(opts.DB)
		},
	}, opts)
}

func runDBDelete(opts options.Database) error {
	dbCurator, err := db.NewCurator(opts.ToCuratorConfig())
	if err != nil {
		return err
	}

	if err := dbCurator.Delete(); err != nil {
		return fmt.Errorf("unable to delete vulnerability database: %+v", err)
	}

	return stderrPrintLnf("Vulnerability database deleted")
}
