package commands

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/grype/cmd/grype/cli/options"
	legacyDistribution "github.com/anchore/grype/grype/db/legacy/distribution"
	"github.com/anchore/grype/grype/db/v6/distribution"
	"github.com/anchore/grype/grype/db/v6/installation"
	"github.com/anchore/grype/internal"
)

func DBImport(app clio.Application) *cobra.Command {
	opts := dbOptionsDefault(app.ID())

	return app.SetupCommand(&cobra.Command{
		Use:     "import FILE",
		Short:   "import a vulnerability database archive",
		Long:    fmt.Sprintf("import a vulnerability database archive from a local FILE.\nDB archives can be obtained from %q.", internal.DBUpdateURL),
		Args:    cobra.ExactArgs(1),
		PreRunE: disableUI(app),
		RunE: func(_ *cobra.Command, args []string) error {
			return runDBImport(opts.DB, args[0])
		},
	}, opts)
}

func runDBImport(opts options.Database, dbArchivePath string) error {
	// TODO: tui update? better logging?

	// TODO: we will only support v6 after development is complete
	if isV6DB(dbArchivePath) {
		return importDB(opts, dbArchivePath)
	}
	return legacyDBImport(opts, dbArchivePath)
}

func importDB(opts options.Database, dbArchivePath string) error {
	client, err := distribution.NewClient(opts.ToClientConfig())
	if err != nil {
		return fmt.Errorf("unable to create distribution client: %w", err)
	}
	c, err := installation.NewCurator(opts.ToCuratorConfig(), client)
	if err != nil {
		return fmt.Errorf("unable to create curator: %w", err)
	}

	if err := c.Import(dbArchivePath); err != nil {
		return fmt.Errorf("unable to import vulnerability database: %w", err)
	}
	return stderrPrintLnf("Vulnerability database imported")
}

func legacyDBImport(opts options.Database, dbArchivePath string) error {
	dbCurator, err := legacyDistribution.NewCurator(opts.ToLegacyCuratorConfig())
	if err != nil {
		return err
	}

	if err := dbCurator.ImportFrom(dbArchivePath); err != nil {
		return fmt.Errorf("unable to import vulnerability database: %w", err)
	}

	return stderrPrintLnf("Vulnerability database imported")
}

func isV6DB(path string) bool {
	return strings.Contains(filepath.Base(path), "vulnerability-db_v6")
}
