package commands

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/grype/cmd/grype/cli/options"
	"github.com/anchore/grype/grype/db/v6/distribution"
	"github.com/anchore/grype/grype/db/v6/installation"
	"github.com/anchore/grype/internal/log"
)

func DBImport(app clio.Application) *cobra.Command {
	opts := options.DefaultDatabaseCommand(app.ID())

	cmd := &cobra.Command{
		Use:   "import FILE | URL",
		Short: "Import a vulnerability database or archive from a local file or URL",
		Long:  fmt.Sprintf("import a vulnerability database archive from a local FILE or URL.\nDB archives can be obtained from %q (or running `db list`). If the URL has a `checksum` query parameter with a fully qualified digest (e.g. 'sha256:abc728...') then the archive/DB will be verified against this value.", opts.DB.UpdateURL),
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return runDBImport(*opts, args[0])
		},
	}

	// prevent from being shown in the grype config
	type configWrapper struct {
		*options.DatabaseCommand `yaml:",inline" mapstructure:",squash"`
	}

	return app.SetupCommand(cmd, &configWrapper{opts})
}

func runDBImport(opts options.DatabaseCommand, reference string) error {
	// TODO: tui update? better logging?
	client, err := distribution.NewClient(opts.ToClientConfig())
	if err != nil {
		return fmt.Errorf("unable to create distribution client: %w", err)
	}
	c, err := installation.NewCurator(opts.ToCuratorConfig(), client)
	if err != nil {
		return fmt.Errorf("unable to create curator: %w", err)
	}

	log.WithFields("reference", reference).Infof("importing vulnerability database archive")
	if err := c.Import(reference); err != nil {
		return fmt.Errorf("unable to import vulnerability database: %w", err)
	}

	s := c.Status()
	log.WithFields("built", s.Built.String(), "status", renderStoreValidation(s)).Info("vulnerability database imported")
	return nil
}
