package commands

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	legacyDistribution "github.com/anchore/grype/grype/db/legacy/distribution"
	v6 "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/distribution"
	"github.com/anchore/grype/grype/db/v6/installation"
)

type dbStatusOptions struct {
	Output    string `yaml:"output" json:"output" mapstructure:"output"`
	DBOptions `yaml:",inline" mapstructure:",squash"`
}

var _ clio.FlagAdder = (*dbStatusOptions)(nil)

func (d *dbStatusOptions) AddFlags(flags clio.FlagSet) {
	flags.StringVarP(&d.Output, "output", "o", "format to display results (available=[text, json])")
}

func DBStatus(app clio.Application) *cobra.Command {
	opts := &dbStatusOptions{
		Output:    textOutputFormat,
		DBOptions: *dbOptionsDefault(app.ID()),
	}

	cmd := &cobra.Command{
		Use:     "status",
		Short:   "display database status",
		Args:    cobra.ExactArgs(0),
		PreRunE: disableUI(app),
		RunE: func(_ *cobra.Command, _ []string) error {
			return runDBStatus(*opts)
		},
	}

	// prevent from being shown in the grype config
	type configWrapper struct {
		Opts *dbStatusOptions `json:"-" yaml:"-" mapstructure:"-"`
	}

	return app.SetupCommand(cmd, &configWrapper{opts})
}

func runDBStatus(opts dbStatusOptions) error {
	if opts.Experimental.DBv6 {
		return newDBStatus(opts)
	}
	return legacyDBStatus(opts)
}

func newDBStatus(opts dbStatusOptions) error {
	client, err := distribution.NewClient(opts.DB.ToClientConfig())
	if err != nil {
		return fmt.Errorf("unable to create distribution client: %w", err)
	}
	c, err := installation.NewCurator(opts.DB.ToCuratorConfig(), client)
	if err != nil {
		return fmt.Errorf("unable to create distribution client: %w", err)
	}

	status := c.Status()

	if err := presentDBStatus(opts.Output, os.Stdout, status); err != nil {
		return fmt.Errorf("failed to present db status information: %+v", err)
	}

	return status.Err
}

func presentDBStatus(format string, writer io.Writer, status v6.Status) error {
	switch format {
	case textOutputFormat:
		fmt.Fprintln(writer, "Path:     ", status.Path)
		fmt.Fprintln(writer, "Schema:   ", status.SchemaVersion)
		fmt.Fprintln(writer, "Built:    ", status.Built.String())
		fmt.Fprintln(writer, "Checksum: ", status.Checksum)
		fmt.Fprintln(writer, "Status:   ", status.Status())
	case jsonOutputFormat:
		enc := json.NewEncoder(writer)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", " ")
		if err := enc.Encode(&status); err != nil {
			return fmt.Errorf("failed to db status information: %+v", err)
		}
	default:
		return fmt.Errorf("unsupported output format: %s", format)
	}

	return nil
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// all legacy processing below ////////////////////////////////////////////////////////////////////////////////////////

func legacyDBStatus(opts dbStatusOptions) error {
	dbCurator, err := legacyDistribution.NewCurator(opts.DB.ToLegacyCuratorConfig())
	if err != nil {
		return err
	}

	status := dbCurator.Status()

	switch opts.Output {
	case textOutputFormat:
		fmt.Println("Location: ", status.Location)
		fmt.Println("Built:    ", status.Built.String())
		fmt.Println("Schema:   ", status.SchemaVersion)
		fmt.Println("Checksum: ", status.Checksum)
		fmt.Println("Status:   ", status.Status())
	case jsonOutputFormat:
		enc := json.NewEncoder(os.Stdout)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", " ")
		if err := enc.Encode(&status); err != nil {
			return fmt.Errorf("failed to db status information: %+v", err)
		}
	default:
		return fmt.Errorf("unsupported output format: %s", opts.Output)
	}

	return status.Err
}
