package commands

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"

	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/grype/cmd/grype/cli/options"
	legacyDistribution "github.com/anchore/grype/grype/db/v5/distribution"
	"github.com/anchore/grype/grype/db/v6/distribution"
)

type dbListOptions struct {
	Output                  string `yaml:"output" json:"output" mapstructure:"output"`
	options.DatabaseCommand `yaml:",inline" mapstructure:",squash"`
}

var _ clio.FlagAdder = (*dbListOptions)(nil)

func (d *dbListOptions) AddFlags(flags clio.FlagSet) {
	flags.StringVarP(&d.Output, "output", "o", "format to display results (available=[text, raw, json])")
}

func DBList(app clio.Application) *cobra.Command {
	opts := &dbListOptions{
		Output:          textOutputFormat,
		DatabaseCommand: *options.DefaultDatabaseCommand(app.ID()),
	}

	cmd := &cobra.Command{
		Use:     "list",
		Short:   "List all DBs available according to the listing URL",
		PreRunE: disableUI(app),
		Args:    cobra.ExactArgs(0),
		RunE: func(_ *cobra.Command, _ []string) error {
			return runDBList(*opts)
		},
	}

	// prevent from being shown in the grype config
	type configWrapper struct {
		Hidden                   *dbListOptions `json:"-" yaml:"-" mapstructure:"-"`
		*options.DatabaseCommand `yaml:",inline" mapstructure:",squash"`
	}

	return app.SetupCommand(cmd, &configWrapper{Hidden: opts, DatabaseCommand: &opts.DatabaseCommand})
}

func runDBList(opts dbListOptions) error {
	if opts.Experimental.DBv6 {
		return newDBList(opts)
	}
	return legacyDBList(opts)
}

func newDBList(opts dbListOptions) error {
	c, err := distribution.NewClient(opts.ToClientConfig())
	if err != nil {
		return fmt.Errorf("unable to create distribution client: %w", err)
	}

	latest, err := c.Latest()
	if err != nil {
		return fmt.Errorf("unable to get database listing: %w", err)
	}

	return presentNewDBList(opts.Output, opts.DB.UpdateURL, os.Stdout, latest)
}

func presentNewDBList(format string, u string, writer io.Writer, latest *distribution.LatestDocument) error {
	if latest == nil {
		return fmt.Errorf("no database listing found")
	}

	parsedURL, err := url.Parse(u)
	if err != nil {
		return fmt.Errorf("failed to parse base URL: %w", err)
	}

	parsedURL.Path = path.Join(path.Dir(parsedURL.Path), latest.Path)

	switch format {
	case textOutputFormat:
		fmt.Fprintf(writer, "Status:   %s\n", latest.Status)
		fmt.Fprintf(writer, "Schema:   %s\n", latest.SchemaVersion.String())
		fmt.Fprintf(writer, "Built:    %s\n", latest.Built.String())
		fmt.Fprintf(writer, "Listing:  %s\n", u)
		fmt.Fprintf(writer, "DB URL:   %s\n", parsedURL.String())
		fmt.Fprintf(writer, "Checksum: %s\n", latest.Checksum)
	case jsonOutputFormat, "raw":
		enc := json.NewEncoder(writer)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", " ")
		if err := enc.Encode(&latest); err != nil {
			return fmt.Errorf("failed to db listing information: %+v", err)
		}
	default:
		return fmt.Errorf("unsupported output format: %s", format)
	}
	return nil
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// all legacy processing below ////////////////////////////////////////////////////////////////////////////////////////

func legacyDBList(opts dbListOptions) error {
	dbCurator, err := legacyDistribution.NewCurator(opts.ToLegacyCuratorConfig())
	if err != nil {
		return err
	}

	listing, err := dbCurator.ListingFromURL()
	if err != nil {
		return err
	}

	supportedSchema := dbCurator.SupportedSchema()
	available, exists := listing.Available[supportedSchema]

	if len(available) == 0 || !exists {
		return stderrPrintLnf("No databases available for the current schema (%d)", supportedSchema)
	}

	switch opts.Output {
	case textOutputFormat:
		// summarize each listing entry for the current DB schema
		for _, l := range available {
			fmt.Printf("Built:    %s\n", l.Built)
			fmt.Printf("URL:      %s\n", l.URL)
			fmt.Printf("Checksum: %s\n\n", l.Checksum)
		}

		fmt.Printf("%d databases available for schema %d\n", len(available), supportedSchema)
	case jsonOutputFormat:
		// show entries for the current schema
		enc := json.NewEncoder(os.Stdout)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", " ")
		if err := enc.Encode(&available); err != nil {
			return fmt.Errorf("failed to db listing information: %+v", err)
		}
	case "raw":
		// show the entire listing file
		enc := json.NewEncoder(os.Stdout)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", " ")
		if err := enc.Encode(&listing); err != nil {
			return fmt.Errorf("failed to db listing information: %+v", err)
		}
	default:
		return fmt.Errorf("unsupported output format: %s", opts.Output)
	}

	return nil
}
