package commands

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/grype/grype/db"
)

type dbListOptions struct {
	Output    string `yaml:"output" json:"output" mapstructure:"output"`
	DBOptions `yaml:",inline" mapstructure:",squash"`
}

var _ clio.FlagAdder = (*dbListOptions)(nil)

func (d *dbListOptions) AddFlags(flags clio.FlagSet) {
	flags.StringVarP(&d.Output, "output", "o", "format to display results (available=[text, raw, json])")
}

func DBList(app clio.Application) *cobra.Command {
	opts := &dbListOptions{
		Output:    "text",
		DBOptions: *dbOptionsDefault(app.ID()),
	}

	return app.SetupCommand(&cobra.Command{
		Use:   "list",
		Short: "list all DBs available according to the listing URL",
		Args:  cobra.ExactArgs(0),
		RunE: func(_ *cobra.Command, _ []string) error {
			return runDBList(opts)
		},
	}, opts)
}

func runDBList(opts *dbListOptions) error {
	dbCurator, err := db.NewCurator(opts.DB.ToCuratorConfig())
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
	case "text":
		// summarize each listing entry for the current DB schema
		for _, l := range available {
			fmt.Printf("Built:    %s\n", l.Built)
			fmt.Printf("URL:      %s\n", l.URL)
			fmt.Printf("Checksum: %s\n\n", l.Checksum)
		}

		fmt.Printf("%d databases available for schema %d\n", len(available), supportedSchema)
	case "json":
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
