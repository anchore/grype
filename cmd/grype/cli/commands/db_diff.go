package commands

import (
	"strings"

	"github.com/hashicorp/go-multierror"
	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/grype/cmd/grype/cli/options"
	"github.com/anchore/grype/grype/db"
	"github.com/anchore/grype/grype/differ"
	"github.com/anchore/grype/internal/bus"
	"github.com/anchore/grype/internal/log"
)

type dbDiffOptions struct {
	Output    string `yaml:"output" json:"output" mapstructure:"output"`
	Delete    bool   `yaml:"delete" json:"delete" mapstructure:"delete"`
	DBOptions `yaml:",inline" mapstructure:",squash"`
}

var _ clio.FlagAdder = (*dbDiffOptions)(nil)

func (d *dbDiffOptions) AddFlags(flags clio.FlagSet) {
	flags.StringVarP(&d.Output, "output", "o", "format to display results (available=[table, json])")
	flags.BoolVarP(&d.Delete, "delete", "d", "delete downloaded databases after diff occurs")
}

func DBDiff(app clio.Application) *cobra.Command {
	opts := &dbDiffOptions{
		Output:    "table",
		DBOptions: *dbOptionsDefault(app.ID()),
	}

	return app.SetupCommand(&cobra.Command{
		Use:   "diff [flags] base_db_url target_db_url",
		Short: "diff two DBs and display the result",
		Args:  cobra.MaximumNArgs(2),
		RunE: func(_ *cobra.Command, args []string) (err error) {
			var base, target string

			switch len(args) {
			case 0:
				log.Info("base_db_url and target_db_url not provided; fetching most recent")
				base, target, err = getDefaultURLs(opts.DB)
				if err != nil {
					return err
				}
			case 1:
				log.Info("target_db_url not provided; fetching most recent")
				base = args[0]
				_, target, err = getDefaultURLs(opts.DB)
				if err != nil {
					return err
				}
			default:
				base = args[0]
				target = args[1]
			}

			return runDBDiff(opts, base, target)
		},
	}, opts)
}

func runDBDiff(opts *dbDiffOptions, base string, target string) (errs error) {
	d, err := differ.NewDiffer(opts.DB.ToCuratorConfig())
	if err != nil {
		return err
	}

	if err := d.SetBaseDB(base); err != nil {
		return err
	}

	if err := d.SetTargetDB(target); err != nil {
		return err
	}

	diff, err := d.DiffDatabases()
	if err != nil {
		return err
	}

	sb := &strings.Builder{}

	if len(*diff) == 0 {
		sb.WriteString("Databases are identical!\n")
	} else {
		err := d.Present(opts.Output, diff, sb)
		if err != nil {
			errs = multierror.Append(errs, err)
		}
	}

	bus.Report(sb.String())

	if opts.Delete {
		errs = multierror.Append(errs, d.DeleteDatabases())
	}

	return errs
}

func getDefaultURLs(opts options.Database) (baseURL string, targetURL string, err error) {
	dbCurator, err := db.NewCurator(opts.ToCuratorConfig())
	if err != nil {
		return "", "", err
	}

	listing, err := dbCurator.ListingFromURL()
	if err != nil {
		return "", "", err
	}

	supportedSchema := dbCurator.SupportedSchema()
	available, exists := listing.Available[supportedSchema]
	if len(available) < 2 || !exists {
		return "", "", stderrPrintLnf("Not enough databases available for the current schema to diff (%d)", supportedSchema)
	}

	targetURL = available[0].URL.String()
	baseURL = available[1].URL.String()

	return baseURL, targetURL, nil
}
