package commands

import (
	"strings"

	"github.com/hashicorp/go-multierror"
	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/grype/cmd/grype/cli/options"
	"github.com/anchore/grype/grype/db/v5/differ"
	"github.com/anchore/grype/grype/db/v5/distribution"
	"github.com/anchore/grype/internal/bus"
	"github.com/anchore/grype/internal/log"
)

type dbDiffOptions struct {
	Output                  string `yaml:"output" json:"output" mapstructure:"output"`
	Delete                  bool   `yaml:"delete" json:"delete" mapstructure:"delete"`
	options.DatabaseCommand `yaml:",inline" mapstructure:",squash"`
}

var _ clio.FlagAdder = (*dbDiffOptions)(nil)

func (d *dbDiffOptions) AddFlags(flags clio.FlagSet) {
	flags.StringVarP(&d.Output, "output", "o", "format to display results (available=[table, json])")
	flags.BoolVarP(&d.Delete, "delete", "d", "delete downloaded databases after diff occurs")
}

func DBDiff(app clio.Application) *cobra.Command {
	opts := &dbDiffOptions{
		Output:          tableOutputFormat,
		DatabaseCommand: *options.DefaultDatabaseCommand(app.ID()),
	}

	cmd := &cobra.Command{
		Use:   "diff [flags] base_db_url target_db_url",
		Short: "Diff two DBs and display the result",
		Args:  cobra.MaximumNArgs(2),
		RunE: func(_ *cobra.Command, args []string) (err error) {
			var base, target string

			switch len(args) {
			case 0:
				log.Info("base_db_url and target_db_url not provided; fetching most recent")
				base, target, err = getDefaultURLs(opts.DatabaseCommand)
				if err != nil {
					return err
				}
			case 1:
				log.Info("target_db_url not provided; fetching most recent")
				base = args[0]
				_, target, err = getDefaultURLs(opts.DatabaseCommand)
				if err != nil {
					return err
				}
			default:
				base = args[0]
				target = args[1]
			}

			return runDBDiff(opts, base, target)
		},
	}

	// prevent from being shown in the grype config
	type configWrapper struct {
		Hidden                   *dbDiffOptions `json:"-" yaml:"-" mapstructure:"-"`
		*options.DatabaseCommand `yaml:",inline" mapstructure:",squash"`
	}

	return app.SetupCommand(cmd, &configWrapper{Hidden: opts, DatabaseCommand: &opts.DatabaseCommand})
}

func runDBDiff(opts *dbDiffOptions, base string, target string) (errs error) {
	d, err := differ.NewDiffer(opts.ToLegacyCuratorConfig())
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

func getDefaultURLs(opts options.DatabaseCommand) (baseURL string, targetURL string, err error) {
	dbCurator, err := distribution.NewCurator(opts.ToLegacyCuratorConfig())
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
