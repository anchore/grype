package commands

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/grype/cmd/grype/cli/options"
	"github.com/anchore/grype/grype/db/v6/diff"
	"github.com/anchore/grype/internal/log"
)

type dbDiffOptions struct {
	Output                  string `yaml:"output" json:"output" mapstructure:"output"`
	options.DatabaseCommand `yaml:",inline" mapstructure:",squash"`
	Old                     string
	New                     string
}

var _ clio.FlagAdder = (*dbDiffOptions)(nil)

func (d *dbDiffOptions) AddFlags(flags clio.FlagSet) {
	flags.StringVarP(&d.Output, "output", "o", "format to display results (available=[text, json])")
}

func DBDiff(app clio.Application) *cobra.Command {
	opts := &dbDiffOptions{
		Output:          textOutputFormat,
		DatabaseCommand: *options.DefaultDatabaseCommand(app.ID()),
	}

	cmd := &cobra.Command{
		Use:   "diff [flags] old_db_url_or_path [new_db_url_or_path]",
		Short: "Diff two databases, showing packages with added, removed, and modified vulnerability matches",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			opts.DB.MaxUpdateCheckFrequency = 0
			return disableUI(app)(cmd, args)
		},
		Args: cobra.RangeArgs(1, 2),
		RunE: func(_ *cobra.Command, args []string) error {
			opts.Old = args[0]
			if len(args) > 1 {
				opts.New = args[1]
			}
			return runDBDiff(*opts)
		},
	}

	type configWrapper struct {
		Hidden                   *dbDiffOptions `json:"-" yaml:"-" mapstructure:"-"`
		*options.DatabaseCommand `yaml:",inline" mapstructure:",squash"`
	}

	return app.SetupCommand(cmd, &configWrapper{Hidden: opts, DatabaseCommand: &opts.DatabaseCommand})
}

func runDBDiff(opts dbDiffOptions) error {
	startTime := time.Now()

	// d, err := diff.NewProviderDiffer(oldResult.dir, newResult.dir)
	d, err := diff.NewDBDiffer(diff.Config{
		Config: opts.ToCuratorConfig(),
		Debug:  opts.Developer.DB.Debug,
		OldDB:  opts.Old,
		NewDB:  opts.New,
	})

	if err != nil {
		return fmt.Errorf("unable to create differ: %w", err)
	}
	defer log.CloseAndLogError(d, "differ")

	result, err := d.Diff()
	if err != nil {
		return fmt.Errorf("unable to diff databases: %w", err)
	}

	log.Infof("diff complete in %s", time.Since(startTime))

	totalAdded, totalRemoved, totalModified := 0, 0, 0
	for _, pkg := range result.Packages {
		totalAdded += len(pkg.Vulnerabilities.Added)
		totalRemoved += len(pkg.Vulnerabilities.Removed)
		totalModified += len(pkg.Vulnerabilities.Modified)
	}

	log.Infof("diff complete: %d added, %d removed, %d modified",
		totalAdded, totalRemoved, totalModified)

	slices.SortFunc(result.Packages, func(a, b diff.PackageDiff) int {
		c := strings.Compare(a.Ecosystem, b.Ecosystem)
		if c != 0 {
			return c
		}
		return strings.Compare(a.Name, b.Name)
	})

	writer := os.Stdout
	if opts.Output == "json" {
		return outputJSON(writer, result)
	}

	return outputText(writer, result)
}

func outputText(writer io.Writer, result *diff.Result) error {
	columns := []string{"Ecosystem", "Package"}

	t := newTable(writer, columns)

	for _, pkg := range result.Packages {
		name := pkg.Name
		if pkg.CPE != "" {
			name = pkg.CPE
		}
		err := t.Append(pkg.Ecosystem, name)
		if err != nil {
			return err
		}
	}
	defer log.CloseAndLogError(t, "tablewriter")

	return t.Render()
}

func outputJSON(writer io.Writer, result *diff.Result) error {
	enc := json.NewEncoder(writer)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}
