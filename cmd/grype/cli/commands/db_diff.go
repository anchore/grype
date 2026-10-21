package commands

import (
	"bufio"
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
	EPSSThreshold           float64     `yaml:"epss-threshold" json:"epss-threshold" mapstructure:"epss-threshold"`
	Include                 diffInclude `json:"include" yaml:"include" mapstructure:"include"`
	Old                     string
	New                     string
}

type diffInclude struct {
	Packages *bool `yaml:"packages" json:"packages" mapstructure:"packages"`
	Vulns    *bool `yaml:"vulns" json:"vulns" mapstructure:"vulns"`
	EPSS     *bool `yaml:"epss" json:"epss" mapstructure:"epss"`
	KEV      *bool `yaml:"kev" json:"kev" mapstructure:"kev"`
}

var _ clio.FlagAdder = (*dbDiffOptions)(nil)

func (d *dbDiffOptions) AddFlags(flags clio.FlagSet) {
	flags.StringVarP(&d.Output, "output", "o", "format to display results (available=[text, json])")
	flags.BoolPtrVarP(&d.Include.Packages, "packages", "", "only include packages")
	flags.BoolPtrVarP(&d.Include.Vulns, "vulns", "", "only include vulnerabilities")
}

func (d *dbDiffOptions) ToIncludes() diff.Includes {
	def := diff.DefaultConfig()
	if d.Include.Packages != nil {
		def.Include.Packages = *d.Include.Packages
	}
	if d.Include.Vulns != nil {
		def.Include.Vulns = *d.Include.Vulns
	}
	if d.Include.EPSS != nil {
		def.Include.EPSS = *d.Include.EPSS
	}
	if d.Include.KEV != nil {
		def.Include.KEV = *d.Include.KEV
	}
	return def.Include
}

func DBDiff(app clio.Application) *cobra.Command {
	cfg := diff.DefaultConfig()
	opts := &dbDiffOptions{
		Output:          textOutputFormat,
		DatabaseCommand: *options.DefaultDatabaseCommand(app.ID()),
		EPSSThreshold:   cfg.EPSSThreshold,
		Include:         diffInclude{}, // this defaults to packages, vulns, and kev where flags will override
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

	d, err := diff.NewDBDiffer(diff.Config{
		Config:        opts.ToCuratorConfig(),
		Include:       opts.ToIncludes(),
		Debug:         opts.Developer.DB.Debug,
		EPSSThreshold: opts.EPSSThreshold,
		OldDB:         opts.Old,
		NewDB:         opts.New,
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

// outputJSON writes the result as indented JSON. This is equivalent to encoding the result with a json.Encoder, but
// encodes one package at a time: a diff can contain millions of changes, and encoding the whole result at once
// requires holding several copies of the full document in memory.
func outputJSON(writer io.Writer, result *diff.Result) error {
	// bufio.Writer errors are sticky (later writes are no-ops and Flush returns the error), so only the first
	// marshal error needs tracking
	w := bufio.NewWriter(writer)
	var err error
	write := func(s string) { _, _ = w.WriteString(s) }
	writeValue := func(value any, prefix string) {
		if err != nil {
			return
		}
		var data []byte
		data, err = json.MarshalIndent(value, prefix, "  ")
		_, _ = w.Write(data)
	}

	// fields are written in the order they are defined on diff.Result, honoring their omitempty options
	write("{\n  \"schema\": ")
	writeValue(result.Schema, "  ")
	write(",\n  \"databases\": ")
	writeValue(result.Databases, "  ")
	if len(result.Packages) > 0 {
		write(",\n  \"packages\": [")
		for i, p := range result.Packages {
			if i > 0 {
				write(",")
			}
			write("\n    ")
			writeValue(p, "    ")
		}
		write("\n  ]")
	}
	if result.Vulnerabilities != nil {
		write(",\n  \"vulnerabilities\": ")
		writeValue(result.Vulnerabilities, "  ")
	}
	write("\n}\n")

	if err != nil {
		return err
	}
	return w.Flush()
}
