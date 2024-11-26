package commands

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/grype/grype"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/bus"
	"github.com/anchore/grype/internal/log"
)

type dbQueryOptions struct {
	Output    string `yaml:"output" json:"output" mapstructure:"output"`
	DBOptions `yaml:",inline" mapstructure:",squash"`
}

var _ clio.FlagAdder = (*dbQueryOptions)(nil)

func (c *dbQueryOptions) AddFlags(flags clio.FlagSet) {
	flags.StringVarP(&c.Output, "output", "o", "format to display results (available=[table, json])")
}

func DBSearch(app clio.Application) *cobra.Command {
	opts := &dbQueryOptions{
		Output:    "table",
		DBOptions: *dbOptionsDefault(app.ID()),
	}

	return app.SetupCommand(&cobra.Command{
		Use:   "search [vulnerability_id]",
		Short: "get information on a vulnerability from the db",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) (err error) {
			id := args[0]
			return runDBSearch(opts, id)
		},
	}, opts)
}

func runDBSearch(opts *dbQueryOptions, vulnerabilityID string) error {
	log.Debug("loading DB")
	str, status, dbCloser, err := grype.LoadVulnerabilityDB(opts.DB.ToLegacyCuratorConfig(), opts.DB.AutoUpdate)
	err = validateDBLoad(err, status)
	if err != nil {
		return err
	}
	if dbCloser != nil {
		defer dbCloser.Close()
	}

	vulnerabilities, err := str.Get(vulnerabilityID, "")
	if err != nil {
		return err
	}

	sb := &strings.Builder{}
	if len(vulnerabilities) == 0 {
		return fmt.Errorf("vulnerability doesn't exist in the DB: %s", vulnerabilityID)
	}

	err = present(opts.Output, vulnerabilities, sb)
	bus.Report(sb.String())

	return err
}

func present(outputFormat string, vulnerabilities []vulnerability.Vulnerability, output io.Writer) error {
	if vulnerabilities == nil {
		return nil
	}

	switch outputFormat {
	case "table":
		rows := [][]string{}
		for _, v := range vulnerabilities {
			rows = append(rows, []string{v.ID, v.PackageName, v.Namespace, v.Constraint.String()})
		}

		table := tablewriter.NewWriter(output)
		columns := []string{"ID", "Package Name", "Namespace", "Version Constraint"}

		table.SetHeader(columns)
		table.SetAutoWrapText(false)
		table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
		table.SetAlignment(tablewriter.ALIGN_LEFT)

		table.SetHeaderLine(false)
		table.SetBorder(false)
		table.SetAutoFormatHeaders(true)
		table.SetCenterSeparator("")
		table.SetColumnSeparator("")
		table.SetRowSeparator("")
		table.SetTablePadding("  ")
		table.SetNoWhiteSpace(true)

		table.AppendBulk(rows)
		table.Render()
	case "json":
		enc := json.NewEncoder(output)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", " ")
		if err := enc.Encode(vulnerabilities); err != nil {
			return fmt.Errorf("failed to encode diff information: %+v", err)
		}
	default:
		return fmt.Errorf("unsupported output format: %s", outputFormat)
	}
	return nil
}
