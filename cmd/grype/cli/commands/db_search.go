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
	"github.com/anchore/grype/grype/db"
	v6 "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/distribution"
	"github.com/anchore/grype/grype/db/v6/installation"
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
		Output:    tableOutputFormat,
		DBOptions: *dbOptionsDefault(app.ID()),
	}

	return app.SetupCommand(&cobra.Command{
		Use:   "search [vulnerability_id]",
		Short: "get information on a vulnerability from the db",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) (err error) {
			id := args[0]
			return runDBSearch(*opts, id)
		},
	}, opts)
}

func runDBSearch(opts dbQueryOptions, vulnerabilityID string) error {
	if opts.Experimental.DBv6 {
		return newDBSearch(opts, vulnerabilityID)
	}
	return legacyDBSearch(opts, vulnerabilityID)
}

func newDBSearch(opts dbQueryOptions, vulnerabilityID string) error {
	client, err := distribution.NewClient(opts.DB.ToClientConfig())
	if err != nil {
		return fmt.Errorf("unable to create distribution client: %w", err)
	}

	c, err := installation.NewCurator(opts.DB.ToCuratorConfig(), client)
	if err != nil {
		return fmt.Errorf("unable to create curator: %w", err)
	}

	reader, err := c.Reader()
	if err != nil {
		return fmt.Errorf("unable to get providers: %w", err)
	}

	vh, err := reader.GetVulnerabilities(&v6.VulnerabilitySpecifier{Name: vulnerabilityID}, &v6.GetVulnerabilityOptions{
		Preload: true,
	})
	if err != nil {
		return fmt.Errorf("unable to get vulnerability: %w", err)
	}

	if len(vh) == 0 {
		return fmt.Errorf("vulnerability doesn't exist in the DB: %s", vulnerabilityID)
	}

	// TODO: we need to implement the functions that inflate models to the grype vulnerability.Vulnerability struct
	panic("not implemented")
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// all legacy processing below ////////////////////////////////////////////////////////////////////////////////////////

func legacyDBSearch(opts dbQueryOptions, vulnerabilityID string) error {
	log.Debug("loading DB")
	str, status, err := grype.LoadVulnerabilityDB(opts.DB.ToLegacyCuratorConfig(), opts.DB.AutoUpdate)
	err = validateDBLoad(err, status)
	if err != nil {
		return err
	}
	defer log.CloseAndLogError(str, status.Location)

	vulnerabilities, err := str.FindVulnerabilities(db.ByID(vulnerabilityID))
	if err != nil {
		return err
	}

	if len(vulnerabilities) == 0 {
		return fmt.Errorf("vulnerability doesn't exist in the DB: %s", vulnerabilityID)
	}

	sb := &strings.Builder{}
	err = presentLegacy(opts.Output, vulnerabilities, sb)
	bus.Report(sb.String())

	return err
}

func presentLegacy(outputFormat string, vulnerabilities []vulnerability.Vulnerability, output io.Writer) error {
	if vulnerabilities == nil {
		return nil
	}

	switch outputFormat {
	case tableOutputFormat:
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
	case jsonOutputFormat:
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
