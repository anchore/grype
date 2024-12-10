package commands

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/araddon/dateparse"
	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/grype/cmd/grype/cli/commands/internal/dbsearch"
	"github.com/anchore/grype/grype"
	v6 "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/distribution"
	"github.com/anchore/grype/grype/db/v6/installation"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/bus"
	"github.com/anchore/grype/internal/log"
)

type dbQueryOptions struct {
	Output string `yaml:"output" json:"output" mapstructure:"output"`

	PublishedAfter string `yaml:"published-after" json:"published-after" mapstructure:"published-after"`
	publishedAfter *time.Time

	ModifiedAfter string `yaml:"modified-after" json:"modified-after" mapstructure:"modified-after"`
	modifiedAfter *time.Time

	DBOptions `yaml:",inline" mapstructure:",squash"`
}

var _ clio.FlagAdder = (*dbQueryOptions)(nil)

func (c *dbQueryOptions) AddFlags(flags clio.FlagSet) {
	flags.StringVarP(&c.Output, "output", "o", "format to display results (available=[table, json])")
	flags.StringVarP(&c.PublishedAfter, "published-after", "", "only show vulnerabilities originally published after the given date (format: YYYY-MM-DD) (for v6+ schemas only)")
	flags.StringVarP(&c.ModifiedAfter, "modified-after", "", "only show vulnerabilities originally published or modified since the given date (format: YYYY-MM-DD) (for v6+ schemas only)")
}

func (c *dbQueryOptions) PostLoad() error {
	handleTimeOption := func(val string, flag string) (*time.Time, error) {
		if val == "" {
			return nil, nil
		}
		parsed, err := dateparse.ParseIn(val, time.UTC)
		if err != nil {
			return nil, fmt.Errorf("invalid date format for %s=%q: %w", flag, val, err)
		}
		return &parsed, nil
	}

	if c.PublishedAfter != "" && c.ModifiedAfter != "" {
		return fmt.Errorf("only one of --published-after or --modified-after can be set")
	}

	var err error
	if c.publishedAfter, err = handleTimeOption(c.PublishedAfter, "published-after"); err != nil {
		return err
	}
	if c.modifiedAfter, err = handleTimeOption(c.ModifiedAfter, "modified-after"); err != nil {
		return err
	}

	return nil
}

func DBSearch(app clio.Application) *cobra.Command {
	opts := &dbQueryOptions{
		Output:    tableOutputFormat,
		DBOptions: *dbOptionsDefault(app.ID()),
	}

	return app.SetupCommand(&cobra.Command{
		Use:   "search [vulnerability_id]",
		Short: "get information on a vulnerability from the db",
		Args:  cobra.ArbitraryArgs,
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
	// TODO: refactor this in terms of search function pattern described in #2132 (in other words, the store should not be directly accessed here)

	affectedPkgs, err := reader.GetAffectedPackages(nil, &v6.GetAffectedPackageOptions{
		PreloadOS:            true,
		PreloadPackage:       true,
		PreloadPackageCPEs:   false,
		PreloadVulnerability: true,
		PreloadBlob:          true,
		Distro:               nil,
		Vulnerability: &v6.VulnerabilitySpecifier{
			Name:           vulnerabilityID,
			PublishedAfter: opts.publishedAfter,
			ModifiedAfter:  opts.modifiedAfter,
		},
	})
	if err != nil {
		return fmt.Errorf("unable to get affected packages: %w", err)
	}

	affectedCPEs, err := reader.GetAffectedCPEs(nil, &v6.GetAffectedCPEOptions{
		PreloadCPE:           true,
		PreloadVulnerability: true,
		PreloadBlob:          true,
		Vulnerability: &v6.VulnerabilitySpecifier{
			Name:           vulnerabilityID,
			PublishedAfter: opts.publishedAfter,
			ModifiedAfter:  opts.modifiedAfter,
		},
	})
	if err != nil {
		return fmt.Errorf("unable to get affected cpes: %w", err)
	}

	rows := dbsearch.NewRows(affectedPkgs, affectedCPEs)

	if len(rows) == 0 {
		return fmt.Errorf("no packages affected by the given vulnerability ID: %s", vulnerabilityID)
	}

	sb := &strings.Builder{}
	err = present(opts.Output, rows, sb)
	bus.Report(sb.String())
	return err
}

func present(outputFormat string, structuredRows []dbsearch.Row, output io.Writer) error {
	if len(structuredRows) == 0 {
		// TODO: show a message that no results were found?
		return nil
	}

	switch outputFormat {
	case tableOutputFormat:
		rows := renderTableRows(structuredRows)

		table := tablewriter.NewWriter(output)
		columns := []string{"ID", "Package", "Ecosystem", "Namespace", "Version Constraint"}

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
		if err := enc.Encode(structuredRows); err != nil {
			return fmt.Errorf("failed to encode diff information: %+v", err)
		}
	default:
		return fmt.Errorf("unsupported output format: %s", outputFormat)
	}
	return nil
}

func renderTableRows(structuredRows []dbsearch.Row) [][]string {
	var rows [][]string
	for _, rr := range structuredRows {
		var pkgOrCPE, ecosystem string
		if rr.Package != nil {
			pkgOrCPE = rr.Package.Name
			ecosystem = rr.Package.Ecosystem
		} else if rr.CPE != nil {
			pkgOrCPE = rr.CPE.String()
			ecosystem = rr.CPE.TargetSoftware
		}

		namespace := rr.Vulnerability.Provider
		if rr.OS != nil {
			namespace = fmt.Sprintf("%s:%s", rr.OS.Family, rr.OS.Version)
		}

		var ranges []string
		for _, ra := range rr.Detail.Ranges {
			ranges = append(ranges, ra.Version.Constraint)
		}
		rangeStr := strings.Join(ranges, " || ")
		rows = append(rows, []string{rr.Vulnerability.ID, pkgOrCPE, ecosystem, namespace, rangeStr})
	}
	return rows
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// all legacy processing below ////////////////////////////////////////////////////////////////////////////////////////

func legacyDBSearch(opts dbQueryOptions, vulnerabilityID string) error {
	if opts.modifiedAfter != nil || opts.publishedAfter != nil {
		return fmt.Errorf("date filtering is only available for v6+ schemas")
	}

	log.Debug("loading DB")
	str, status, err := grype.LoadVulnerabilityDB(opts.DB.ToLegacyCuratorConfig(), opts.DB.AutoUpdate)
	err = validateDBLoad(err, status)
	if err != nil {
		return err
	}
	defer log.CloseAndLogError(str, status.Location)

	vulnerabilities, err := str.Get(vulnerabilityID, "")
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
