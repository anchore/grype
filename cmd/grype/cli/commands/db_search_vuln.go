package commands

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/hashicorp/go-multierror"
	"github.com/scylladb/go-set/strset"
	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/grype/cmd/grype/cli/commands/internal/dbsearch"
	"github.com/anchore/grype/cmd/grype/cli/options"
	v6 "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/distribution"
	"github.com/anchore/grype/grype/db/v6/installation"
	"github.com/anchore/grype/internal/bus"
)

type dbSearchVulnerabilityOptions struct {
	Format        options.DBSearchFormat          `yaml:",inline" mapstructure:",squash"`
	Vulnerability options.DBSearchVulnerabilities `yaml:",inline" mapstructure:",squash"`
	Bounds        options.DBSearchBounds          `yaml:",inline" mapstructure:",squash"`

	options.DatabaseCommand `yaml:",inline" mapstructure:",squash"`
}

func DBSearchVulnerabilities(app clio.Application) *cobra.Command {
	opts := &dbSearchVulnerabilityOptions{
		Format: options.DefaultDBSearchFormat(),
		Vulnerability: options.DBSearchVulnerabilities{
			UseVulnIDFlag: false, // we input this through the args
		},
		Bounds:          options.DefaultDBSearchBounds(),
		DatabaseCommand: *options.DefaultDatabaseCommand(app.ID()),
	}

	cmd := &cobra.Command{
		Use:     "vuln ID...",
		Aliases: []string{"vulnerability", "vulnerabilities", "vulns"},
		Short:   "Search for vulnerabilities within the DB (supports DB schema v6+ only)",
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) == 0 {
				return fmt.Errorf("must specify at least one vulnerability ID")
			}
			opts.Vulnerability.VulnerabilityIDs = args
			return nil
		},
		RunE: func(_ *cobra.Command, _ []string) (err error) {
			return runDBSearchVulnerabilities(*opts)
		},
	}

	// prevent from being shown in the grype config
	type configWrapper struct {
		Hidden                   *dbSearchVulnerabilityOptions `json:"-" yaml:"-" mapstructure:"-"`
		*options.DatabaseCommand `yaml:",inline" mapstructure:",squash"`
	}

	return app.SetupCommand(cmd, &configWrapper{Hidden: opts, DatabaseCommand: &opts.DatabaseCommand})
}

func runDBSearchVulnerabilities(opts dbSearchVulnerabilityOptions) error {
	client, err := distribution.NewClient(opts.ToClientConfig())
	if err != nil {
		return fmt.Errorf("unable to create distribution client: %w", err)
	}

	c, err := installation.NewCurator(opts.ToCuratorConfig(), client)
	if err != nil {
		return fmt.Errorf("unable to create curator: %w", err)
	}

	reader, err := c.Reader()
	if err != nil {
		return fmt.Errorf("unable to get providers: %w", err)
	}

	if err := validateProvidersFilter(reader, opts.Vulnerability.Providers); err != nil {
		return err
	}

	rows, err := dbsearch.FindVulnerabilities(reader, dbsearch.VulnerabilitiesOptions{
		Vulnerability: opts.Vulnerability.Specs,
		RecordLimit:   opts.Bounds.RecordLimit,
	})
	if err != nil {
		return err
	}

	sb := &strings.Builder{}
	err = presentDBSearchVulnerabilities(opts.Format.Output, rows, sb)
	rep := sb.String()
	if rep != "" {
		bus.Report(rep)
	}

	return err
}

func validateProvidersFilter(reader v6.Reader, providers []string) error {
	if len(providers) == 0 {
		return nil
	}
	availableProviders, err := reader.AllProviders()
	if err != nil {
		return fmt.Errorf("unable to get providers: %w", err)
	}
	activeProviders := strset.New()
	for _, p := range availableProviders {
		activeProviders.Add(p.ID)
	}

	provSet := strset.New(providers...)

	diff := strset.Difference(provSet, activeProviders)
	diffList := diff.List()
	sort.Strings(diffList)
	var errs error
	for _, p := range diffList {
		errs = multierror.Append(errs, fmt.Errorf("provider not found: %q", p))
	}

	return errs
}

func presentDBSearchVulnerabilities(outputFormat string, structuredRows []dbsearch.Vulnerability, output io.Writer) error {
	switch outputFormat {
	case tableOutputFormat:
		if len(structuredRows) == 0 {
			bus.Notify("No results found")
			return nil
		}

		rows := renderDBSearchVulnerabilitiesTableRows(structuredRows)

		table := newTable(output)

		table.SetHeader([]string{"ID", "Provider", "Published", "Severity", "Reference"})
		table.AppendBulk(rows)
		table.Render()
	case jsonOutputFormat:
		if structuredRows == nil {
			// always allocate the top level collection
			structuredRows = []dbsearch.Vulnerability{}
		}
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

func renderDBSearchVulnerabilitiesTableRows(structuredRows []dbsearch.Vulnerability) [][]string {
	type row struct {
		Vuln                    string
		ProviderWithoutVersions string
		PublishedDate           string
		Severity                string
		Reference               string
	}

	versionsByRow := make(map[row][]string)
	for _, rr := range structuredRows {
		r := row{
			Vuln:                    rr.ID,
			ProviderWithoutVersions: rr.Provider,
			PublishedDate:           getDate(rr.PublishedDate),
			Severity:                rr.Severity,
			Reference:               getPrimaryReference(rr.References),
		}
		versionsByRow[r] = append(versionsByRow[r], getOSVersions(rr.OperatingSystems)...)
	}

	var rows [][]string
	for r, versions := range versionsByRow {
		prov := r.ProviderWithoutVersions
		if len(versions) > 0 {
			sort.Strings(versions)
			prov = fmt.Sprintf("%s (%s)", r.ProviderWithoutVersions, strings.Join(versions, ", "))
		}
		rows = append(rows, []string{r.Vuln, prov, r.PublishedDate, r.Severity, r.Reference})
	}

	// sort rows by each column
	sort.Slice(rows, func(i, j int) bool {
		for k := range rows[i] {
			if rows[i][k] != rows[j][k] {
				return rows[i][k] < rows[j][k]
			}
		}
		return false
	})

	return rows
}

func getOSVersions(oss []dbsearch.OperatingSystem) []string {
	var versions []string
	for _, os := range oss {
		versions = append(versions, os.Version)
	}
	return versions
}

func getPrimaryReference(refs []v6.Reference) string {
	if len(refs) > 0 {
		return refs[0].URL
	}

	return ""
}

func getDate(t *time.Time) string {
	if t != nil && !t.IsZero() {
		return t.Format("2006-01-02")
	}
	return ""
}
