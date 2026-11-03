package commands

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"

	"github.com/scylladb/go-set/strset"
	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/grype/cmd/grype/cli/commands/internal/dbsearch"
	"github.com/anchore/grype/cmd/grype/cli/options"
	v6 "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/distribution"
	"github.com/anchore/grype/grype/db/v6/installation"
	"github.com/anchore/grype/internal/bus"
	"github.com/anchore/grype/internal/log"
)

type dbSearchMatchOptions struct {
	Format        options.DBSearchFormat          `yaml:",inline" mapstructure:",squash"`
	Vulnerability options.DBSearchVulnerabilities `yaml:",inline" mapstructure:",squash"`
	Package       options.DBSearchPackages        `yaml:",inline" mapstructure:",squash"`
	OS            options.DBSearchOSs             `yaml:",inline" mapstructure:",squash"`
	Bounds        options.DBSearchBounds          `yaml:",inline" mapstructure:",squash"`

	options.DatabaseCommand `yaml:",inline" mapstructure:",squash"`
}

var alasPattern = regexp.MustCompile(`^alas[\w]*-\d+-\d+$`)

func (o *dbSearchMatchOptions) applyArgs(args []string) error {
	for _, arg := range args {
		lowerArg := strings.ToLower(arg)
		switch {
		case hasAnyPrefix(lowerArg, "cpe:", "purl:"):
			// this is explicitly a package...
			log.WithFields("value", arg).Trace("assuming arg is a package specifier")
			o.Package.Packages = append(o.Package.Packages, arg)
		case hasAnyPrefix(lowerArg, "cve-", "ghsa-", "elsa-", "rhsa-") || alasPattern.MatchString(lowerArg):
			// this is a vulnerability...
			log.WithFields("value", arg).Trace("assuming arg is a vulnerability ID")
			o.Vulnerability.VulnerabilityIDs = append(o.Vulnerability.VulnerabilityIDs, arg)
		default:
			// assume this is a package name
			log.WithFields("value", arg).Trace("assuming arg is a package name")
			o.Package.Packages = append(o.Package.Packages, arg)
		}
	}

	if err := o.Vulnerability.PostLoad(); err != nil {
		return err
	}

	if err := o.Package.PostLoad(); err != nil {
		return err
	}

	return nil
}

func hasAnyPrefix(s string, prefixes ...string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(s, prefix) {
			return true
		}
	}
	return false
}

func DBSearch(app clio.Application) *cobra.Command {
	opts := &dbSearchMatchOptions{
		Format: options.DefaultDBSearchFormat(),
		Vulnerability: options.DBSearchVulnerabilities{
			UseVulnIDFlag: true,
		},
		Bounds:          options.DefaultDBSearchBounds(),
		DatabaseCommand: *options.DefaultDatabaseCommand(app.ID()),
	}

	cmd := &cobra.Command{
		Use:   "search",
		Short: "Search the DB for vulnerabilities or affected packages",
		Example: `
  Search for affected packages by vulnerability ID:

    $ grype db search --vuln ELSA-2023-12205

  Search for affected packages by package name:

    $ grype db search --pkg log4j

  Search for affected packages by package name, filtering down to a specific vulnerability:

    $ grype db search --pkg log4j --vuln CVE-2021-44228

  Search for affected packages by PURL (note: version is not considered):

    $ grype db search --pkg 'pkg:rpm/redhat/openssl' # or: '--ecosystem rpm --pkg openssl

  Search for affected packages by CPE (note: version/update is not considered):

    $ grype db search --pkg 'cpe:2.3:a:jetty:jetty_http_server:*:*:*:*:*:*:*:*'
    $ grype db search --pkg 'cpe:/a:jetty:jetty_http_server'`,
		PreRunE: disableUI(app),
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			if len(args) > 0 {
				// try to stay backwards compatible with v5 search command (which takes args)
				if err := opts.applyArgs(args); err != nil {
					return err
				}
			}
			err = runDBSearchMatches(*opts)
			if err != nil {
				if errors.Is(err, dbsearch.ErrNoSearchCriteria) {
					_ = cmd.Usage()
				}
				return err
			}
			return nil
		},
	}

	cmd.AddCommand(
		DBSearchVulnerabilities(app),
	)

	// prevent from being shown in the grype config
	type configWrapper struct {
		Hidden                   *dbSearchMatchOptions `json:"-" yaml:"-" mapstructure:"-"`
		*options.DatabaseCommand `yaml:",inline" mapstructure:",squash"`
	}

	return app.SetupCommand(cmd, &configWrapper{Hidden: opts, DatabaseCommand: &opts.DatabaseCommand})
}

func runDBSearchMatches(opts dbSearchMatchOptions) error {
	client, err := distribution.NewClient(opts.ToClientConfig())
	if err != nil {
		return fmt.Errorf("unable to create distribution client: %w", err)
	}

	curator, err := installation.NewCurator(opts.ToCuratorConfig(), client)
	if err != nil {
		return fmt.Errorf("unable to create curator: %w", err)
	}

	reader, err := curator.Reader()
	if err != nil {
		return fmt.Errorf("unable to get providers: %w", err)
	}

	if err := validateProvidersFilter(reader, opts.Vulnerability.Providers); err != nil {
		return err
	}

	rows, queryErr := dbsearch.FindMatches(reader, dbsearch.AffectedPackagesOptions{
		Vulnerability:         opts.Vulnerability.Specs,
		Package:               opts.Package.PkgSpecs,
		CPE:                   opts.Package.CPESpecs,
		OS:                    opts.OS.Specs,
		AllowBroadCPEMatching: opts.Package.AllowBroadCPEMatching,
		RecordLimit:           opts.Bounds.RecordLimit,
		FixedStates:           opts.Vulnerability.FixedState,
	})
	if queryErr != nil {
		if !errors.Is(queryErr, v6.ErrLimitReached) {
			return queryErr
		}
	}

	sb := &strings.Builder{}
	err = presentDBSearchMatches(opts.Format.Output, rows, sb)
	rep := sb.String()
	if rep != "" {
		bus.Report(rep)
	}
	if err != nil {
		return fmt.Errorf("unable to present search results: %w", err)
	}

	return queryErr
}

func presentDBSearchMatches(outputFormat string, structuredRows dbsearch.Matches, output io.Writer) error {
	switch outputFormat {
	case tableOutputFormat:
		if len(structuredRows) == 0 {
			bus.Notify("No results found")
			return nil
		}
		rows := renderDBSearchPackagesTableRows(structuredRows)

		table := newTable(output, []string{"Vulnerability", "Package", "Ecosystem", "Namespace", "Version Constraint"})

		if err := table.Bulk(rows); err != nil {
			return fmt.Errorf("failed to add table rows: %+v", err)
		}
		return table.Render()
	case jsonOutputFormat:
		if structuredRows == nil {
			// always allocate the top level collection
			structuredRows = dbsearch.Matches{}
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

// packageTableRowKey identifies a table row, all package records with the same key are displayed on a single row
type packageTableRowKey struct {
	vulnerability string
	pkgOrCPE      string
	ecosystem     string
	namespace     string
}

// anyVersionConstraint is displayed for package records without a version constraint, which apply to all versions
const anyVersionConstraint = "*"

// packageTableRowConstraints is the set of version constraints from all package records displayed on a single table row
type packageTableRowConstraints struct {
	affected   []string
	unaffected []string
}

// String renders the affected constraints followed by the unaffected constraints, e.g. "< 1.2.3; unaffected: = 1.2.0+patch.1"
func (c packageTableRowConstraints) String() string {
	var parts []string
	if len(c.affected) > 0 {
		parts = append(parts, joinConstraints(c.affected))
	}
	if len(c.unaffected) > 0 {
		parts = append(parts, "unaffected: "+joinConstraints(c.unaffected))
	}
	return strings.Join(parts, "; ")
}

// joinConstraints returns the distinct constraints in sorted order, joined with "||" since "," is an AND within a single constraint
func joinConstraints(constraints []string) string {
	distinct := strset.New(constraints...).List()
	sort.Strings(distinct)
	return strings.Join(distinct, " || ")
}

func renderDBSearchPackagesTableRows(matches dbsearch.Matches) [][]string {
	var keys []packageTableRowKey
	constraintsByKey := make(map[packageTableRowKey]*packageTableRowConstraints)

	// rowConstraints returns the constraints of the table row that the package record is displayed on
	rowConstraints := func(rr dbsearch.AffectedPackage) *packageTableRowConstraints {
		var pkgOrCPE, ecosystem string
		if rr.Package != nil {
			pkgOrCPE = rr.Package.Name
			ecosystem = rr.Package.Ecosystem
		} else if rr.CPE != nil {
			pkgOrCPE = rr.CPE.String()
			ecosystem = rr.CPE.TargetSoftware
		}

		key := packageTableRowKey{
			vulnerability: rr.Vulnerability.ID,
			pkgOrCPE:      pkgOrCPE,
			ecosystem:     ecosystem,
			namespace:     mimicV5Namespace(rr),
		}
		constraints, ok := constraintsByKey[key]
		if !ok {
			constraints = &packageTableRowConstraints{}
			constraintsByKey[key] = constraints
			keys = append(keys, key)
		}
		return constraints
	}

	for _, m := range matches {
		for _, pkg := range m.AffectedPackages {
			constraints := rowConstraints(dbsearch.AffectedPackage{Vulnerability: m.Vulnerability, AffectedPackageInfo: pkg})
			constraints.affected = append(constraints.affected, versionConstraints(pkg)...)
		}
		for _, pkg := range m.Unaffected {
			constraints := rowConstraints(dbsearch.AffectedPackage{Vulnerability: m.Vulnerability, AffectedPackageInfo: pkg})
			constraints.unaffected = append(constraints.unaffected, versionConstraints(pkg)...)
		}
	}

	var rows [][]string
	for _, key := range keys {
		rows = append(rows, []string{key.vulnerability, key.pkgOrCPE, key.ecosystem, key.namespace, constraintsByKey[key].String()})
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

// versionConstraints returns the version constraints of the package record ranges, using anyVersionConstraint for
// ranges or records without a version constraint so they are not hidden by other records displayed on the same row
func versionConstraints(pkg dbsearch.AffectedPackageInfo) []string {
	var constraints []string
	for _, ra := range pkg.Detail.Ranges {
		constraint := ra.Version.Constraint
		if constraint == "" {
			constraint = anyVersionConstraint
		}
		constraints = append(constraints, constraint)
	}
	if len(constraints) == 0 {
		return []string{anyVersionConstraint}
	}
	return constraints
}

func mimicV5Namespace(row dbsearch.AffectedPackage) string {
	namespace := v6.MimicV5Namespace(&row.Vulnerability.Model, row.Model)

	if row.Model != nil && row.Model.OperatingSystem != nil && row.Model.OperatingSystem.Channel != "" {
		return namespace + ":" + row.Model.OperatingSystem.Channel
	}

	return namespace
}
