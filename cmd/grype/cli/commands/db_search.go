package commands

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/grype/cmd/grype/cli/commands/internal/dbsearch"
	"github.com/anchore/grype/cmd/grype/cli/options"
	"github.com/anchore/grype/grype"
	v6 "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/distribution"
	"github.com/anchore/grype/grype/db/v6/installation"
	"github.com/anchore/grype/grype/search"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/bus"
	"github.com/anchore/grype/internal/log"
)

type dbSearchMatchOptions struct {
	Format        options.DBSearchFormat          `yaml:",inline" mapstructure:",squash"`
	Vulnerability options.DBSearchVulnerabilities `yaml:",inline" mapstructure:",squash"`
	Package       options.DBSearchPackages        `yaml:",inline" mapstructure:",squash"`
	OS            options.DBSearchOSs             `yaml:",inline" mapstructure:",squash"`
	Bounds        options.DBSearchBounds          `yaml:",inline" mapstructure:",squash"`

	DBOptions `yaml:",inline" mapstructure:",squash"`
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
		Bounds:    options.DefaultDBSearchBounds(),
		DBOptions: *dbOptionsDefault(app.ID()),
	}

	cmd := &cobra.Command{
		// this is here to support v5 functionality today but will be removed when v6 is the default DB version
		Use:   "search VULN|PKG...",
		Short: "Search the DB for vulnerabilities or affected packages",
		Example: `
  Search for affected packages by vulnerability ID:

    $ grype db search ELSA-2023-12205            # same as '--vuln ELSA-2023-12205'

  Search for affected packages by package name:

    $ grype db search log4j                      # same as '--pkg log4j'

  Search for affected packages by package name, filtering down to a specific vulnerability:

    $ grype db search log4j CVE-2021-44228       # same as '--pkg log4j --vuln CVE-2021-44228'

  Search for affected packages by PURL (note: version is not considered):

    $ grype db search 'pkg:rpm/redhat/openssl'   # same as '--ecosystem rpm --pkg openssl'

  Search for affected packages by CPE (note: version/update is not considered):

    $ grype db search 'cpe:2.3:a:jetty:jetty_http_server:*:*:*:*:*:*'
    $ grype db search 'cpe:/a:jetty:jetty_http_server'`,
		PreRunE: disableUI(app),
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			if opts.Experimental.DBv6 {
				if len(args) > 0 {
					// try to stay backwards compatible with v5 search command (which takes args)
					if err := opts.applyArgs(args); err != nil {
						return err
					}
				}
				err := runDBSearchMatches(*opts)
				if err != nil {
					if errors.Is(err, dbsearch.ErrNoSearchCriteria) {
						_ = cmd.Usage()
					}
					return err
				}
				return nil
			}

			// this is v5, do arg handling here. Why not do this earlier in the struct Args field? When v6 functionality is
			// enabled we want this command to show usage and exit, so we need to do this check later in processing (here).
			if err := cobra.MinimumNArgs(1)(cmd, args); err != nil {
				return err
			}
			return legacyDBSearchPackages(*opts, args)
		},
	}

	cmd.AddCommand(
		DBSearchVulnerabilities(app),
	)

	// prevent from being shown in the grype config
	type configWrapper struct {
		Hidden     *dbSearchMatchOptions `json:"-" yaml:"-" mapstructure:"-"`
		*DBOptions `yaml:",inline" mapstructure:",squash"`
	}

	return app.SetupCommand(cmd, &configWrapper{Hidden: opts, DBOptions: &opts.DBOptions})
}

func runDBSearchMatches(opts dbSearchMatchOptions) error {
	client, err := distribution.NewClient(opts.DB.ToClientConfig())
	if err != nil {
		return fmt.Errorf("unable to create distribution client: %w", err)
	}

	curator, err := installation.NewCurator(opts.DB.ToCuratorConfig(), client)
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
		Vulnerability: opts.Vulnerability.Specs,
		Package:       opts.Package.PkgSpecs,
		CPE:           opts.Package.CPESpecs,
		OS:            opts.OS.Specs,
		RecordLimit:   opts.Bounds.RecordLimit,
	})
	if queryErr != nil {
		if !errors.Is(queryErr, v6.ErrLimitReached) {
			return queryErr
		}
	}

	if len(rows) != 0 {
		sb := &strings.Builder{}
		err = presentDBSearchMatches(opts.Format.Output, rows, sb)
		bus.Report(sb.String())
		if err != nil {
			return fmt.Errorf("unable to present search results: %w", err)
		}
	} else {
		bus.Notify("No results found")
	}

	return queryErr
}

func presentDBSearchMatches(outputFormat string, structuredRows dbsearch.Matches, output io.Writer) error {
	switch outputFormat {
	case tableOutputFormat:
		rows := renderDBSearchPackagesTableRows(structuredRows.Flatten())

		table := newTable(output)

		table.SetHeader([]string{"Vulnerability", "Package", "Ecosystem", "Namespace", "Version Constraint"})
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

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// legacy search functionality

func legacyDBSearchPackages(opts dbSearchMatchOptions, vulnerabilityIDs []string) error {
	if len(opts.Package.CPESpecs) > 0 {
		return errors.New("CPE search is not supported with the v5 DB schema")
	}

	if len(opts.Package.PkgSpecs) > 0 {
		return errors.New("package search is not supported with the v5 DB schema")
	}

	log.Debug("loading DB")
	str, status, err := grype.LoadVulnerabilityDB(opts.DB.ToLegacyCuratorConfig(), opts.DB.AutoUpdate)
	err = validateDBLoad(err, status)
	if err != nil {
		return err
	}
	defer log.CloseAndLogError(str, status.Location)

	var vulnerabilities []vulnerability.Vulnerability
	for _, vulnerabilityID := range vulnerabilityIDs {
		vulns, err := str.FindVulnerabilities(search.ByID(vulnerabilityID))
		if err != nil {
			return fmt.Errorf("unable to get vulnerability %q: %w", vulnerabilityID, err)
		}
		vulnerabilities = append(vulnerabilities, vulns...)
	}

	if len(vulnerabilities) != 0 {
		sb := &strings.Builder{}
		err = presentLegacyDBSearchPackages(opts.Format.Output, vulnerabilities, sb)
		bus.Report(sb.String())
	}

	return err
}

func presentLegacyDBSearchPackages(outputFormat string, vulnerabilities []vulnerability.Vulnerability, output io.Writer) error {
	if vulnerabilities == nil {
		return nil
	}

	switch outputFormat {
	case tableOutputFormat:
		rows := [][]string{}
		for _, v := range vulnerabilities {
			rows = append(rows, []string{v.ID, v.PackageName, v.Namespace, v.Constraint.String()})
		}

		table := newTable(output)

		table.SetHeader([]string{"ID", "Package Name", "Namespace", "Version Constraint"})
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

func renderDBSearchPackagesTableRows(structuredRows []dbsearch.AffectedPackage) [][]string {
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

		var ranges []string
		for _, ra := range rr.Detail.Ranges {
			ranges = append(ranges, ra.Version.Constraint)
		}
		rangeStr := strings.Join(ranges, " || ")
		rows = append(rows, []string{rr.Vulnerability.ID, pkgOrCPE, ecosystem, v5Namespace(rr), rangeStr})
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

// v5Namespace returns the namespace for a given affected package based on what schema v5 did.
func v5Namespace(row dbsearch.AffectedPackage) string {
	switch row.Vulnerability.Provider {
	case "nvd":
		return "nvd:cpe"
	case "github":
		language := row.Package.Ecosystem
		// normalize from purl type, github ecosystem types, and vunnel mappings
		switch strings.ToLower(row.Package.Ecosystem) {
		case "golang", "go-module":
			language = "go"
		case "composer", "php-composer":
			language = "php"
		case "cargo", "rust-crate":
			language = "rust"
		case "dart-pub", "pub":
			language = "dart"
		case "nuget":
			language = "dotnet"
		case "maven":
			language = "java"
		case "swifturl":
			language = "swift"
		case "npm", "node":
			language = "javascript"
		case "pypi", "pip":
			language = "python"
		case "rubygems", "gem":
			language = "ruby"
		}
		return fmt.Sprintf("github:language:%s", language)
	}
	if row.OS != nil {
		// distro family fixes
		family := row.OS.Name
		switch row.OS.Name {
		case "amazon":
			family = "amazonlinux"
		case "mariner":
			switch row.OS.Version {
			case "1.0", "2.0":
				family = "mariner"
			default:
				family = "azurelinux"
			}
		case "oracle":
			family = "oraclelinux"
		}

		// provider fixes
		pr := row.Vulnerability.Provider
		if pr == "rhel" {
			pr = "redhat"
		}

		// version fixes
		ver := row.OS.Version
		switch row.Vulnerability.Provider {
		case "rhel", "oracle":
			// ensure we only keep the major version
			ver = strings.Split(row.OS.Version, ".")[0]
		}

		return fmt.Sprintf("%s:distro:%s:%s", pr, family, ver)
	}
	return row.Vulnerability.Provider
}
