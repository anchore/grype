package commands

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

func DBSearch(app clio.Application) *cobra.Command {
	opts := &dbSearchMatchOptions{
		Format: options.DBSearchFormat{
			Output: tableOutputFormat,
			Allowable: []string{
				tableOutputFormat,
				jsonOutputFormat,
			},
		},
		Vulnerability: options.DBSearchVulnerabilities{
			UseVulnIDFlag: true,
		},
		Bounds: options.DBSearchBounds{
			RecordLimit: 1000,
		},
		DBOptions: *dbOptionsDefault(app.ID()),
	}

	cmd := &cobra.Command{
		// this is here to support v5 functionality today but will be removed when v6 is the default DB version
		Use:     "search",
		Short:   "Search the DB for vulnerabilities or affected packages",
		PreRunE: disableUI(app),
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			if opts.Experimental.DBv6 {
				if len(args) > 0 {
					// try to stay backwards compatible with v5 search command
					opts.Vulnerability.VulnerabilityIDs = append(opts.Vulnerability.VulnerabilityIDs, args...)
					if err := opts.Vulnerability.PostLoad(); err != nil {
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

	return app.SetupCommand(cmd, opts)
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

	if len(rows) == 0 {
		return errors.New("no affected packages found")
	}

	sb := &strings.Builder{}
	err = presentDBSearchMatches(opts.Format.Output, rows, sb)
	bus.Report(sb.String())
	if err != nil {
		return fmt.Errorf("unable to present search results: %w", err)
	}
	return queryErr
}

func presentDBSearchMatches(outputFormat string, structuredRows dbsearch.Matches, output io.Writer) error {
	if len(structuredRows) == 0 {
		// TODO: show a message that no results were found?
		return nil
	}

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
	log.Debug("loading DB")
	str, status, err := grype.LoadVulnerabilityDB(opts.DB.ToLegacyCuratorConfig(), opts.DB.AutoUpdate)
	err = validateDBLoad(err, status)
	if err != nil {
		return err
	}
	defer log.CloseAndLogError(str, status.Location)

	var vulnerabilities []vulnerability.Vulnerability
	for _, vulnerabilityID := range vulnerabilityIDs {
		vulns, err := str.Get(vulnerabilityID, "")
		if err != nil {
			return fmt.Errorf("unable to get vulnerability %q: %w", vulnerabilityID, err)
		}
		vulnerabilities = append(vulnerabilities, vulns...)
	}

	if len(vulnerabilities) == 0 {
		return errors.New("no affected packages found")
	}

	sb := &strings.Builder{}
	err = presentLegacyDBSearchPackages(opts.Format.Output, vulnerabilities, sb)
	bus.Report(sb.String())

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

// mimic v5 behavior:
// +--------------------------------------+
// | namespace                            |
// +--------------------------------------+
// | nvd:cpe                              |
// | github:language:javascript           |
// | ubuntu:distro:ubuntu:14.04           |
// | ubuntu:distro:ubuntu:16.04           |
// | ubuntu:distro:ubuntu:18.04           |
// | ubuntu:distro:ubuntu:20.04           |
// | ubuntu:distro:ubuntu:22.04           |
// | ubuntu:distro:ubuntu:22.10           |
// | ubuntu:distro:ubuntu:23.04           |
// | ubuntu:distro:ubuntu:23.10           |
// | ubuntu:distro:ubuntu:24.10           |
// | debian:distro:debian:8               |
// | debian:distro:debian:9               |
// | ubuntu:distro:ubuntu:12.04           |
// | ubuntu:distro:ubuntu:15.04           |
// | sles:distro:sles:15                  |
// | sles:distro:sles:15.1                |
// | sles:distro:sles:15.2                |
// | sles:distro:sles:15.3                |
// | sles:distro:sles:15.4                |
// | sles:distro:sles:15.5                |
// | sles:distro:sles:15.6                |
// | amazon:distro:amazonlinux:2          |
// | debian:distro:debian:10              |
// | debian:distro:debian:11              |
// | debian:distro:debian:12              |
// | debian:distro:debian:unstable        |
// | oracle:distro:oraclelinux:6          |
// | oracle:distro:oraclelinux:7          |
// | oracle:distro:oraclelinux:8          |
// | oracle:distro:oraclelinux:9          |
// | redhat:distro:redhat:6               |
// | redhat:distro:redhat:7               |
// | redhat:distro:redhat:8               |
// | redhat:distro:redhat:9               |
// | ubuntu:distro:ubuntu:12.10           |
// | ubuntu:distro:ubuntu:13.04           |
// | ubuntu:distro:ubuntu:14.10           |
// | ubuntu:distro:ubuntu:15.10           |
// | ubuntu:distro:ubuntu:16.10           |
// | ubuntu:distro:ubuntu:17.04           |
// | ubuntu:distro:ubuntu:17.10           |
// | ubuntu:distro:ubuntu:18.10           |
// | ubuntu:distro:ubuntu:19.04           |
// | ubuntu:distro:ubuntu:19.10           |
// | ubuntu:distro:ubuntu:20.10           |
// | ubuntu:distro:ubuntu:21.04           |
// | ubuntu:distro:ubuntu:21.10           |
// | ubuntu:distro:ubuntu:24.04           |
// | github:language:php                  |
// | debian:distro:debian:13              |
// | debian:distro:debian:7               |
// | redhat:distro:redhat:5               |
// | sles:distro:sles:11.1                |
// | sles:distro:sles:11.3                |
// | sles:distro:sles:11.4                |
// | sles:distro:sles:11.2                |
// | sles:distro:sles:12                  |
// | sles:distro:sles:12.1                |
// | sles:distro:sles:12.2                |
// | sles:distro:sles:12.3                |
// | sles:distro:sles:12.4                |
// | sles:distro:sles:12.5                |
// | chainguard:distro:chainguard:rolling |
// | wolfi:distro:wolfi:rolling           |
// | github:language:go                   |
// | alpine:distro:alpine:3.20            |
// | alpine:distro:alpine:3.21            |
// | alpine:distro:alpine:edge            |
// | github:language:rust                 |
// | github:language:python               |
// | sles:distro:sles:11                  |
// | oracle:distro:oraclelinux:5          |
// | github:language:ruby                 |
// | github:language:dotnet               |
// | alpine:distro:alpine:3.12            |
// | alpine:distro:alpine:3.13            |
// | alpine:distro:alpine:3.14            |
// | alpine:distro:alpine:3.15            |
// | alpine:distro:alpine:3.16            |
// | alpine:distro:alpine:3.17            |
// | alpine:distro:alpine:3.18            |
// | alpine:distro:alpine:3.19            |
// | mariner:distro:mariner:2.0           |
// | github:language:java                 |
// | github:language:dart                 |
// | amazon:distro:amazonlinux:2023       |
// | alpine:distro:alpine:3.10            |
// | alpine:distro:alpine:3.11            |
// | alpine:distro:alpine:3.4             |
// | alpine:distro:alpine:3.5             |
// | alpine:distro:alpine:3.7             |
// | alpine:distro:alpine:3.8             |
// | alpine:distro:alpine:3.9             |
// | mariner:distro:azurelinux:3.0        |
// | mariner:distro:mariner:1.0           |
// | alpine:distro:alpine:3.3             |
// | alpine:distro:alpine:3.6             |
// | amazon:distro:amazonlinux:2022       |
// | alpine:distro:alpine:3.2             |
// | github:language:swift                |
// +--------------------------------------+
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

		return fmt.Sprintf("%s:distro:%s:%s", row.Vulnerability.Provider, family, row.OS.Version)
	}
	return row.Vulnerability.Provider
}
