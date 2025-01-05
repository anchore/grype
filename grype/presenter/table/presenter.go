package table

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/olekukonko/tablewriter"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/presenter/models"
	"github.com/anchore/grype/grype/vulnerability"
)

const (
	appendSuppressed    = " (suppressed)"
	appendSuppressedVEX = " (suppressed by VEX)"
)

// Presenter is a generic struct for holding fields needed for reporting
type Presenter struct {
	results          match.Matches
	ignoredMatches   []match.IgnoredMatch
	packages         []pkg.Package
	metadataProvider vulnerability.MetadataProvider
	showSuppressed   bool
	withColor        bool
}

// NewPresenter is a *Presenter constructor
func NewPresenter(pb models.PresenterConfig, showSuppressed bool) *Presenter {
	return &Presenter{
		results:          pb.Matches,
		ignoredMatches:   pb.IgnoredMatches,
		packages:         pb.Packages,
		metadataProvider: pb.MetadataProvider,
		showSuppressed:   showSuppressed,
		withColor:        supportsColor(),
	}
}

// Present creates a JSON-based reporting
func (pres *Presenter) Present(output io.Writer) error {
	rows := make([][]string, 0)

	columns := []string{"Name", "Installed", "Fixed-In", "Type", "Vulnerability", "Severity"}
	// Generate rows for matching vulnerabilities
	for m := range pres.results.Enumerate() {
		row, err := createRow(m, pres.metadataProvider, "")
		if err != nil {
			return err
		}
		rows = append(rows, row)
	}

	// Generate rows for suppressed vulnerabilities
	if pres.showSuppressed {
		for _, m := range pres.ignoredMatches {
			msg := appendSuppressed
			if m.AppliedIgnoreRules != nil {
				for i := range m.AppliedIgnoreRules {
					if m.AppliedIgnoreRules[i].Namespace == "vex" {
						msg = appendSuppressedVEX
					}
				}
			}
			row, err := createRow(m.Match, pres.metadataProvider, msg)

			if err != nil {
				return err
			}
			rows = append(rows, row)
		}
	}

	if len(rows) == 0 {
		_, err := io.WriteString(output, "No vulnerabilities found\n")
		return err
	}

	rows = sortRows(removeDuplicateRows(rows))

	table := tablewriter.NewWriter(output)
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

	if pres.withColor {
		for _, row := range rows {
			severityColor := getSeverityColor(row[len(row)-1])
			table.Rich(row, []tablewriter.Colors{{}, {}, {}, {}, {}, severityColor})
		}
	} else {
		table.AppendBulk(rows)
	}

	table.Render()

	return nil
}

func supportsColor() bool {
	return lipgloss.NewStyle().Foreground(lipgloss.Color("5")).Render("") != ""
}

func sortRows(rows [][]string) [][]string {
	// sort
	sort.SliceStable(rows, func(i, j int) bool {
		var (
			name        = 0
			ver         = 1
			fix         = 2
			packageType = 3
			vuln        = 4
			sev         = 5
		)
		// name, version, type, severity, vulnerability
		// > is for numeric sorting like severity or year/number of vulnerability
		// < is for alphabetical sorting like name, version, type
		if rows[i][name] == rows[j][name] {
			if rows[i][ver] == rows[j][ver] {
				if rows[i][packageType] == rows[j][packageType] {
					if models.SeverityScore(rows[i][sev]) == models.SeverityScore(rows[j][sev]) {
						if rows[i][vuln] == rows[j][vuln] {
							return rows[i][fix] < rows[j][fix]
						}
						// we use > here to get the most recently filed vulnerabilities
						// to show at the top of the severity
						return rows[i][vuln] > rows[j][vuln]
					}
					return models.SeverityScore(rows[i][sev]) > models.SeverityScore(rows[j][sev])
				}
				return rows[i][packageType] < rows[j][packageType]
			}
			return rows[i][ver] < rows[j][ver]
		}
		return rows[i][name] < rows[j][name]
	})

	return rows
}

func removeDuplicateRows(items [][]string) [][]string {
	seen := map[string][]string{}
	var result [][]string

	for _, v := range items {
		key := strings.Join(v, "|")
		if seen[key] != nil {
			// dup!
			continue
		}

		seen[key] = v
		result = append(result, v)
	}
	return result
}

func createRow(m match.Match, metadataProvider vulnerability.MetadataProvider, severitySuffix string) ([]string, error) {
	var severity string

	metadata, err := metadataProvider.VulnerabilityMetadata(m.Vulnerability.Reference)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch vuln=%q metadata: %+v", m.Vulnerability.ID, err)
	}

	if metadata != nil {
		severity = metadata.Severity + severitySuffix
	}

	fixVersion := strings.Join(m.Vulnerability.Fix.Versions, ", ")
	switch m.Vulnerability.Fix.State {
	case vulnerability.FixStateWontFix:
		fixVersion = "(won't fix)"
	case vulnerability.FixStateUnknown:
		fixVersion = ""
	}

	return []string{m.Package.Name, m.Package.Version, fixVersion, string(m.Package.Type), m.Vulnerability.ID, severity}, nil
}

func getSeverityColor(severity string) tablewriter.Colors {
	severityFontType, severityColor := tablewriter.Normal, tablewriter.Normal

	switch strings.ToLower(severity) {
	case "critical":
		severityFontType = tablewriter.Bold
		severityColor = tablewriter.FgRedColor
	case "high":
		severityColor = tablewriter.FgRedColor
	case "medium":
		severityColor = tablewriter.FgYellowColor
	case "low":
		severityColor = tablewriter.FgGreenColor
	case "negligible":
		severityColor = tablewriter.FgBlueColor
	}

	return tablewriter.Colors{severityFontType, severityColor}
}
