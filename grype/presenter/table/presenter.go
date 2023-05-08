package table

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/olekukonko/tablewriter"

	grypeDb "github.com/anchore/grype/grype/db/v5"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/presenter/models"
	"github.com/anchore/grype/grype/vulnerability"
)

const (
	appendSuppressed = " (suppressed)"
)

// Presenter is a generic struct for holding fields needed for reporting
type Presenter struct {
	results          match.Matches
	ignoredMatches   []match.IgnoredMatch
	packages         []pkg.Package
	metadataProvider vulnerability.MetadataProvider
	showSuppressed   bool
	noColor          bool
}

// NewPresenter is a *Presenter constructor
func NewPresenter(pb models.PresenterConfig, showSuppressed bool, noColor bool) *Presenter {
	return &Presenter{
		results:          pb.Matches,
		ignoredMatches:   pb.IgnoredMatches,
		packages:         pb.Packages,
		metadataProvider: pb.MetadataProvider,
		showSuppressed:   showSuppressed,
		noColor:          noColor,
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
			row, err := createRow(m.Match, pres.metadataProvider, appendSuppressed)

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

	// sort by name, version, then type
	sort.SliceStable(rows, func(i, j int) bool {
		for col := 0; col < len(columns); col++ {
			if rows[i][col] != rows[j][col] {
				return rows[i][col] < rows[j][col]
			}
		}
		return false
	})
	rows = removeDuplicateRows(rows)

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

	if !pres.noColor {
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

	metadata, err := metadataProvider.GetMetadata(m.Vulnerability.ID, m.Vulnerability.Namespace)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch vuln=%q metadata: %+v", m.Vulnerability.ID, err)
	}

	if metadata != nil {
		severity = metadata.Severity + severitySuffix
	}

	fixVersion := strings.Join(m.Vulnerability.Fix.Versions, ", ")
	switch m.Vulnerability.Fix.State {
	case grypeDb.WontFixState:
		fixVersion = "(won't fix)"
	case grypeDb.UnknownFixState:
		fixVersion = ""
	}

	return []string{m.Package.Name, m.Package.Version, fixVersion, string(m.Package.Type), m.Vulnerability.ID, severity}, nil
}
