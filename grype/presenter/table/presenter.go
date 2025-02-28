package table

import (
	"io"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/olekukonko/tablewriter"

	"github.com/anchore/grype/grype/presenter/models"
	"github.com/anchore/grype/grype/vulnerability"
)

const (
	appendSuppressed    = " (suppressed)"
	appendSuppressedVEX = " (suppressed by VEX)"
)

// Presenter is a generic struct for holding fields needed for reporting
type Presenter struct {
	document       models.Document
	showSuppressed bool
	withColor      bool
}

// NewPresenter is a *Presenter constructor
func NewPresenter(pb models.PresenterConfig, showSuppressed bool) *Presenter {
	return &Presenter{
		document:       pb.Document,
		showSuppressed: showSuppressed,
		withColor:      supportsColor(),
	}
}

// Present creates a JSON-based reporting
func (p *Presenter) Present(output io.Writer) error {
	rs := getRows(p.document, p.showSuppressed)

	if len(rs) == 0 {
		_, err := io.WriteString(output, "No vulnerabilities found\n")
		return err
	}

	table := tablewriter.NewWriter(output)
	table.SetHeader([]string{"Name", "Installed", "Fixed-In", "Type", "Vulnerability", "Severity"})
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

	if p.withColor {
		for _, row := range rs.Render() {
			severityColor := getSeverityColor(row[len(row)-1])
			table.Rich(row, []tablewriter.Colors{{}, {}, {}, {}, {}, severityColor})
		}
	} else {
		table.AppendBulk(rs.Render())
	}

	table.Render()

	return nil
}

func getRows(doc models.Document, showSuppressed bool) rows {
	var rs rows

	// generate rows for matching vulnerabilities
	for _, m := range doc.Matches {
		rs = append(rs, newRow(m, ""))
	}

	// generate rows for suppressed vulnerabilities
	if showSuppressed {
		for _, m := range doc.IgnoredMatches {
			msg := appendSuppressed
			if m.AppliedIgnoreRules != nil {
				for i := range m.AppliedIgnoreRules {
					if m.AppliedIgnoreRules[i].Namespace == "vex" {
						msg = appendSuppressedVEX
					}
				}
			}
			rs = append(rs, newRow(m.Match, msg))
		}
	}
	return rs
}

func supportsColor() bool {
	return lipgloss.NewStyle().Foreground(lipgloss.Color("5")).Render("") != ""
}

type rows []row

type row struct {
	Name            string
	Version         string
	Fix             string
	PackageType     string
	VulnerabilityID string
	Severity        string
}

func newRow(m models.Match, severitySuffix string) row {
	severity := m.Vulnerability.Severity
	if severity != "" {
		severity += severitySuffix
	}

	fixVersion := strings.Join(m.Vulnerability.Fix.Versions, ", ")
	switch m.Vulnerability.Fix.State {
	case vulnerability.FixStateWontFix.String():
		fixVersion = "(won't fix)"
	case vulnerability.FixStateUnknown.String():
		fixVersion = ""
	}

	return row{
		Name:            m.Artifact.Name,
		Version:         m.Artifact.Version,
		Fix:             fixVersion,
		PackageType:     string(m.Artifact.Type),
		VulnerabilityID: m.Vulnerability.ID,
		Severity:        severity,
	}
}

func (r row) Columns() []string {
	return []string{r.Name, r.Version, r.Fix, r.PackageType, r.VulnerabilityID, r.Severity}
}

func (r row) String() string {
	return strings.Join(r.Columns(), "|")
}

func (rs rows) Render() [][]string {
	// deduplicate
	seen := map[string]row{}
	var deduped rows

	for _, v := range rs {
		key := v.String()
		if _, ok := seen[key]; ok {
			// dup!
			continue
		}

		seen[key] = v
		deduped = append(deduped, v)
	}

	// render final columns
	out := make([][]string, len(deduped))
	for idx, r := range deduped {
		out[idx] = r.Columns()
	}
	return out
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
