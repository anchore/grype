package table

import (
	"io"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/olekukonko/tablewriter"
	"github.com/scylladb/go-set/strset"

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

	recommendedFixStyle lipgloss.Style
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

// NewPresenter is a *Presenter constructor
func NewPresenter(pb models.PresenterConfig, showSuppressed bool) *Presenter {
	withColor := supportsColor()
	fixStyle := lipgloss.NewStyle().Border(lipgloss.Border{Left: "*"}, false, false, false, true)
	if withColor {
		fixStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("6")).Bold(true).Underline(true)
	}
	return &Presenter{
		document:            pb.Document,
		showSuppressed:      showSuppressed,
		withColor:           withColor,
		recommendedFixStyle: fixStyle,
	}
}

// Present creates a JSON-based reporting
func (p *Presenter) Present(output io.Writer) error {
	rs := p.getRows(p.document, p.showSuppressed)

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
		for _, row := range rs.Deduplicate() {
			severityColor := getSeverityColor(row.Severity)
			table.Rich(row.Columns(), []tablewriter.Colors{
				{},            // name
				{},            // version
				{},            // fix
				{},            // package type
				{},            // vulnerability ID
				severityColor, // severity
			})
		}
	} else {
		table.AppendBulk(rs.Render())
	}

	table.Render()

	return nil
}

func (p *Presenter) getRows(doc models.Document, showSuppressed bool) rows {
	var rs rows

	// generate rows for matching vulnerabilities
	for _, m := range doc.Matches {
		rs = append(rs, p.newRow(m, ""))
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
			rs = append(rs, p.newRow(m.Match, msg))
		}
	}
	return rs
}

func supportsColor() bool {
	return lipgloss.NewStyle().Foreground(lipgloss.Color("5")).Render("") != ""
}

func (p *Presenter) newRow(m models.Match, severitySuffix string) row {
	severity := m.Vulnerability.Severity
	if severity != "" {
		severity += severitySuffix
	}

	return row{
		Name:            m.Artifact.Name,
		Version:         m.Artifact.Version,
		Fix:             p.formatFix(m),
		PackageType:     string(m.Artifact.Type),
		VulnerabilityID: m.Vulnerability.ID,
		Severity:        severity,
	}
}

func (p *Presenter) formatFix(m models.Match) string {
	switch m.Vulnerability.Fix.State {
	case vulnerability.FixStateWontFix.String():
		return "(won't fix)"
	case vulnerability.FixStateUnknown.String():
		return ""
	}

	recommended := strset.New()
	for _, d := range m.MatchDetails {
		if d.Fix == nil {
			continue
		}
		if d.Fix.SuggestedVersion != "" {
			recommended.Add(d.Fix.SuggestedVersion)
		}
	}

	var vers []string
	hasMultipleVersions := len(m.Vulnerability.Fix.Versions) > 1
	for _, v := range m.Vulnerability.Fix.Versions {
		if hasMultipleVersions && recommended.Has(v) {
			vers = append(vers, p.recommendedFixStyle.Render(v))
			continue
		}
		vers = append(vers, v)
	}

	return strings.Join(vers, ", ")
}

func (r row) Columns() []string {
	return []string{r.Name, r.Version, r.Fix, r.PackageType, r.VulnerabilityID, r.Severity}
}

func (r row) String() string {
	return strings.Join(r.Columns(), "|")
}

func (rs rows) Render() [][]string {
	deduped := rs.Deduplicate()
	out := make([][]string, len(deduped))
	for idx, r := range deduped {
		out[idx] = r.Columns()
	}
	return out
}

func (rs rows) Deduplicate() []row {
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
	return deduped
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
