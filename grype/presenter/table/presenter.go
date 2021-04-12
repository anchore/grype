package table

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/anchore/grype/grype"

	"github.com/olekukonko/tablewriter"
)

// The Name of the kind of presenter.
const Name = "table"

// Presenter is a generic struct for holding fields needed for reporting
type Presenter struct{}

// NewPresenter is a *Presenter constructor
func NewPresenter() *Presenter {
	return &Presenter{}
}

// Present creates a JSON-based reporting
func (pres *Presenter) Present(output io.Writer, analysis grype.Analysis) error {
	rows := make([][]string, 0)

	columns := []string{"Name", "Installed", "Fixed-In", "Vulnerability", "Severity"}
	for m := range analysis.Matches.Enumerate() {
		var severity string

		metadata, err := analysis.MetadataProvider.GetMetadata(m.Vulnerability.ID, m.Vulnerability.RecordSource)
		if err != nil {
			return fmt.Errorf("unable to fetch vuln=%q metadata: %+v", m.Vulnerability.ID, err)
		}

		if metadata != nil {
			severity = metadata.Severity
		}

		row := []string{
			m.Package.Name,
			m.Package.Version,
			m.Vulnerability.FixedInVersion,
			m.Vulnerability.ID,
			severity,
		}
		rows = append(rows, row)
	}

	if len(rows) == 0 {
		_, err := io.WriteString(output, "No vulnerabilities found\n")
		return err
	}

	// sort by name, version, then type
	sort.SliceStable(rows, func(i, j int) bool {
		for col := 0; col < len(columns); col++ {
			if rows[i][0] != rows[j][0] {
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

	table.AppendBulk(rows)
	table.Render()

	return nil
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
