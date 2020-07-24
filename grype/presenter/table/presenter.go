package table

import (
	"fmt"
	"io"
	"sort"

	"github.com/anchore/grype/grype/result"
	"github.com/anchore/syft/syft/pkg"
	"github.com/olekukonko/tablewriter"
)

// Presenter is a generic struct for holding fields needed for reporting
type Presenter struct{}

// NewPresenter is a *Presenter constructor
func NewPresenter() *Presenter {
	return &Presenter{}
}

// Present creates a JSON-based reporting
func (pres *Presenter) Present(output io.Writer, catalog *pkg.Catalog, results result.Result) error {
	rows := make([][]string, 0)

	columns := []string{"Name", "Installed", "Vulnerability", "Found-By"}
	for p := range results.Enumerate() {
		row := []string{
			p.Package.Name,
			p.Package.Version,
			p.Vulnerability.ID,
			fmt.Sprintf("%s %s", p.Matcher.String(), p.SearchKey),
		}
		rows = append(rows, row)
	}

	if len(rows) == 0 {
		_, err := io.WriteString(output, "No vulnerabilities found")
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

	table := tablewriter.NewWriter(output)

	table.SetHeader(columns)
	table.SetAutoMergeCells(true)
	table.SetRowLine(true)
	table.SetAutoWrapText(false)
	table.SetCenterSeparator("·") // + ┼ ╎  ┆ ┊ · •
	table.SetColumnSeparator("│")
	table.SetRowSeparator("─")
	table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
	table.SetAlignment(tablewriter.ALIGN_LEFT)

	table.AppendBulk(rows)
	table.Render()

	return nil
}
