package table

import (
	"fmt"
	"io"
	"sort"

	"github.com/anchore/grype/grype/result"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/pkg"
	"github.com/olekukonko/tablewriter"
)

// Presenter is a generic struct for holding fields needed for reporting
type Presenter struct {
	results          result.Result
	catalog          *pkg.Catalog
	metadataProvider vulnerability.MetadataProvider
}

// NewPresenter is a *Presenter constructor
func NewPresenter(results result.Result, catalog *pkg.Catalog, metadataProvider vulnerability.MetadataProvider) *Presenter {
	return &Presenter{
		results:          results,
		catalog:          catalog,
		metadataProvider: metadataProvider,
	}
}

// Present creates a JSON-based reporting
func (pres *Presenter) Present(output io.Writer) error {
	rows := make([][]string, 0)

	columns := []string{"Name", "Installed", "Fixed-In", "Vulnerability", "Severity"}
	for m := range pres.results.Enumerate() {
		var severity string

		metadata, err := pres.metadataProvider.GetMetadata(m.Vulnerability.ID, m.Vulnerability.RecordSource)
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
