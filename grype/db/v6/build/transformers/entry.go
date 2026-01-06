package transformers

import (
	"fmt"
	"strings"

	"github.com/anchore/grype/grype/db/data"
	grypeDB "github.com/anchore/grype/grype/db/v6"
)

type RelatedEntries struct {
	VulnerabilityHandle *grypeDB.VulnerabilityHandle
	Provider            *grypeDB.Provider
	Related             []any
}

func NewEntries(models ...any) []data.Entry {
	var entry RelatedEntries

	for i := range models {
		model := models[i]
		switch m := model.(type) {
		case grypeDB.VulnerabilityHandle:
			entry.VulnerabilityHandle = &m
		case grypeDB.AffectedPackageHandle, grypeDB.UnaffectedPackageHandle, grypeDB.AffectedCPEHandle,
			grypeDB.UnaffectedCPEHandle, grypeDB.KnownExploitedVulnerabilityHandle, grypeDB.EpssHandle, grypeDB.CWEHandle:
			entry.Related = append(entry.Related, m)
		case grypeDB.Provider:
			entry.Provider = &m
		default:
			panic(fmt.Sprintf("unsupported model type: %T", m))
		}
	}

	return []data.Entry{
		{
			DBSchemaVersion: grypeDB.ModelVersion,
			Data:            entry,
		},
	}
}

func (re RelatedEntries) String() string {
	var pkgs []string
	for _, r := range re.Related {
		switch v := r.(type) {
		case grypeDB.AffectedPackageHandle:
			pkgs = append(pkgs, v.Package.String())
		case grypeDB.AffectedCPEHandle:
			pkgs = append(pkgs, fmt.Sprintf("%s/%s", v.CPE.Vendor, v.CPE.Product))
		case grypeDB.KnownExploitedVulnerabilityHandle:
			pkgs = append(pkgs, "kev="+v.Cve)
		}
	}
	var fields []string
	if re.VulnerabilityHandle != nil {
		fields = append(fields, fmt.Sprintf("vuln=%q", re.VulnerabilityHandle.Name))
		fields = append(fields, fmt.Sprintf("provider=%q", re.VulnerabilityHandle.ProviderID))
	} else if re.Provider != nil {
		fields = append(fields, fmt.Sprintf("provider=%q", re.Provider.ID))
	}

	fields = append(fields, fmt.Sprintf("entries=%d", len(re.Related)))

	return fmt.Sprintf("%s: %s", strings.Join(fields, " "), strings.Join(pkgs, ", "))
}
