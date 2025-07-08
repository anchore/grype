package transformers

import (
	"fmt"
	"strings"

	"github.com/anchore/grype/grype/db/data"
	v6 "github.com/anchore/grype/internal/db/v6"
)

type RelatedEntries struct {
	VulnerabilityHandle *v6.VulnerabilityHandle
	Provider            *v6.Provider
	Related             []any
}

func NewEntries(models ...any) []data.Entry {
	var entry RelatedEntries

	for i := range models {
		model := models[i]
		switch m := model.(type) {
		case v6.VulnerabilityHandle:
			entry.VulnerabilityHandle = &m
		case v6.AffectedPackageHandle:
			entry.Related = append(entry.Related, m)
		case v6.AffectedCPEHandle:
			entry.Related = append(entry.Related, m)
		case v6.KnownExploitedVulnerabilityHandle:
			entry.Related = append(entry.Related, m)
		case v6.Provider:
			entry.Provider = &m
		case v6.EpssHandle:
			entry.Related = append(entry.Related, m)
		default:
			panic(fmt.Sprintf("unsupported model type: %T", m))
		}
	}

	return []data.Entry{
		{
			DBSchemaVersion: v6.ModelVersion,
			Data:            entry,
		},
	}
}

func (re RelatedEntries) String() string {
	var pkgs []string
	for _, r := range re.Related {
		switch v := r.(type) {
		case v6.AffectedPackageHandle:
			pkgs = append(pkgs, v.Package.String())
		case v6.AffectedCPEHandle:
			pkgs = append(pkgs, fmt.Sprintf("%s/%s", v.CPE.Vendor, v.CPE.Product))
		case v6.KnownExploitedVulnerabilityHandle:
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
