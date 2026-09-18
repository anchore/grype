package transformers

import (
	"fmt"
	"strings"

	"github.com/anchore/grype/grype/db/data"
	db "github.com/anchore/grype/grype/db/v6"
)

type RelatedEntries struct {
	VulnerabilityHandle *db.VulnerabilityHandle
	Provider            *db.Provider
	Related             []any

	// MergeByName asks the writer to fold this entry with others sharing its provider and
	// name. Transformers set it when one advisory identity is spread across many source
	// records; the store's write-once dedup is not sufficient. See name_merge.go.
	MergeByName bool
}

// GoVulnDBAffectedPackage wraps an affected package emitted by the govulndb transformer with
// ranges and PseudoVersion fixes(see the goVulnDBMerger's handleEntry).
type GoVulnDBAffectedPackage struct {
	Handle db.AffectedPackageHandle

	// PseudoVersionFix is the fixed version of the record's single standard range, when it is a
	// Go pseudo-version and the record carries exactly one custom range describing the same fix
	// in the module's real (tag) versioning. An aliased GHSA range pinned to this exact
	// pseudo-version can be replaced with CustomRanges.
	PseudoVersionFix string

	// CustomRanges is the ecosystem_specific.custom_ranges in the module's
	// real (tag) versioning; the replacement payload for a GHSA range still pinned to
	// PseudoVersionFix.
	CustomRanges []db.Range
}

// NewEntries keeps only the last VulnerabilityHandle passed, so callers needing several
// names must call it once per name and concatenate.
func NewEntries(models ...any) []data.Entry {
	return newEntries(false, models...)
}

// NewMergeableEntries is NewEntries with MergeByName set.
func NewMergeableEntries(models ...any) []data.Entry {
	return newEntries(true, models...)
}

func newEntries(mergeByName bool, models ...any) []data.Entry {
	entry := RelatedEntries{MergeByName: mergeByName}

	for i := range models {
		model := models[i]
		switch m := model.(type) {
		case db.VulnerabilityHandle:
			entry.VulnerabilityHandle = &m
		case db.AffectedPackageHandle, db.UnaffectedPackageHandle, db.AffectedCPEHandle,
			db.UnaffectedCPEHandle, db.KnownExploitedVulnerabilityHandle, db.EpssHandle, db.CWEHandle,
			db.SsvcHandle, db.OperatingSystemEOLHandle, GoVulnDBAffectedPackage:
			entry.Related = append(entry.Related, m)
		case db.Provider:
			entry.Provider = &m
		default:
			panic(fmt.Sprintf("unsupported model type: %T", m))
		}
	}

	return []data.Entry{
		{
			DBSchemaVersion: db.ModelVersion,
			Data:            entry,
		},
	}
}

func (re RelatedEntries) String() string {
	var pkgs []string
	for _, r := range re.Related {
		switch v := r.(type) {
		case db.AffectedPackageHandle:
			pkgs = append(pkgs, v.Package.String())
		case GoVulnDBAffectedPackage:
			pkgs = append(pkgs, v.Handle.Package.String())
		case db.AffectedCPEHandle:
			pkgs = append(pkgs, fmt.Sprintf("%s/%s", v.CPE.Vendor, v.CPE.Product))
		case db.KnownExploitedVulnerabilityHandle:
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
