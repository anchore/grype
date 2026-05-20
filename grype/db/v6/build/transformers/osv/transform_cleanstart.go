package osv

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/google/osv-scanner/pkg/models"

	"github.com/anchore/grype/grype/db/data"
	"github.com/anchore/grype/grype/db/internal/codename"
	"github.com/anchore/grype/grype/db/internal/provider/unmarshal"
	"github.com/anchore/grype/grype/db/provider"
	db "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/build/transformers"
	"github.com/anchore/grype/grype/db/v6/build/transformers/internal"
	"github.com/anchore/grype/grype/db/v6/name"
	"github.com/anchore/syft/syft/pkg"
)

const cleanStart = "cleanstart"

// cleanstartStrategy handles CleanStart Security Advisory (CLEANSTART) records.
// CleanStart OSV records describe affected version ranges for APK packages.
//
// CleanStart-specific decisions:
//   - Ecosystem is "CleanStart" or "CleanStart:<version>"; package type is
//     always APK; OS metadata is extracted from the ecosystem string.
//   - CleanStart is a rolling distro — no version suffix means rolling.
//   - OSV ranges (introduced/fixed events) are converted directly to
//     AffectedPackageHandle records with "< fixVersion" constraints, matching
//     how Alpine and Wolfi vulnerability data is stored.
//   - ADVISORY-type references get their refID set to the record ID.
type cleanstartStrategy struct{}

func (cleanstartStrategy) Matches(id string) bool {
	return strings.HasPrefix(id, "CLEANSTART-")
}

func (cleanstartStrategy) Transform(vuln unmarshal.OSVVulnerability, state provider.State) ([]data.Entry, error) {
	severities, err := getSeverities(vuln)
	if err != nil {
		return nil, fmt.Errorf("unable to obtain severities: %w", err)
	}

	aliases := append([]string{}, vuln.Aliases...)

	in := []any{
		db.VulnerabilityHandle{
			Name:          vuln.ID,
			ProviderID:    state.Provider,
			Provider:      provider.Model(state),
			Status:        db.VulnerabilityActive,
			ModifiedDate:  &vuln.Modified,
			PublishedDate: &vuln.Published,
			BlobValue: &db.VulnerabilityBlob{
				ID:          vuln.ID,
				Description: vuln.Details,
				References:  cleanstartReferences(vuln),
				Aliases:     aliases,
				Severities:  severities,
			},
		},
	}

	for _, aph := range cleanstartAffectedPackages(vuln) {
		in = append(in, aph)
	}
	return transformers.NewEntries(in...), nil
}

func cleanstartReferences(vuln unmarshal.OSVVulnerability) []db.Reference {
	var refs []db.Reference
	for _, ref := range vuln.References {
		refID := ""
		if ref.Type == models.ReferenceAdvisory {
			refID = vuln.ID
		}
		refs = append(refs, db.Reference{
			ID:   refID,
			URL:  ref.URL,
			Tags: []string{string(ref.Type)},
		})
	}
	return refs
}

func cleanstartAffectedPackages(vuln unmarshal.OSVVulnerability) []db.AffectedPackageHandle {
	if len(vuln.Affected) == 0 {
		return nil
	}
	var aphs []db.AffectedPackageHandle
	for _, affected := range vuln.Affected {
		aphs = append(aphs, db.AffectedPackageHandle{
			Package:         cleanstartPackage(affected.Package),
			OperatingSystem: cleanstartOSFromEcosystem(string(affected.Package.Ecosystem)),
			BlobValue:       cleanstartAffectedBlob(vuln, affected),
		})
	}
	sort.Sort(internal.ByAffectedPackage(aphs))
	return aphs
}

func cleanstartAffectedBlob(vuln unmarshal.OSVVulnerability, affected models.Affected) *db.PackageBlob {
	var ranges []db.Range
	for _, r := range affected.Ranges {
		ranges = append(ranges, getGrypeRangesFromRange(r, cleanstartRangeType(r.Type))...)
	}
	return &db.PackageBlob{
		CVEs:   vuln.Aliases,
		Ranges: ranges,
	}
}

func cleanstartPackage(p models.Package) *db.Package {
	return &db.Package{
		Ecosystem: pkg.ApkPkg.String(),
		Name:      name.Normalize(p.Name, pkg.ApkPkg),
	}
}

func cleanstartRangeType(t models.RangeType) string {
	if t == models.RangeEcosystem {
		return pkg.ApkPkg.String()
	}
	return defaultRangeType(t)
}

// cleanstartOSFromEcosystem extracts OS metadata from a CleanStart ecosystem
// string. CleanStart is a rolling distro; a bare "CleanStart" ecosystem (no
// version suffix) maps to a rolling OS entry.
func cleanstartOSFromEcosystem(ecosystem string) *db.OperatingSystem {
	if ecosystem == "" {
		return nil
	}

	parts := strings.SplitN(ecosystem, ":", 2)
	osName := strings.ToLower(parts[0])

	if osName != cleanStart {
		return nil
	}

	if len(parts) < 2 || parts[1] == "" {
		return &db.OperatingSystem{
			Name: cleanStart,
		}
	}

	osVersion := parts[1]
	versionFields := strings.Split(osVersion, ".")
	if len(versionFields) == 0 || versionFields[0] == "" {
		return nil
	}

	major := versionFields[0]
	if _, err := strconv.Atoi(major[0:1]); err != nil {
		return &db.OperatingSystem{
			Name:         cleanStart,
			LabelVersion: osVersion,
			Codename:     codename.LookupOS(cleanStart, "", ""),
		}
	}

	var minor string
	if len(versionFields) > 1 {
		minor = versionFields[1]
	}
	return &db.OperatingSystem{
		Name:         cleanStart,
		MajorVersion: major,
		MinorVersion: minor,
		Codename:     codename.LookupOS(cleanStart, major, minor),
	}
}