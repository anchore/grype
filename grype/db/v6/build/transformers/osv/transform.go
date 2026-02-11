package osv

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/google/osv-scanner/pkg/models"

	"github.com/anchore/grype/grype/db/data"
	"github.com/anchore/grype/grype/db/internal/codename"
	"github.com/anchore/grype/grype/db/internal/provider/unmarshal"
	"github.com/anchore/grype/grype/db/internal/versionutil"
	"github.com/anchore/grype/grype/db/provider"
	db "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/build/transformers"
	"github.com/anchore/grype/grype/db/v6/build/transformers/internal"
	"github.com/anchore/grype/grype/db/v6/name"
	"github.com/anchore/syft/syft/pkg"
)

// osvOSPackageTypes maps OSV ecosystem name prefixes (lowercased) to their package types.
// This is used when PURLs are not available to determine the package type from the ecosystem string.
var osvOSPackageTypes = map[string]pkg.Type{
	"almalinux": pkg.RpmPkg,
	"rocky":     pkg.RpmPkg,
	"alpaquita": pkg.ApkPkg,
	"openeuler": pkg.RpmPkg,
}

func Transform(vulnerability unmarshal.OSVVulnerability, state provider.State) ([]data.Entry, error) {
	severities, err := getSeverities(vulnerability)
	if err != nil {
		return nil, fmt.Errorf("unable to obtain severities: %w", err)
	}

	isAdvisory := isAdvisoryRecord(vulnerability)
	aliases := vulnerability.Aliases

	if isAdvisory {
		aliases = append(aliases, vulnerability.Related...)
	}

	in := []any{
		db.VulnerabilityHandle{
			Name:          vulnerability.ID,
			ProviderID:    state.Provider,
			Provider:      provider.Model(state),
			Status:        db.VulnerabilityActive,
			ModifiedDate:  &vulnerability.Modified,
			PublishedDate: &vulnerability.Published,
			BlobValue: &db.VulnerabilityBlob{
				ID:          vulnerability.ID,
				Assigners:   nil,
				Description: vulnerability.Details,
				References:  getReferences(vulnerability),
				Aliases:     aliases,
				Severities:  severities,
			},
		},
	}

	// Check if this is an advisory record
	if isAdvisory {
		// For advisory records, emit unaffected packages
		for _, u := range getUnaffectedPackages(vulnerability) {
			in = append(in, u)
		}
	} else {
		// For vulnerability records, emit affected packages
		for _, a := range getAffectedPackages(vulnerability) {
			in = append(in, a)
		}
	}

	return transformers.NewEntries(in...), nil
}

func getAffectedPackages(vuln unmarshal.OSVVulnerability) []db.AffectedPackageHandle {
	if len(vuln.Affected) == 0 {
		return nil
	}

	// CPES might be in the database_specific information
	cpes, withCPE := vuln.DatabaseSpecific["cpes"]
	if withCPE {
		if _, ok := cpes.([]string); !ok {
			withCPE = false
		}
	}

	var aphs []db.AffectedPackageHandle
	for _, affected := range vuln.Affected {
		aph := db.AffectedPackageHandle{
			Package:         getPackage(affected.Package),
			OperatingSystem: getOperatingSystemFromEcosystem(string(affected.Package.Ecosystem)),
			BlobValue:       &db.PackageBlob{CVEs: vuln.Aliases},
		}

		// Extract qualifiers (CPE and RPM modularity)
		qualifiers := getPackageQualifiers(affected, cpes, withCPE)
		if qualifiers != nil {
			aph.BlobValue.Qualifiers = qualifiers
		}

		var ranges []db.Range
		for _, r := range affected.Ranges {
			ranges = append(ranges, getGrypeRangesFromRange(r, string(affected.Package.Ecosystem))...)
		}
		aph.BlobValue.Ranges = ranges
		aphs = append(aphs, aph)
	}

	// stable ordering
	sort.Sort(internal.ByAffectedPackage(aphs))

	return aphs
}

// getPackageQualifiers extracts package qualifiers from affected package data
// including CPE information and RPM modularity
func getPackageQualifiers(affected models.Affected, cpes any, withCPE bool) *db.PackageQualifiers {
	var qualifiers *db.PackageQualifiers

	// Handle CPE qualifiers (existing logic)
	if withCPE {
		if cpeList, ok := cpes.([]string); ok {
			qualifiers = &db.PackageQualifiers{
				PlatformCPEs: cpeList,
			}
		}
	}

	// Extract RPM modularity from ecosystem_specific
	rpmModularity := extractRpmModularity(affected)
	if rpmModularity != "" {
		if qualifiers == nil {
			qualifiers = &db.PackageQualifiers{}
		}
		qualifiers.RpmModularity = &rpmModularity
	}

	return qualifiers
}

// extractRpmModularity extracts RPM modularity information from affected package ecosystem_specific
func extractRpmModularity(affected models.Affected) string {
	if affected.EcosystemSpecific == nil {
		return ""
	}

	rpmModularity, ok := affected.EcosystemSpecific["rpm_modularity"]
	if !ok {
		return ""
	}

	rpmModularityStr, ok := rpmModularity.(string)
	if !ok {
		return ""
	}

	return rpmModularityStr
}

// OSV supports flattened ranges, so both formats below are valid:
// "ranges": [
//
//	{
//	  "type": "SEMVER",
//	  "events": [
//	    {
//	      "introduced": "12.0.0"
//	    },
//	    {
//	      "fixed": "12.18.4"
//	    }
//	  ]
//	},
//	{
//	  "type": "SEMVER",
//	  "events": [
//	    {
//	      "introduced": "14.0.0"
//	    },
//	    {
//	      "fixed": "14.11.0"
//	    }
//	  ]
//	}
//
// ]
// "ranges": [
//
//	{
//	  "type": "SEMVER",
//	  "events": [
//		{
//		  "introduced": "12.0.0"
//		},
//		{
//		  "fixed": "12.18.4"
//		},
//		{
//		  "introduced": "14.0.0"
//		},
//		{
//		  "fixed": "14.11.0"
//		}
//	  ]
//	}
//
// ]
func getGrypeRangesFromRange(r models.Range, ecosystem string) []db.Range { // nolint: gocognit,funlen
	var ranges []db.Range
	if len(r.Events) == 0 {
		return nil
	}

	var constraint string
	updateConstraint := func(c string) {
		if constraint == "" {
			constraint = c
		} else {
			constraint = versionutil.AndConstraints(constraint, c)
		}
	}

	fixByVersion := extractFixAvailability(r)

	rangeType := normalizeRangeType(r.Type, ecosystem)
	for _, e := range r.Events {
		switch {
		case e.Introduced != "" && e.Introduced != "0":
			constraint = fmt.Sprintf(">= %s", e.Introduced)
		case e.LastAffected != "":
			updateConstraint(fmt.Sprintf("<= %s", e.LastAffected))
			// We don't know the fix if last affected is set
			ranges = append(ranges, db.Range{
				Version: db.Version{
					Type:       rangeType,
					Constraint: normalizeConstraint(constraint),
				},
			})
			// Reset the constraint
			constraint = ""
		case e.Fixed != "":
			var detail *db.FixDetail
			if f, ok := fixByVersion[e.Fixed]; ok {
				detail = &db.FixDetail{
					Available: &f,
				}
			}
			updateConstraint(fmt.Sprintf("< %s", e.Fixed))
			ranges = append(ranges, db.Range{
				Fix: normalizeFix(e.Fixed, detail),
				Version: db.Version{
					Type:       rangeType,
					Constraint: normalizeConstraint(constraint),
				},
			})
			// Reset the constraint
			constraint = ""
		}
	}

	// Check if there's an event that "introduced" but never had a "fixed" or "last affected" event
	if constraint != "" {
		ranges = append(ranges, db.Range{
			Version: db.Version{
				Type:       rangeType,
				Constraint: normalizeConstraint(constraint),
			},
		})
	}

	return ranges
}

func normalizeConstraint(constraint string) string {
	// All compound constraints from OSV need to be comma-separated for grype.
	// For example, ">= 0.2 < 1.8" becomes ">=0.2,<1.8".
	return versionutil.EnforceSemVerConstraint(constraint)
}

func normalizeFix(fix string, detail *db.FixDetail) *db.Fix {
	fixedInVersion := versionutil.CleanFixedInVersion(fix)
	fixState := db.NotFixedStatus
	if len(fixedInVersion) > 0 {
		fixState = db.FixedStatus
	}

	return &db.Fix{
		State:   fixState,
		Version: fixedInVersion,
		Detail:  detail,
	}
}

func normalizeRangeType(t models.RangeType, ecosystem string) string {
	// For Bitnami ecosystem, use "bitnami" format instead of "semver"
	if ecosystem == "Bitnami" && t == models.RangeSemVer {
		return "bitnami"
	}

	switch t {
	case models.RangeSemVer, models.RangeEcosystem, models.RangeGit:
		return strings.ToLower(string(t))
	default:
		return "unknown"
	}
}

func getPackage(p models.Package) *db.Package {
	// Try to determine package type from ecosystem or PURL
	var pkgType pkg.Type
	var ecosystem string

	if p.Purl != "" {
		pkgType = pkg.TypeFromPURL(p.Purl)
		ecosystem = string(p.Ecosystem)
	} else {
		pkgType = getPackageTypeFromEcosystem(string(p.Ecosystem))
		// If we found a package type from OS ecosystem, use it; otherwise use original ecosystem
		if pkgType != "" {
			ecosystem = string(pkgType)
		} else {
			ecosystem = string(p.Ecosystem)
		}
	}

	return &db.Package{
		Ecosystem: ecosystem,
		Name:      name.Normalize(p.Name, pkgType),
	}
}

// getPackageTypeFromEcosystem determines package type from OSV ecosystem
// for ecosystems that don't provide PURLs in their advisories.
func getPackageTypeFromEcosystem(ecosystem string) pkg.Type {
	if ecosystem == "" {
		return ""
	}

	// Split ecosystem by colon to get OS name
	parts := strings.Split(ecosystem, ":")
	osName := strings.ToLower(parts[0])

	if pt, ok := osvOSPackageTypes[osName]; ok {
		return pt
	}

	switch osName {
	case "cran":
		return pkg.Rpkg
	}

	// For other ecosystems (like Bitnami, npm, pypi, etc.), return empty type
	// The package type will be determined from PURL if available
	return ""
}

func getReferences(vuln unmarshal.OSVVulnerability) []db.Reference {
	var refs []db.Reference
	for _, ref := range vuln.References {
		// For advisory references, use the vulnerability ID as the advisory ID
		// This allows tools consuming the data to link back to the specific advisory
		refID := ""
		if ref.Type == models.ReferenceAdvisory && isAdvisoryRecord(vuln) {
			refID = vuln.ID
		}

		refs = append(refs,
			db.Reference{
				ID:   refID,
				URL:  ref.URL,
				Tags: []string{string(ref.Type)},
			},
		)
	}

	return transformers.DeduplicateReferences(refs)
}

var cvssPattern = regexp.MustCompile(`^CVSS:(\d+\.\d+)/(.+)$`)

// extractCVSSInfo extracts the CVSS version and vector from the CVSS string
func extractCVSSInfo(cvss string) (string, string, error) {
	matches := cvssPattern.FindStringSubmatch(cvss)

	if len(matches) != 3 {
		return "", "", fmt.Errorf("invalid CVSS format")
	}

	return matches[1], matches[0], nil
}

func normalizeSeverity(severity models.Severity) (db.Severity, error) {
	switch severity.Type {
	case models.SeverityCVSSV2, models.SeverityCVSSV3, models.SeverityCVSSV4:
		version, vector, err := extractCVSSInfo(severity.Score)
		if err != nil {
			return db.Severity{}, err
		}

		return db.Severity{
			Scheme: db.SeveritySchemeCVSS,
			Value: db.CVSSSeverity{
				Vector:  vector,
				Version: version,
			},
		}, nil
	default:
		return db.Severity{
			Scheme: db.UnknownSeverityScheme,
			Value:  severity.Score,
		}, nil
	}
}

func getSeverities(vuln unmarshal.OSVVulnerability) ([]db.Severity, error) {
	var severities []db.Severity
	for _, sev := range vuln.Severity {
		severity, err := normalizeSeverity(sev)
		if err != nil {
			return nil, err
		}
		severities = append(severities, severity)
	}

	for _, affected := range vuln.Affected {
		for _, sev := range affected.Severity {
			severity, err := normalizeSeverity(sev)
			if err != nil {
				return nil, err
			}
			severities = append(severities, severity)
		}
	}

	return severities, nil
}

// getOperatingSystemFromEcosystem extracts operating system information from OSV ecosystem field.
// It handles any OS ecosystem in the format "OSName:Version" where the OS name is recognized
// in osvOSPackageTypes (e.g. "AlmaLinux:8", "Alpaquita:stream", "Rocky:9.2").
func getOperatingSystemFromEcosystem(ecosystem string) *db.OperatingSystem {
	if ecosystem == "" {
		return nil
	}

	// Split ecosystem by colon to get components
	parts := strings.Split(ecosystem, ":")
	if len(parts) < 2 {
		return nil
	}

	osName := strings.ToLower(parts[0])

	// Only handle known OS ecosystems
	if _, ok := osvOSPackageTypes[osName]; !ok {
		return nil
	}

	osVersion := parts[1]

	// Separate any label suffix from the version (e.g. "20.03-LTS-SP4" → version="20.03", label="LTS-SP4")
	var labelVersion string
	if idx := strings.Index(osVersion, "-"); idx > 0 {
		labelVersion = osVersion[idx+1:]
		osVersion = osVersion[:idx]
	}

	// Parse version into major/minor components
	versionFields := strings.Split(osVersion, ".")
	var majorVersion, minorVersion string
	if len(versionFields) > 0 {
		majorVersion = versionFields[0]
		// Check if the first field is actually a number
		if len(majorVersion) == 0 || !isDigit(majorVersion[0]) {
			// If not numeric, treat the whole thing as a label version (e.g. "stream")
			if labelVersion != "" {
				majorVersion = majorVersion + "-" + labelVersion
			}
			return &db.OperatingSystem{
				Name:         osName,
				ReleaseID:    osName,
				LabelVersion: majorVersion,
				Codename:     codename.LookupOS(osName, "", ""),
			}
		}
		if len(versionFields) > 1 {
			minorVersion = versionFields[1]
		}
	}

	return &db.OperatingSystem{
		Name:         osName,
		ReleaseID:    osName,
		MajorVersion: majorVersion,
		MinorVersion: minorVersion,
		LabelVersion: labelVersion,
		Codename:     codename.LookupOS(osName, majorVersion, minorVersion),
	}
}

func isDigit(b byte) bool {
	return b >= '0' && b <= '9'
}

// isAdvisoryRecord checks if the OSV record is marked as an advisory
func isAdvisoryRecord(vuln unmarshal.OSVVulnerability) bool {
	if vuln.DatabaseSpecific == nil {
		return false
	}

	anchoreData, ok := vuln.DatabaseSpecific["anchore"]
	if !ok {
		return false
	}

	anchoreMap, ok := anchoreData.(map[string]any)
	if !ok {
		return false
	}

	recordType, ok := anchoreMap["record_type"]
	if !ok {
		return false
	}

	recordTypeStr, ok := recordType.(string)
	if !ok {
		return false
	}

	return recordTypeStr == "advisory"
}

// getUnaffectedPackages creates UnaffectedPackageHandle entries for advisory records
func getUnaffectedPackages(vuln unmarshal.OSVVulnerability) []db.UnaffectedPackageHandle {
	if len(vuln.Affected) == 0 {
		return nil
	}

	var uphs []db.UnaffectedPackageHandle
	for _, affected := range vuln.Affected {
		uph := db.UnaffectedPackageHandle{
			Package:         getPackage(affected.Package),
			OperatingSystem: getOperatingSystemFromEcosystem(string(affected.Package.Ecosystem)),
			BlobValue:       getUnaffectedBlob(vuln.Aliases, affected.Ranges, affected),
		}
		uphs = append(uphs, uph)
	}

	// stable ordering
	sort.Sort(internal.ByUnaffectedPackage(uphs))

	return uphs
}

// getUnaffectedBlob creates a package blob for unaffected packages (advisories)
// For advisories, we need to invert the ranges to represent unaffected versions
func getUnaffectedBlob(aliases []string, ranges []models.Range, affected models.Affected) *db.PackageBlob {
	var grypeRanges []db.Range
	ecosystem := string(affected.Package.Ecosystem)
	for _, r := range ranges {
		grypeRanges = append(grypeRanges, getGrypeUnaffectedRangesFromRange(r, ecosystem)...)
	}

	// Extract qualifiers including RPM modularity
	qualifiers := getPackageQualifiers(affected, nil, false)

	return &db.PackageBlob{
		CVEs:       aliases,
		Ranges:     grypeRanges,
		Qualifiers: qualifiers,
	}
}

// getGrypeUnaffectedRangesFromRange converts OSV ranges to unaffected version ranges for unaffected packages
// This inverts the logic: instead of "< fix_version" (affected), we create ">= fix_version" (unaffected)
func getGrypeUnaffectedRangesFromRange(r models.Range, ecosystem string) []db.Range {
	if len(r.Events) == 0 {
		return nil
	}

	fixByVersion := extractFixAvailability(r)
	rangeType := normalizeRangeType(r.Type, ecosystem)

	return buildUnaffectedRangesFromEvents(r.Events, fixByVersion, rangeType)
}

// extractFixAvailability extracts fix availability information from DatabaseSpecific
func extractFixAvailability(r models.Range) map[string]db.FixAvailability {
	fixByVersion := make(map[string]db.FixAvailability)

	dbSpecific, hasDBSpecific := r.DatabaseSpecific["anchore"]
	if !hasDBSpecific {
		return fixByVersion
	}

	anchoreInfo, isMap := dbSpecific.(map[string]any)
	if !isMap {
		return fixByVersion
	}

	fixes, hasFixes := anchoreInfo["fixes"]
	if !hasFixes {
		return fixByVersion
	}

	fixList, isList := fixes.([]any)
	if !isList {
		return fixByVersion
	}

	for _, fixEntry := range fixList {
		parseSingleFixEntry(fixEntry, fixByVersion)
	}

	return fixByVersion
}

// parseSingleFixEntry parses a single fix entry and adds it to the fixByVersion map
func parseSingleFixEntry(fixEntry any, fixByVersion map[string]db.FixAvailability) {
	fixMap, isMap := fixEntry.(map[string]any)
	if !isMap {
		return
	}

	version, vOk := fixMap["version"].(string)
	kind, kOk := fixMap["kind"].(string)
	date, dOk := fixMap["date"].(string)

	if vOk && kOk && dOk {
		fixByVersion[version] = db.FixAvailability{
			Date: internal.ParseTime(date),
			Kind: kind,
		}
	}
}

// buildUnaffectedRangesFromEvents processes events to create unaffected version ranges
func buildUnaffectedRangesFromEvents(events []models.Event, fixByVersion map[string]db.FixAvailability, rangeType string) []db.Range {
	var ranges []db.Range

	for _, e := range events {
		if e.Fixed != "" {
			unaffectedRange := createUnaffectedRange(e.Fixed, fixByVersion, rangeType)
			ranges = append(ranges, unaffectedRange)
		}
	}

	return ranges
}

// createUnaffectedRange creates a single safe range for a fixed version
func createUnaffectedRange(fixedVersion string, fixByVersion map[string]db.FixAvailability, rangeType string) db.Range {
	var detail *db.FixDetail
	if f, ok := fixByVersion[fixedVersion]; ok {
		detail = &db.FixDetail{
			Available: &f,
		}
	}

	constraint := fmt.Sprintf(">= %s", fixedVersion)
	return db.Range{
		Fix: normalizeFix(fixedVersion, detail),
		Version: db.Version{
			Type:       rangeType,
			Constraint: normalizeConstraint(constraint),
		},
	}
}
