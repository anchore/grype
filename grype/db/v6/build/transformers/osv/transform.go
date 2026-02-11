package osv

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
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

const (
	almaLinux = "almalinux"
)

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

		// Extract qualifiers (CPE, RPM modularity, and Root IO)
		qualifiers := getPackageQualifiers(affected, cpes, withCPE, vuln)
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
// including CPE information, RPM modularity, and Root IO markers
func getPackageQualifiers(affected models.Affected, cpes any, withCPE bool, vuln unmarshal.OSVVulnerability) *db.PackageQualifiers {
	var qualifiers *db.PackageQualifiers

	// Handle CPE qualifiers (existing logic)
	if withCPE {
		qualifiers = &db.PackageQualifiers{
			PlatformCPEs: cpes.([]string),
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

	// Check if this is a Root IO package
	if isRootIORecord(vuln) {
		if qualifiers == nil {
			qualifiers = &db.PackageQualifiers{}
		}
		rootIO := true
		qualifiers.RootIO = &rootIO
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

// OSV supports flattered ranges, so both formats below are valid:
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

	fixByVersion := make(map[string]db.FixAvailability)
	// check r.DatabaseSpecific for "anchore" key which has
	// {"fixes": [{
	//   "version": "v1.2.3",
	//   "date": "YYYY-MM-DD",
	//   "kind": "first-observed",
	// }]}

	if dbSpecific, ok := r.DatabaseSpecific["anchore"]; ok {
		if anchoreInfo, ok := dbSpecific.(map[string]any); ok {
			if fixes, ok := anchoreInfo["fixes"]; ok {
				if fixList, ok := fixes.([]any); ok {
					for _, fixEntry := range fixList {
						if fixMap, ok := fixEntry.(map[string]any); ok {
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
					}
				}
			}
		}
	}

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
					Constraint: normalizeConstraint(constraint, rangeType),
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
					Constraint: normalizeConstraint(constraint, rangeType),
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
				Constraint: normalizeConstraint(constraint, rangeType),
			},
		})
	}

	return ranges
}

func normalizeConstraint(constraint string, rangeType string) string {
	if rangeType == "semver" || rangeType == "bitnami" {
		return versionutil.EnforceSemVerConstraint(constraint)
	}
	return constraint
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
// Supports AlmaLinux and Root IO OS ecosystems (Alpine, Debian, Ubuntu)
// Also supports Root IO language ecosystems (npm, pypi, maven)
func getPackageTypeFromEcosystem(ecosystem string) pkg.Type {
	if ecosystem == "" {
		return ""
	}

	ecosystemLower := strings.ToLower(ecosystem)

	// Check for language ecosystems (Root IO)
	switch ecosystemLower {
	case "npm":
		return pkg.NpmPkg
	case "pypi", "python", "pip":
		return pkg.PythonPkg
	case "maven", "java":
		return pkg.JavaPkg
	}

	// Split ecosystem by colon to get OS name
	parts := strings.Split(ecosystem, ":")
	if len(parts) < 2 {
		return ""
	}
	osName := strings.ToLower(parts[0])

	// Handle OS ecosystems
	switch osName {
	case almaLinux:
		return pkg.RpmPkg
	case "alpine":
		return pkg.ApkPkg
	case "debian", "ubuntu":
		return pkg.DebPkg
	default:
		// For other ecosystems (like Bitnami), return empty type
		// The package type will be determined from PURL if available
		return ""
	}
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

	return refs
}

// extractCVSSInfo extracts the CVSS version and vector from the CVSS string
func extractCVSSInfo(cvss string) (string, string, error) {
	re := regexp.MustCompile(`^CVSS:(\d+\.\d+)/(.+)$`)
	matches := re.FindStringSubmatch(cvss)

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

// getOperatingSystemFromEcosystem extracts operating system information from OSV ecosystem field
// Supports AlmaLinux and Root IO OS ecosystems (Alpine, Debian, Ubuntu)
// Examples: "AlmaLinux:8" -> almalinux 8, "Alpine:3.18" -> alpine 3.18, "Ubuntu:20.04" -> ubuntu 20.04
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

	// Check if this is a supported OS
	switch osName {
	case almaLinux, "alpine", "debian", "ubuntu":
		// Supported OS, continue processing
	default:
		return nil
	}

	osVersion := parts[1]

	// Parse version into major/minor components
	versionFields := strings.Split(osVersion, ".")
	var majorVersion, minorVersion string
	if len(versionFields) > 0 {
		majorVersion = versionFields[0]
		// Check if the first field is actually a number
		if _, err := strconv.Atoi(majorVersion[0:1]); err != nil {
			// If not numeric, treat the whole thing as a label version
			return &db.OperatingSystem{
				Name:         normalizeOSName(osName),
				LabelVersion: osVersion,
				Codename:     codename.LookupOS(normalizeOSName(osName), "", ""),
			}
		}
		if len(versionFields) > 1 {
			minorVersion = versionFields[1]
		}
	}

	return &db.OperatingSystem{
		Name:         normalizeOSName(osName),
		MajorVersion: majorVersion,
		MinorVersion: minorVersion,
		Codename:     codename.LookupOS(normalizeOSName(osName), majorVersion, minorVersion),
	}
}

// normalizeOSName normalizes operating system names for consistency
func normalizeOSName(osName string) string {
	return strings.ToLower(osName)
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
			BlobValue:       getUnaffectedBlob(vuln.Aliases, affected.Ranges, affected, vuln),
		}
		uphs = append(uphs, uph)
	}

	// stable ordering
	sort.Sort(internal.ByUnaffectedPackage(uphs))

	return uphs
}

// getUnaffectedBlob creates a package blob for unaffected packages (advisories)
// For advisories, we need to invert the ranges to represent unaffected versions
func getUnaffectedBlob(aliases []string, ranges []models.Range, affected models.Affected, vuln unmarshal.OSVVulnerability) *db.PackageBlob {
	var grypeRanges []db.Range
	ecosystem := string(affected.Package.Ecosystem)
	for _, r := range ranges {
		grypeRanges = append(grypeRanges, getGrypeUnaffectedRangesFromRange(r, ecosystem)...)
	}

	// Extract qualifiers including RPM modularity and Root IO
	qualifiers := getPackageQualifiers(affected, nil, false, vuln)

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
			Constraint: normalizeConstraint(constraint, rangeType),
		},
	}
}

// ============================================================================
// Root IO Detection
// ============================================================================

const rootIOSourceIdentifier = "Root"

// isRootIORecord checks if an OSV record is from Root IO by examining database_specific.source
// This is used to apply Root IO-specific package qualifiers
func isRootIORecord(vuln unmarshal.OSVVulnerability) bool {
	if vuln.DatabaseSpecific == nil {
		return false
	}

	source, ok := vuln.DatabaseSpecific["source"]
	if !ok {
		return false
	}

	sourceStr, ok := source.(string)
	return ok && sourceStr == rootIOSourceIdentifier
}
