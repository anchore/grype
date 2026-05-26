package csaf

import (
	"slices"

	"github.com/gocsaf/csaf/v3/csaf"

	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/packageurl-go"
)

// advisoryMatch captures the criteria that caused a vulnerability to match a CSAF advisory
type advisoryMatch struct {
	Vulnerability *csaf.Vulnerability
	Status        status
	ProductID     csaf.ProductID
}

// cve returns the CVE of the vulnerability that matched
func (m *advisoryMatch) cve() string {
	if m == nil || m.Vulnerability == nil || m.Vulnerability.CVE == nil {
		return ""
	}

	return string(*m.Vulnerability.CVE)
}

// statement returns the statement of the vulnerability that matched
func (m *advisoryMatch) statement() string {
	if m == nil || m.Vulnerability == nil {
		return ""
	}

	// an impact statement SHALL exist as machine readable flag in /vulnerabilities[]/flags (...)
	for _, flag := range m.Vulnerability.Flags {
		if flag == nil || flag.ProductIds == nil || flag.Label == nil {
			continue
		}
		for _, pID := range *flag.ProductIds {
			if pID == nil {
				continue
			}
			if *pID == m.ProductID {
				return string(*flag.Label)
			}
		}
	}
	// (...) or as human readable justification in /vulnerabilities[]/threats
	for _, th := range m.Vulnerability.Threats {
		if th == nil || th.Category == nil || th.Details == nil {
			continue
		}
		if *th.Category != csaf.CSAFThreatCategoryImpact {
			continue
		}
		for _, pID := range *th.ProductIds {
			if pID == nil {
				continue
			}
			if *pID == m.ProductID {
				return *th.Details
			}
		}
	}

	return ""
}

type advisories []*csaf.Advisory

// matches returns the first CSAF advisory to match for a given vulnerability ID and package URL
//
//nolint:gocognit
func (advisories advisories) matches(vulnID, purl string) *advisoryMatch {
	for _, adv := range advisories {
		if adv == nil || adv.Vulnerabilities == nil {
			continue
		}

		// Auxiliary function to find in the advisory the 1st product ID that matches a given pURL
		findProductID := func(products csaf.Products, purl string) csaf.ProductID {
			for _, p := range products {
				if p == nil {
					continue
				}
				if slices.Contains(purlsFromProductIdentificationHelpers(adv.ProductTree.CollectProductIdentificationHelpers(*p)), purl) {
					return *p
				}
			}
			return ""
		}

		for _, vuln := range adv.Vulnerabilities {
			if vuln == nil || vuln.CVE == nil || string(*vuln.CVE) != vulnID {
				continue
			}

			productsByStatus := map[status]*csaf.Products{
				firstAffected:      vuln.ProductStatus.FirstAffected,
				firstFixed:         vuln.ProductStatus.FirstFixed,
				fixed:              vuln.ProductStatus.Fixed,
				knownAffected:      vuln.ProductStatus.KnownAffected,
				knownNotAffected:   vuln.ProductStatus.KnownNotAffected,
				lastAffected:       vuln.ProductStatus.LastAffected,
				recommended:        vuln.ProductStatus.Recommended,
				underInvestigation: vuln.ProductStatus.UnderInvestigation,
			}
			for status, products := range productsByStatus {
				if products == nil {
					continue
				}
				if productID := findProductID(*products, purl); productID != "" {
					return &advisoryMatch{vuln, status, productID}
				}
			}
		}
	}

	return nil
}

// purlsFromProductIdentificationHelpers returns a slice of PackageURLs (string format) given a slice of ProductIdentificationHelpers.
func purlsFromProductIdentificationHelpers(helpers []*csaf.ProductIdentificationHelper) []string {
	var purls []string
	for _, helper := range helpers {
		if helper == nil || helper.PURL == nil {
			continue
		}
		purls = append(purls, string(*helper.PURL))
	}
	return purls
}

// synthesisCandidate describes a (vulnerability, package) pair that should be
// added to grype's results based on a CSAF advisory, when no DB-backed match
// already exists.
type synthesisCandidate struct {
	Vulnerability *csaf.Vulnerability
	Status        status
	ProductID     csaf.ProductID
	Package       *pkg.Package
}

// findSynthesisCandidates walks every advisory and yields (vuln, package)
// pairs eligible for synthesis. Range semantics are applied per status:
//   - last_affected: pkg.version <= stmt.version (ceiling)
//   - first_affected: pkg.version >= stmt.version (floor)
//   - known_affected, recommended, under_investigation: exact match
//     (or wildcard if the statement purl has no version)
//
// Statuses that are not "affected-like" (fixed, known_not_affected) never
// trigger synthesis.
//
//nolint:gocognit
func (advisories advisories) findSynthesisCandidates(pkgs []pkg.Package) []synthesisCandidate {
	var out []synthesisCandidate
	if len(pkgs) == 0 {
		return out
	}

	for _, adv := range advisories {
		if adv == nil || adv.Vulnerabilities == nil {
			continue
		}

		for _, vuln := range adv.Vulnerabilities {
			if vuln == nil || vuln.CVE == nil {
				continue
			}

			productsByStatus := map[status]*csaf.Products{
				firstAffected:      vuln.ProductStatus.FirstAffected,
				knownAffected:      vuln.ProductStatus.KnownAffected,
				lastAffected:       vuln.ProductStatus.LastAffected,
				recommended:        vuln.ProductStatus.Recommended,
				underInvestigation: vuln.ProductStatus.UnderInvestigation,
			}

			for st, products := range productsByStatus {
				if products == nil {
					continue
				}
				for _, productIDPtr := range *products {
					if productIDPtr == nil {
						continue
					}
					productID := *productIDPtr
					helpers := adv.ProductTree.CollectProductIdentificationHelpers(productID)
					for _, stmtPURL := range purlsFromProductIdentificationHelpers(helpers) {
						for i := range pkgs {
							p := &pkgs[i]
							if p.PURL == "" {
								continue
							}
							if !packageMatchesStatement(stmtPURL, p, st) {
								continue
							}
							out = append(out, synthesisCandidate{
								Vulnerability: vuln,
								Status:        st,
								ProductID:     productID,
								Package:       p,
							})
						}
					}
				}
			}
		}
	}

	return out
}

// packageMatchesStatement reports whether the given package's purl falls
// within the scope of a VEX statement that names stmtPURL with the given
// CSAF status. Type/namespace/name/qualifiers must always match; the version
// dimension is interpreted according to the status.
func packageMatchesStatement(stmtPURL string, p *pkg.Package, st status) bool {
	stmt, err := packageurl.FromString(stmtPURL)
	if err != nil {
		return false
	}
	pkgPURL, err := packageurl.FromString(p.PURL)
	if err != nil {
		return false
	}

	if stmt.Type != pkgPURL.Type || stmt.Namespace != pkgPURL.Namespace || stmt.Name != pkgPURL.Name {
		return false
	}
	if !qualifierSubset(stmt.Qualifiers, pkgPURL.Qualifiers) {
		return false
	}

	// No version in the statement -> wildcard, matches any pkg version.
	if stmt.Version == "" {
		return true
	}
	if pkgPURL.Version == "" {
		// Statement is version-specific but the package's purl has none.
		return false
	}

	format := pkg.VersionFormat(*p)

	switch st {
	case lastAffected:
		return compareVersions(pkgPURL.Version, stmt.Version, format, version.LTE)
	case firstAffected:
		return compareVersions(pkgPURL.Version, stmt.Version, format, version.GTE)
	default:
		// knownAffected, recommended, underInvestigation: exact match.
		return stmt.Version == pkgPURL.Version
	}
}

func compareVersions(pkgVersion, stmtVersion string, format version.Format, op version.Operator) bool {
	pkgV := version.New(pkgVersion, format)
	stmtV := version.New(stmtVersion, format)
	ok, err := pkgV.Is(op, stmtV)
	if err != nil {
		return false
	}
	return ok
}

func qualifierSubset(stmtQ, pkgQ packageurl.Qualifiers) bool {
	pkgMap := pkgQ.Map()
	for _, sq := range stmtQ {
		if v, ok := pkgMap[sq.Key]; !ok || v != sq.Value {
			return false
		}
	}
	return true
}

// toAdvisoryMatch returns the advisoryMatch shape expected by the rest of the
// CSAF code (so a synthesis candidate plugs into matchingRule, statement(),
// etc.).
func (c synthesisCandidate) toAdvisoryMatch() *advisoryMatch {
	return &advisoryMatch{
		Vulnerability: c.Vulnerability,
		Status:        c.Status,
		ProductID:     c.ProductID,
	}
}
