package github

import (
	"sort"
	"strings"

	"github.com/anchore/grype/grype/db/data"
	"github.com/anchore/grype/grype/db/internal/provider/unmarshal"
	"github.com/anchore/grype/grype/db/internal/versionutil"
	"github.com/anchore/grype/grype/db/provider"
	db "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/build/internal/transformers"
	"github.com/anchore/grype/grype/db/v6/build/internal/transformers/internal"
	"github.com/anchore/grype/grype/db/v6/name"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/internal/log"
	"github.com/anchore/syft/syft/pkg"
)

func Transform(vulnerability unmarshal.GitHubAdvisory, state provider.State) ([]data.Entry, error) {
	ins := []any{
		getVulnerability(vulnerability, state),
	}

	for _, a := range getAffectedPackage(vulnerability) {
		ins = append(ins, a)
	}

	return transformers.NewEntries(ins...), nil
}

func getVulnerability(vuln unmarshal.GitHubAdvisory, state provider.State) db.VulnerabilityHandle {
	return db.VulnerabilityHandle{
		Name:          vuln.Advisory.GhsaID,
		ProviderID:    state.Provider,
		Provider:      internal.ProviderModel(state),
		ModifiedDate:  internal.ParseTime(vuln.Advisory.Updated),
		PublishedDate: internal.ParseTime(vuln.Advisory.Published),
		WithdrawnDate: internal.ParseTime(vuln.Advisory.Withdrawn),
		Status:        getVulnStatus(vuln),
		BlobValue: &db.VulnerabilityBlob{
			ID: vuln.Advisory.GhsaID,
			// it does not appear to be possible to get "credits" or any user information from the graphql API
			// for security advisories (see https://docs.github.com/en/graphql/reference/queries#securityadvisories),
			// thus assigner is left empty.
			Assigners:   nil,
			Description: strings.TrimSpace(vuln.Advisory.Summary),
			References:  getReferences(vuln),
			Aliases:     getAliases(vuln),
			Severities:  getSeverities(vuln),
		},
	}
}

func getVulnStatus(vuln unmarshal.GitHubAdvisory) db.VulnerabilityStatus {
	if vuln.Advisory.Withdrawn == "" {
		return db.VulnerabilityActive
	}

	return db.VulnerabilityRejected
}

func getAffectedPackage(vuln unmarshal.GitHubAdvisory) []db.AffectedPackageHandle {
	var afs []db.AffectedPackageHandle
	groups := groupFixedIns(vuln)
	hasRangeErr := false
	for group, fixedIns := range groups {
		for _, fixedInEntry := range fixedIns {
			ranges, rangeErr := getRanges(fixedInEntry)
			if rangeErr != nil {
				hasRangeErr = true
			}
			afs = append(afs, db.AffectedPackageHandle{
				Package: getPackage(group),
				BlobValue: &db.PackageBlob{
					CVEs:   getAliases(vuln),
					Ranges: ranges,
				},
			})
		}
	}

	// stable ordering
	sort.Sort(internal.ByAffectedPackage(afs))

	if hasRangeErr {
		log.Warnf("for %s falling back to fuzzy matching on at least one constraint range", vuln.Advisory.GhsaID)
	}
	return afs
}

func getRanges(fixedInEntry unmarshal.GithubFixedIn) ([]db.Range, error) {
	fixedVersion := db.Version{
		Type:       getAffectedVersionFormat(fixedInEntry),
		Constraint: versionutil.EnforceSemVerConstraint(fixedInEntry.Range),
	}
	err := validateAffectedVersion(fixedVersion)
	if err != nil {
		log.Warnf("failed to validate affected version: %v", err)
		fixedVersion.Type = version.UnknownFormat.String()
	}
	return []db.Range{
		{
			Version: fixedVersion,
			Fix:     getFix(fixedInEntry),
		},
	}, err
}

func validateAffectedVersion(v db.Version) error {
	versionFormat := version.ParseFormat(v.Type)
	c, err := version.GetConstraint(v.Constraint, versionFormat)
	if err != nil {
		return err
	}

	// ensure we can use this version format in a comparison
	ver := version.New("1.0.0", versionFormat)
	if err := ver.Validate(); err != nil {
		// don't have a good example to use here
		// TODO: we should consider finding a better way to do this without having to create a valid version for comparison
		return nil
	}

	_, err = c.Satisfied(ver)

	return err
}

func getAffectedVersionFormat(fixedInEntry unmarshal.GithubFixedIn) string {
	versionFormat := strings.ToLower(fixedInEntry.Ecosystem)

	if versionFormat == "pip" {
		versionFormat = "python"
	}

	return versionFormat
}

func getFix(fixedInEntry unmarshal.GithubFixedIn) *db.Fix {
	fixedInVersion := versionutil.CleanFixedInVersion(fixedInEntry.Identifier)

	fixState := db.NotFixedStatus
	if len(fixedInVersion) > 0 {
		fixState = db.FixedStatus
	}

	var detail *db.FixDetail
	availability := getFixAvailability(fixedInEntry)
	if availability != nil {
		detail = &db.FixDetail{
			Available: availability,
		}
	}

	return &db.Fix{
		Version: fixedInVersion,
		State:   fixState,
		Detail:  detail,
	}
}

func getFixAvailability(fixedInEntry unmarshal.GithubFixedIn) *db.FixAvailability {
	if fixedInEntry.Available.Date == "" {
		return nil
	}

	t := internal.ParseTime(fixedInEntry.Available.Date)
	if t == nil {
		log.WithFields("date", fixedInEntry.Available.Date).Warn("unable to parse fix availability date")
		return nil
	}

	return &db.FixAvailability{
		Date: t,
		Kind: fixedInEntry.Available.Kind,
	}
}

type groupIndex struct {
	name      string
	ecosystem string
}

func groupFixedIns(vuln unmarshal.GitHubAdvisory) map[groupIndex][]unmarshal.GithubFixedIn {
	grouped := make(map[groupIndex][]unmarshal.GithubFixedIn)

	for _, fixedIn := range vuln.Advisory.FixedIn {
		g := groupIndex{
			name:      fixedIn.Name,
			ecosystem: fixedIn.Ecosystem,
		}

		grouped[g] = append(grouped[g], fixedIn)
	}
	return grouped
}

func getPackageType(ecosystem string) pkg.Type {
	ecosystem = strings.ToLower(ecosystem)
	switch ecosystem {
	case "composer":
		return pkg.PhpComposerPkg
	case "rust", "cargo":
		return pkg.RustPkg
	case "dart":
		return pkg.DartPubPkg
	case "nuget", ".net":
		return pkg.DotnetPkg
	case "go", "golang":
		return pkg.GoModulePkg
	case "maven", "java":
		return pkg.JavaPkg
	case "npm":
		return pkg.NpmPkg
	case "pypi", "python", "pip":
		return pkg.PythonPkg
	case "swift":
		return pkg.SwiftPkg
	case "rubygems", "ruby", "gem":
		return pkg.GemPkg
	case "erlang", "hex", "elixir":
		return pkg.HexPkg
	case "apk":
		return pkg.ApkPkg
	case "rpm":
		return pkg.RpmPkg
	case "deb":
		return pkg.DebPkg
	case "github-action":
		return pkg.GithubActionPkg
	}
	ty := pkg.TypeByName(ecosystem)
	if ty != pkg.UnknownPkg {
		return ty
	}

	log.Warnf("using unknown ecosystem intead of syft pkg type (this will probably cause issues when matching): %q", ecosystem)

	return pkg.Type(ecosystem)
}

func getPackage(group groupIndex) *db.Package {
	t := getPackageType(group.ecosystem)
	return &db.Package{
		Name:      name.Normalize(group.name, t),
		Ecosystem: string(t),
	}
}

func getSeverities(vulnerability unmarshal.GitHubAdvisory) []db.Severity {
	var severities []db.Severity

	// the string severity and CVSS is not necessarily correlated (nor is CVSS guaranteed to be provided
	// at all... see https://github.com/advisories/GHSA-xwg4-93c6-3h42 for example), so we need to keep them separate
	cleanSeverity := strings.ToLower(strings.TrimSpace(vulnerability.Advisory.Severity))

	if cleanSeverity != "" {
		severities = append(severities, db.Severity{
			// This is the string severity based off of CVSS v3
			// see https://docs.github.com/en/code-security/security-advisories/working-with-global-security-advisories-from-the-github-advisory-database/about-the-github-advisory-database?learn=security_advisories&learnProduct=code-security#about-cvss-levels
			Scheme: db.SeveritySchemeCHML,
			Value:  cleanSeverity,
		})
	}

	// If the new CVSSSeverities field isn't populated, fallback to the old CVSS property
	if len(vulnerability.Advisory.CVSSSeverities) == 0 && vulnerability.Advisory.CVSS != nil {
		severities = append(severities, db.Severity{
			Scheme: db.SeveritySchemeCVSS,
			Value: db.CVSSSeverity{
				Vector:  vulnerability.Advisory.CVSS.VectorString,
				Version: vulnerability.Advisory.CVSS.Version,
			},
		})
	} else {
		for _, cvss := range vulnerability.Advisory.CVSSSeverities {
			severities = append(severities, db.Severity{
				Scheme: db.SeveritySchemeCVSS,
				Value: db.CVSSSeverity{
					Vector:  cvss.Vector,
					Version: cvss.Version,
				},
			})
		}
	}

	return severities
}

func getAliases(vulnerability unmarshal.GitHubAdvisory) (aliases []string) {
	aliases = append(aliases, vulnerability.Advisory.CVE...)
	return
}

func getReferences(vulnerability unmarshal.GitHubAdvisory) []db.Reference {
	// Capture the GitHub Advisory URL as the first reference
	refs := []db.Reference{
		{
			URL: vulnerability.Advisory.URL,
		},
	}

	for _, reference := range vulnerability.Advisory.References {
		clean := strings.TrimSpace(reference.URL)
		if clean == "" {
			continue
		}
		// TODO there is other info we could be capturing too (source)
		refs = append(refs, db.Reference{
			URL: clean,
		})
	}

	return transformers.DeduplicateReferences(refs)
}
