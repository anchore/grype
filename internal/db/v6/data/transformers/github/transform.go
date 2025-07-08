package github

import (
	"sort"
	"strings"

	"github.com/anchore/grype/grype/db/data"
	"github.com/anchore/grype/grype/db/data/provider"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/internal/db/data/unmarshal"
	v6 "github.com/anchore/grype/internal/db/v6"
	"github.com/anchore/grype/internal/db/v6/data/transformers"
	"github.com/anchore/grype/internal/db/v6/data/transformers/internal"
	"github.com/anchore/grype/internal/db/v6/name"
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

func getVulnerability(vuln unmarshal.GitHubAdvisory, state provider.State) v6.VulnerabilityHandle {
	return v6.VulnerabilityHandle{
		Name:          vuln.Advisory.GhsaID,
		ProviderID:    state.Provider,
		Provider:      internal.ProviderModel(state),
		ModifiedDate:  internal.ParseTime(vuln.Advisory.Updated),
		PublishedDate: internal.ParseTime(vuln.Advisory.Published),
		WithdrawnDate: internal.ParseTime(vuln.Advisory.Withdrawn),
		Status:        getVulnStatus(vuln),
		BlobValue: &v6.VulnerabilityBlob{
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

func getVulnStatus(vuln unmarshal.GitHubAdvisory) v6.VulnerabilityStatus {
	if vuln.Advisory.Withdrawn == "" {
		return v6.VulnerabilityActive
	}

	return v6.VulnerabilityRejected
}

func getAffectedPackage(vuln unmarshal.GitHubAdvisory) []v6.AffectedPackageHandle {
	var afs []v6.AffectedPackageHandle
	groups := groupFixedIns(vuln)
	hasRangeErr := false
	for group, fixedIns := range groups {
		for _, fixedInEntry := range fixedIns {
			ranges, rangeErr := getRanges(fixedInEntry)
			if rangeErr != nil {
				hasRangeErr = true
			}
			afs = append(afs, v6.AffectedPackageHandle{
				Package: getPackage(group),
				BlobValue: &v6.AffectedPackageBlob{
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

func getRanges(fixedInEntry unmarshal.GithubFixedIn) ([]v6.AffectedRange, error) {
	fixedVersion := v6.AffectedVersion{
		Type:       getAffectedVersionFormat(fixedInEntry),
		Constraint: internal.EnforceSemVerConstraint(fixedInEntry.Range),
	}
	err := validateAffectedVersion(fixedVersion)
	if err != nil {
		log.Warnf("failed to validate affected version: %v", err)
		fixedVersion.Type = version.UnknownFormat.String()
	}
	return []v6.AffectedRange{
		{
			Version: fixedVersion,
			Fix:     getFix(fixedInEntry),
		},
	}, err
}

func validateAffectedVersion(v v6.AffectedVersion) error {
	versionFormat := version.ParseFormat(v.Type)
	c, err := version.GetConstraint(v.Constraint, versionFormat)
	if err != nil {
		return err
	}

	// ensure we can use this version format in a comparison
	ver := version.NewVersion("1.0.0", versionFormat)
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

func getFix(fixedInEntry unmarshal.GithubFixedIn) *v6.Fix {
	fixedInVersion := internal.CleanFixedInVersion(fixedInEntry.Identifier)

	fixState := v6.NotFixedStatus
	if len(fixedInVersion) > 0 {
		fixState = v6.FixedStatus
	}

	return &v6.Fix{
		Version: fixedInVersion,
		State:   fixState,
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

func getPackage(group groupIndex) *v6.Package {
	t := getPackageType(group.ecosystem)
	return &v6.Package{
		Name:      name.Normalize(group.name, t),
		Ecosystem: string(t),
	}
}

func getSeverities(vulnerability unmarshal.GitHubAdvisory) []v6.Severity {
	var severities []v6.Severity

	// the string severity and CVSS is not necessarily correlated (nor is CVSS guaranteed to be provided
	// at all... see https://github.com/advisories/GHSA-xwg4-93c6-3h42 for example), so we need to keep them separate
	cleanSeverity := strings.ToLower(strings.TrimSpace(vulnerability.Advisory.Severity))

	if cleanSeverity != "" {
		severities = append(severities, v6.Severity{
			// This is the string severity based off of CVSS v3
			// see https://docs.github.com/en/code-security/security-advisories/working-with-global-security-advisories-from-the-github-advisory-database/about-the-github-advisory-database?learn=security_advisories&learnProduct=code-security#about-cvss-levels
			Scheme: v6.SeveritySchemeCHML,
			Value:  cleanSeverity,
		})
	}

	if vulnerability.Advisory.CVSS != nil {
		severities = append(severities, v6.Severity{
			Scheme: v6.SeveritySchemeCVSS,
			Value: v6.CVSSSeverity{
				Vector:  vulnerability.Advisory.CVSS.VectorString,
				Version: vulnerability.Advisory.CVSS.Version,
			},
		})
	}

	return severities
}

func getAliases(vulnerability unmarshal.GitHubAdvisory) (aliases []string) {
	aliases = append(aliases, vulnerability.Advisory.CVE...)
	return
}

func getReferences(vulnerability unmarshal.GitHubAdvisory) []v6.Reference {
	// TODO: The additional reference links are not currently captured in the vunnel result, but should be enhanced to
	// https://github.com/anchore/vunnel/issues/646 to capture this
	refs := []v6.Reference{
		{
			URL: vulnerability.Advisory.URL,
		},
	}

	return refs
}
