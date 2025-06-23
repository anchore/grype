package apk

import (
	"errors"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher/internal"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/search"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/log"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

type Matcher struct {
}

func (m *Matcher) PackageTypes() []syftPkg.Type {
	return []syftPkg.Type{syftPkg.ApkPkg}
}

func (m *Matcher) Type() match.MatcherType {
	return match.ApkMatcher
}

func (m *Matcher) Match(store vulnerability.Provider, p pkg.Package) ([]match.Match, []match.IgnoreFilter, error) {

	// direct matches with package itself
	matches, ignored, err := m.findMatchesForPackage(store, p, match.ExactDirectMatch)
	if err != nil {
		return nil, nil, err
	}

	// indirect matches via package's origin package
	for _, indirectPackage := range pkg.UpstreamPackages(p) {
		indMatches, indIgnored, err := m.findMatchesForPackage(store, indirectPackage, match.ExactIndirectMatch)
		if err != nil {
			return nil, nil, err
		}
		matches = append(matches, indMatches...)
		ignored = append(ignored, indIgnored...)
	}

	return matches, ignored, err
}

func (m *Matcher) findMatchesForPackage(store vulnerability.Provider, p pkg.Package, ty match.Type) ([]match.Match, []match.IgnoreFilter, error) {
	c := internal.NewMatchFactory(p)

	cfg := internal.DisclosureConfig{
		KeepFixVersions: false,
		// we do not want to keep the fix versions for APK matches, because they are not useful in this context
	}
	// find SecDB matches for the given package name and version
	secDBMatches, _, err := internal.MatchPackageByDistro(store, p, ty, m.Type())
	if err != nil {
		// TODO: we're dropping some....
		return nil, nil, err
	}

	c.AddMatchesAsDisclosures(cfg, secDBMatches...)

	// TODO: are there other errors that we should handle here that causes this to short circuit
	err = m.cpeMatchesWithoutSecDBFixes(store, c, p)
	if err != nil && !errors.Is(err, internal.ErrEmptyCPEMatch) {
		// TODO: we're dropping some....
		return nil, nil, err
	}

	// APK sources are also able to NAK vulnerabilities, so we want to return these as explicit ignores in order
	// to allow rules later to use these to ignore "the same" vulnerability found in "the same" locations
	naks, err := store.FindVulnerabilities(
		search.ByDistro(*p.Distro),
		search.ByPackageName(p.Name),
		nakConstraint,
	)
	if err != nil {
		// TODO: we're dropping some....
		return nil, nil, err
	}

	c.AddVulnsAsResolutions(
		naks...,
	)

	matches, ignored, err := c.Matches()
	if err != nil {
		// TODO: we're dropping some....
		return nil, nil, err
	}

	// we still need to raise up explicit ignore rules for every package that has a NAK vulnerability. Note that
	// this is separate from the combination of disclosures and resolutions that we have already created. This is
	// because NAKs should apply to results from other matchers, not just the APK matcher.
	for _, nak := range naks {
		meta, ok := p.Metadata.(pkg.ApkMetadata)
		if !ok {
			continue
		}

		for _, f := range meta.Files {
			ignored = append(ignored,
				match.IgnoreRule{
					Vulnerability:  nak.ID,
					IncludeAliases: true,
					Reason:         "Explicit APK NAK",
					Package: match.IgnoreRulePackage{
						Location: f.Path,
					},
				})
		}
	}

	return matches, ignored, nil
}

//nolint:funlen,gocognit
func (m *Matcher) cpeMatchesWithoutSecDBFixes(provider vulnerability.Provider, c *internal.MatchFactory, p pkg.Package) error {
	if p.Distro == nil {
		return nil
	}

	cfg := internal.DisclosureConfig{
		KeepFixVersions: false,
	}

	// find CPE-indexed vulnerability matches specific to the given package name and version
	cpeMatches, err := internal.MatchPackageByCPEs(provider, p, m.Type())
	if err != nil {
		log.WithFields("package", p.Name, "error", err).Debug("failed to find CPE matches for package")
	}

	c.AddMatchesAsDisclosures(cfg, cpeMatches...)

	// remove cpe matches where there is an entry in the secDB for the particular package-vulnerability pairing, and the
	// installed package version is >= the fixed in version for the secDB record.
	secDBVulnerabilities, err := provider.FindVulnerabilities(
		search.ByPackageName(p.Name),
		search.ByDistro(*p.Distro),
	)
	if err != nil {
		return err
	}

	// TODO: this is a different set of packages than what the match factory represents... can we combine indirect and direct indications here?
	for _, upstreamPkg := range pkg.UpstreamPackages(p) {
		secDBVulnerabilitiesForUpstream, err := provider.FindVulnerabilities(
			search.ByPackageName(upstreamPkg.Name),
			search.ByDistro(*upstreamPkg.Distro))
		if err != nil {
			return err
		}
		secDBVulnerabilities = append(secDBVulnerabilities, secDBVulnerabilitiesForUpstream...)
	}

	c.AddVulnsAsResolutions(secDBVulnerabilities...)

	return nil
}

var (
	nakVersionString = version.MustGetConstraint("< 0", version.ApkFormat).String()
	// nakConstraint checks the exact version string for being an APK version with "< 0"
	nakConstraint = search.ByConstraintFunc(func(c version.Constraint) (bool, error) {
		return c.String() == nakVersionString, nil
	})
)
