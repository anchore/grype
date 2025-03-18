package rpm

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/scylladb/go-set/strset"

	"github.com/anchore/go-logger"
	"github.com/anchore/grype/grype/distro"
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
	return []syftPkg.Type{syftPkg.RpmPkg}
}

func (m *Matcher) Type() match.MatcherType {
	return match.RpmMatcher
}

//nolint:funlen
func (m *Matcher) Match(provider vulnerability.Provider, p pkg.Package) ([]match.Match, []match.IgnoreFilter, error) {
	matches := make([]match.Match, 0)

	// let's match with a synthetic package that doesn't exist. We will create a new
	// package that matches the same name and version as what is contained in the
	// "sourceRPM" field.

	// Regarding RPM epoch and comparisons... RedHat is explicit that when an RPM
	// epoch is not specified that it should be assumed to be zero (see
	// https://github.com/rpm-software-management/rpm/issues/450). This comment from
	// RedHat is applicable for a project that has elected to not use epoch and has
	// not changed their version scheme at all --therefore it is safe to assume that
	// the epoch (though not specified) is 0. However, in cases where there may be a
	// non-zero epoch and it has been omitted from the version string it is NOT safe
	// to assume an epoch of 0... as this could lead to misleading comparison
	// results.

	// For example, take the perl-Errno package:
	//		name: 		perl-Errno
	//		version:	0:1.28-419.el8_4.1
	//		sourceRPM:	perl-5.26.3-419.el8_4.1.src.rpm

	// Say we have a vulnerability with the following information (note this is
	// against the SOURCE package "perl", not the target package, "perl-Errno"):
	// 		ID:					CVE-2020-10543
	//		Package Name:		perl
	//		Version constraint:	< 4:5.26.3-419.el8

	// Note that the vulnerability information has complete knowledge about the
	// version and it's lineage (epoch + version), however, the source package
	// information for perl-Errno does not include any information about epoch. With
	// the rule from RedHat we should assume a 0 epoch and make the comparison:

	//		0:5.26.3-419.el8 < 4:5.26.3-419.el8 = true! ... therefore we are vulnerable since epoch 0 < 4.
	//                                                  ... this is an INVALID comparison!

	// The problem with this is that sourceRPMs tend to not specify epoch even though
	// there may be a non-zero epoch for that package! This is important. The "more
	// correct" thing to do in this case is to drop the epoch:

	//		5.26.3-419.el8 < 5.26.3-419.el8 = false!    ... these are the SAME VERSION

	// There is still a problem with this approach: it essentially makes an
	// assumption that a missing epoch really is the SAME epoch to the other version
	// being compared (in our example, no perl epoch on one side means we should
	// really assume an epoch of 4 on the other side). This could still lead to
	// problems since an epoch delimits potentially non-comparable version lineages.

	sourceMatches, err := m.matchUpstreamPackages(provider, p)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to match by source indirection: %w", err)
	}
	matches = append(matches, sourceMatches...)

	// let's match with the package given to us (direct match).

	// Regarding RPM epochs... we know that the package and vulnerability will have
	// well specified epochs since both are sourced from either the RPMDB directly or
	// the upstream RedHat vulnerability data. Note: this is very much UNLIKE our
	// matching on a source package above where the epoch could be dropped in the
	// reference data. This means that any missing epoch CAN be assumed to be zero,
	// as it falls into the case of "the project elected to NOT have a epoch for the
	// first version scheme" and not into any other case.

	// For this reason match exactly on a package we should be EXPLICIT about the
	// epoch (since downstream version comparison logic will strip the epoch during
	// comparison for the above mentioned reasons --essentially for the source RPM
	// case). To do this we fill in missing epoch values in the package versions with
	// an explicit 0.

	exactMatches, err := m.matchPackage(provider, p)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to match by exact package name: %w", err)
	}

	matches = append(matches, exactMatches...)

	return matches, nil, nil
}

func (m *Matcher) matchUpstreamPackages(provider vulnerability.Provider, p pkg.Package) ([]match.Match, error) {
	var matches []match.Match

	for _, indirectPackage := range pkg.UpstreamPackages(p) {
		indirectMatches, _, err := findMatches(provider, indirectPackage, m.Type())
		if err != nil {
			return nil, fmt.Errorf("failed to find vulnerabilities for rpm upstream source package: %w", err)
		}
		matches = append(matches, indirectMatches...)
	}

	// we want to make certain that we are tracking the match based on the package from the SBOM (not the indirect package).
	// The match details already contains the specific indirect package information used to make the match.
	match.ConvertToIndirectMatches(matches, p)

	return matches, nil
}

func (m *Matcher) matchPackage(provider vulnerability.Provider, p pkg.Package) ([]match.Match, error) {
	// we want to ensure that the version ALWAYS has an epoch specified...
	originalPkg := p

	addEpochIfApplicable(&p)

	matches, _, err := findMatches(provider, p, m.Type())
	if err != nil {
		return nil, fmt.Errorf("failed to find vulnerabilities by dpkg source indirection: %w", err)
	}

	// we want to make certain that we are tracking the match based on the package from the SBOM (not the modified package).
	for idx := range matches {
		matches[idx].Package = originalPkg
	}

	return matches, nil
}

func addEpochIfApplicable(p *pkg.Package) {
	meta, ok := p.Metadata.(pkg.RpmMetadata)
	ver := p.Version
	if ver == "" {
		return // no version to work with, so we should not bother with an epoch
	}
	switch {
	case strings.Contains(ver, ":"):
		// we already have an epoch embedded in the version string
		return
	case ok && meta.Epoch != nil:
		// we have an explicit epoch in the metadata
		p.Version = fmt.Sprintf("%d:%s", *meta.Epoch, ver)
	default:
		// no epoch was found, so we will add one
		p.Version = "0:" + ver
	}
}

func findMatches(provider vulnerability.Provider, p pkg.Package, upstreamMatcher match.MatcherType) ([]match.Match, []match.IgnoredMatch, error) {
	if isUnknownVersion(p.Version) {
		log.WithFields("package", p.Name).Trace("skipping package with unknown version")
		return nil, nil, nil
	}

	if isEUSContext(p.Distro) {
		return findEUSMatches(provider, p, upstreamMatcher)
	}

	return internal.MatchPackageByDistro(provider, p, upstreamMatcher)
}

func findEUSMatches(provider vulnerability.Provider, p pkg.Package, upstreamMatcher match.MatcherType) ([]match.Match, []match.IgnoredMatch, error) {
	verObj, err := version.NewVersionFromPkg(p)
	if err != nil {
		if errors.Is(err, version.ErrUnsupportedVersion) {
			log.WithFields("error", err).Tracef("skipping package '%s@%s'", p.Name, p.Version)
			return nil, nil, nil
		}
		return nil, nil, fmt.Errorf("matcher failed to parse version pkg=%q ver=%q: %w", p.Name, p.Version, err)
	}

	disclosures, err := provider.FindVulnerabilities(
		search.ByPackageName(p.Name),
		search.ByDistro(selectDisclosureRange(*p.Distro)...),
		internal.OnlyQualifiedPackages(p),
		// TODO: answer : we can never do this? well, can't do it for alma
		internal.OnlyVulnerableVersions(verObj), // TODO: we do less work by including this here, but if we were being pure about this we'd let the collection handle this
	)
	if err != nil {
		return nil, nil, fmt.Errorf("matcher failed to fetch disclosures for distro=%q pkg=%q: %w", p.Distro, p.Name, err)
	}

	if len(disclosures) == 0 {
		return nil, nil, nil
	}

	c := newCollection(matchPrototype{
		pkg:     p,
		ty:      match.ExactDirectMatch,
		matcher: upstreamMatcher,
		searchedBy: match.DistroParameters{
			Distro: match.DistroIdentification{
				Type:    p.Distro.Type.String(),
				Version: p.Distro.Version,
			},
			Package: match.PackageParameter{
				Name:    p.Name,
				Version: p.Version,
			},
		},
	})

	c.AddDisclosures(disclosures...)

	resolutions, err := provider.FindVulnerabilities(
		search.ByPackageName(p.Name),
		// TODO!
		search.ByDistro(selectResolutionRange(*p.Distro)...),
		internal.OnlyQualifiedPackages(p),
		// internal.OnlyVulnerableVersions(verObj), // this is applied within the collection, so is WRONG to apply here (will result in FPs)
	)

	if err != nil {
		return nil, nil, fmt.Errorf("matcher failed to fetch resolutions for distro=%q pkg=%q: %w", p.Distro, p.Name, err)
	}

	c.AddResolutions(resolutions...)

	matches, err := c.Matches(
		func(v vulnerability.Vulnerability) any {
			return match.DistroResult{
				VulnerabilityID:   v.ID,
				VersionConstraint: v.Constraint.String(),
			}
		},
	)
	// TODO: raise up evidence of ignored matches?
	return matches, nil, err
}

func selectDisclosureRange(d distro.Distro) []distro.Distro {
	if d.Variant == "" {
		return []distro.Distro{d}
	}
	// clear the minor version an designator
	f := d.Version.Segments()
	if len(f) == 0 {
		return []distro.Distro{d}
	}

	newd := distro.New(d.Type, strconv.Itoa(f[0]), d.IDLike...)

	return []distro.Distro{
		*newD,
	}
}

func selectResolutionRange(p vulnerability.Provider, d distro.Distro) []distro.Distro {
	if d.Variant == "" {
		return []distro.Distro{d}
	}

	// TODO: in the future this should reflect based on what OS entries there are in the DB, not just making it up here... and they should be pre-computed
	// answer: no, use criteria

	//f := d.Version.Segments()
	d.Variant = "" // clear the designator so that we can generate new distros without it

	// given rhe 9.4 eus
	// return
	// 9.0, 9.1, 9.2, 9.3, 9.4, 9.4 eus

	return []distro.Distro{
		d,
	}

	//var major, minor int
	//if len(f) == 0 {
	//	// no version segments, so we cannot determine a minor version
	//	return []distro.Distro{d}
	//}
	//major = f[0]
	//if len(f) >= 2 {
	//	minor = f[1]
	//}

	//// generate new distro entries for each minor version staring at 2, every 2 versions, until just before current minor version
	//var distros []distro.Distro
	//for i := 2; i <= minor; i += 2 {
	//	ver := fmt.Sprintf("%d.%d", major, i)
	//	newd := distro.New(d.Type, ver, d.IDLike...)
	//	if err != nil {
	//		continue // if we cannot create a new distro, we will just skip it
	//	}
	//	newD.Variant = d.Variant // ensure we keep the designator
	//	distros = append(distros, *newD)
	//}

	//return distros
}

func isUnknownVersion(v string) bool {
	return v == "" || strings.ToLower(v) == "unknown"
}

func isEUSContext(d *distro.Distro) bool {
	if d == nil {
		return false
	}

	return strings.ToLower(d.Variant) == "eus"
}

type collection struct {
	matchPrototype
	ids             *strset.Set
	disclosuresByID map[string][]Disclosure
	resolutionsByID map[string][]Resolution
}

type matchPrototype struct {
	pkg        pkg.Package
	ty         match.Type
	matcher    match.MatcherType
	searchedBy any
}

func newCollection(prototype matchPrototype) *collection {
	return &collection{
		matchPrototype:  prototype,
		ids:             strset.New(),
		disclosuresByID: make(map[string][]Disclosure),
		resolutionsByID: make(map[string][]Resolution),
	}
}

func (c *collection) AddDisclosures(vs ...vulnerability.Vulnerability) {
	for _, d := range toDisclosures(vs...) {
		if d.ID == "" {
			return // we cannot add a disclosure without an ID
		}
		c.ids.Add(d.ID)
		if existing, ok := c.disclosuresByID[d.ID]; ok {
			c.disclosuresByID[d.ID] = append(existing, d)
		} else {
			c.disclosuresByID[d.ID] = []Disclosure{d}
		}
	}
}

func (c *collection) AddResolutions(vs ...vulnerability.Vulnerability) {
	for _, r := range toResolutions(vs...) {
		if r.ID == "" {
			return // we cannot add a resolution without an ID
		}
		c.ids.Add(r.ID)
		if existing, ok := c.resolutionsByID[r.ID]; ok {
			c.resolutionsByID[r.ID] = append(existing, r)
		} else {
			c.resolutionsByID[r.ID] = []Resolution{r}
		}
	}
}

func (c *collection) Reconcile() ([]vulnerability.Vulnerability, error) {
	ids := c.ids.List()
	sort.Strings(ids)

	p := c.matchPrototype.pkg
	verObj, err := version.NewVersionFromPkg(p)
	if err != nil {
		if errors.Is(err, version.ErrUnsupportedVersion) {
			log.WithFields("error", err).Tracef("skipping package '%s@%s'", p.Name, p.Version)
			return nil, nil
		}
		return nil, fmt.Errorf("unable to reconsile disclosures and resolutions due version pkg=%q ver=%q: %w", p.Name, p.Version, err)
	}

	var vulns []vulnerability.Vulnerability
vulnLoop:
	for _, id := range ids {
		ds, ok := c.disclosuresByID[id]
		if len(ds) == 0 || !ok {
			log.WithFields(logger.Fields{
				"vulnerability": id,
			}).Trace("no disclosures found for vulnerability, skipping")
			continue vulnLoop
		}

		rs, ok := c.resolutionsByID[id]
		if len(rs) == 0 || !ok {
			// no resolutions found for this vulnerability, so we will not include it
			for _, d := range ds {
				vulns = append(vulns, d.Vulnerability)
			}
			continue vulnLoop
		}

		// keep only the disclosures that match the criteria of the resolution
	disclosureLoop:
		for _, d := range ds {
			fixVersions := strset.New()
			var state vulnerability.FixState
			for _, r := range rs {
				switch r.Fix.State {
				case vulnerability.FixStateWontFix, vulnerability.FixStateUnknown:
					// these do not negate disclosures, so we will skip them
					continue
				}
				isVulnerable, err := r.Constraint.Satisfied(verObj)
				if err != nil {
					log.WithFields(logger.Fields{
						"vulnerability": d.ID,
						"error":         err,
					}).Tracef("failed to check constraint for vulnerability")
					continue // skip this resolution, but check other resolutions
				}
				if !isVulnerable {
					// a fix applies to the package, so we're not vulnerable (thus should not keep this disclosure)
					// TODO: in the future raise up evidence of this
					continue disclosureLoop
				}
				// we're vulnerable! keep any fix versions that could have been applied

				fixVersions.Add(r.Fix.Versions...)
				if state != vulnerability.FixStateFixed {
					state = r.Fix.State
				}
			}

			if state != vulnerability.FixStateFixed {
				// TODO: this needs to get rethought as we come up with more reasons here (e.g. not applicable, not vulnerable, etc.)
				continue
			}

			vuln := d.Vulnerability

			fixVersions.Remove("")
			fixVersionList := fixVersions.List()
			sort.Strings(fixVersionList) // TODO: use version sort, not lexically

			vuln.Fix.State = state
			vuln.Fix.Versions = fixVersionList

			// this disclosure does not have a resolution that satisfies it, so we will keep it... patching on any fixes that we are aware of
			vulns = append(vulns, vuln)
		}

		// TODO: in the future we should save evidence of being ignored here
	}

	return vulns, nil
}

func (c *collection) Matches(found func(vulnerability.Vulnerability) any) ([]match.Match, error) {
	vulns, err := c.Reconcile()
	if err != nil {
		return nil, fmt.Errorf("failed to reconcile vulnerabilities: %w", err)
	}

	var matches []match.Match
	for _, vuln := range vulns {
		sb := c.matchPrototype.searchedBy
		switch v := sb.(type) {
		case match.DistroParameters:
			v.Namespace = vuln.Namespace
			sb = v
		}

		detail := match.Detail{
			Type:       c.matchPrototype.ty,
			Matcher:    c.matchPrototype.matcher,
			SearchedBy: sb,
			Found:      found(vuln),
			Confidence: confidenceForMatchType(c.matchPrototype.ty),
		}

		matches = append(matches, match.Match{
			Vulnerability: vuln,
			Package:       c.matchPrototype.pkg,
			Details:       []match.Detail{detail},
		})
	}
	return matches, nil
}

func confidenceForMatchType(mt match.Type) float64 {
	switch mt {
	case match.ExactDirectMatch, match.ExactIndirectMatch:
		return 1.0 // TODO: this is hard coded for now
	case match.CPEMatch:
		return 0.9 // TODO: this is hard coded for now
	default:
		return 0.0
	}
}

// Disclosure represents a claim of something being vulnerable.
type Disclosure struct {
	// temporary
	// TODO: we must not include fix info (e.g. alma)
	vulnerability.Vulnerability
}

// Resolution represents the conclusion of a vulnerability being fixed, wont-fixed, or not-fixed, and the specifics thereof.
type Resolution struct {
	// temporary
	vulnerability.Reference
	vulnerability.Fix
	Constraint version.Constraint // TODO: i really don't want this here, but we don't have the format until we expose the data from the fix directly
}

func toDisclosures(vs ...vulnerability.Vulnerability) []Disclosure {
	// temporary
	var out []Disclosure
	for _, v := range vs {
		// TODO: should we remove the fix info?
		out = append(out, Disclosure{Vulnerability: v})
	}
	return out
}

func toResolutions(vs ...vulnerability.Vulnerability) []Resolution {
	// temporary
	var out []Resolution
	for _, v := range vs {
		if len(v.Fix.Versions) == 0 {
			continue
		}
		var constraints []string
		for _, f := range v.Fix.Versions {
			constraints = append(constraints, fmt.Sprintf("< %s", f))
		}

		constraint, err := version.GetConstraint(strings.Join(constraints, " || "), v.Constraint.Format())
		if err != nil {
			log.WithFields("error", err, "vulnerability", v.String()).Debug("unable to parse fix constraint")
			continue // skip this resolution
		}

		out = append(out, Resolution{
			Reference:  v.Reference,
			Fix:        v.Fix,
			Constraint: constraint, // TODO: not great, but is actionable based on the fix
		})
	}
	return out
}
