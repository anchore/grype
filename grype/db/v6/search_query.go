package v6

import (
	"fmt"

	"github.com/anchore/grype/grype/db/v6/name"
	"github.com/anchore/grype/grype/search"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/cpe"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// searchQuery holds the parsed criteria and search parameters
type searchQuery struct {
	pkgSpec        *PackageSpecifier
	cpeSpec        *cpe.Attributes
	osSpecs        OSSpecifiers
	vulnSpecs      VulnerabilitySpecifiers
	pkgType        syftPkg.Type
	versionMatcher search.VersionConstraintMatcher
	unaffectedOnly bool
}

func newSearchQuery(criteriaSet []vulnerability.Criteria) (*searchQuery, []vulnerability.Criteria, error) {
	builder := newSearchQueryBuilder()

	if err := builder.ApplyCriteria(criteriaSet); err != nil {
		return nil, nil, err
	}

	return builder.Build()
}

// searchQueryBuilder provides a structured way to build searchQuery objects
// from vulnerability criteria, replacing the large switch statement with focused handler methods.
type searchQueryBuilder struct {
	query             *searchQuery
	remainingCriteria []vulnerability.Criteria
}

// newSearchQueryBuilder creates a new searchQueryBuilder with an empty query
func newSearchQueryBuilder() *searchQueryBuilder {
	return &searchQueryBuilder{
		query:             &searchQuery{},
		remainingCriteria: make([]vulnerability.Criteria, 0),
	}
}

// ApplyCriteria processes all criteria using type-switch dispatch to individual handlers
func (b *searchQueryBuilder) ApplyCriteria(criteriaSet []vulnerability.Criteria) error {
	for _, c := range criteriaSet {
		applied := false

		switch c := c.(type) {
		case *search.PackageNameCriteria:
			b.handlePackageName(c)
			applied = true
		case *search.UnaffectedCriteria:
			b.handleUnaffected(c)
			applied = true
		case *search.EcosystemCriteria:
			b.handleEcosystem(c)
			applied = true
		case *search.IDCriteria:
			b.handleID(c)
			applied = true
		case *search.CPECriteria:
			if err := b.handleCPE(c); err != nil {
				return err
			}
			applied = true
		case *search.DistroCriteria:
			b.handleDistro(c)
			applied = true
		case *search.ExactDistroCriteria:
			b.handleExactDistro(c)
			applied = true
		}

		if !applied {
			b.remainingCriteria = append(b.remainingCriteria, c)
		}
	}
	return nil
}

func (b *searchQueryBuilder) handlePackageName(c *search.PackageNameCriteria) {
	if b.query.pkgSpec == nil {
		b.query.pkgSpec = &PackageSpecifier{}
	}
	b.query.pkgSpec.Name = c.PackageName
}

func (b *searchQueryBuilder) handleUnaffected(_ *search.UnaffectedCriteria) {
	b.query.unaffectedOnly = true
}

func (b *searchQueryBuilder) handleEcosystem(c *search.EcosystemCriteria) {
	if b.query.pkgSpec == nil {
		b.query.pkgSpec = &PackageSpecifier{}
	}

	// the v6 store normalizes ecosystems around the syft package type, so that field is preferred
	switch {
	case c.PackageType != "" && c.PackageType != syftPkg.UnknownPkg:
		// prefer to match by a non-blank, known package type
		b.query.pkgType = c.PackageType
		b.query.pkgSpec.Ecosystem = string(c.PackageType)
	case c.Language != "":
		// if there's no known package type, but there is a non-blank language try that
		b.query.pkgSpec.Ecosystem = string(c.Language)
	case c.PackageType == syftPkg.UnknownPkg:
		// if language is blank, and package type is explicitly "UnknownPkg" and not just blank, use that
		b.query.pkgType = c.PackageType
		b.query.pkgSpec.Ecosystem = string(c.PackageType)
	}
}

func (b *searchQueryBuilder) handleID(c *search.IDCriteria) {
	b.query.vulnSpecs = append(b.query.vulnSpecs, VulnerabilitySpecifier{
		Name: c.ID,
	})
}

func (b *searchQueryBuilder) handleCPE(c *search.CPECriteria) error {
	if b.query.cpeSpec == nil {
		b.query.cpeSpec = &cpe.Attributes{}
	}
	*b.query.cpeSpec = c.CPE.Attributes

	if b.query.cpeSpec.Product == cpe.Any {
		return fmt.Errorf("must specify product to search by CPE; got: %s", c.CPE.Attributes.BindToFmtString())
	}

	if b.query.pkgSpec == nil {
		b.query.pkgSpec = &PackageSpecifier{}
	}
	b.query.pkgSpec.CPE = &c.CPE.Attributes

	return nil
}

func (b *searchQueryBuilder) handleDistro(c *search.DistroCriteria) {
	for _, d := range c.Distros {
		var foundChannels int
		for _, channel := range d.Channels {
			if channel == "" {
				// if the channel is empty, we should not add it to the OS specifier
				continue
			}
			foundChannels++
			b.query.osSpecs = append(b.query.osSpecs, &OSSpecifier{
				Name:             d.Name(),
				MajorVersion:     d.MajorVersion(),
				MinorVersion:     d.MinorVersion(),
				RemainingVersion: d.RemainingVersion(),
				LabelVersion:     d.Codename,
				Channel:          channel,
			})
		}
		if foundChannels == 0 {
			b.query.osSpecs = append(b.query.osSpecs, &OSSpecifier{
				Name:             d.Name(),
				MajorVersion:     d.MajorVersion(),
				MinorVersion:     d.MinorVersion(),
				RemainingVersion: d.RemainingVersion(),
				LabelVersion:     d.Codename,
			})
		}
	}
}

func (b *searchQueryBuilder) handleExactDistro(c *search.ExactDistroCriteria) {
	for _, d := range c.Distros {
		var foundChannels int
		for _, channel := range d.Channels {
			if channel == "" {
				// if the channel is empty, we should not add it to the OS specifier
				continue
			}
			foundChannels++
			b.query.osSpecs = append(b.query.osSpecs, &OSSpecifier{
				Name:             d.Name(),
				MajorVersion:     d.MajorVersion(),
				MinorVersion:     d.MinorVersion(),
				RemainingVersion: d.RemainingVersion(),
				LabelVersion:     d.Codename,
				Channel:          channel,
				DisableAliasing:  true,
			})
		}
		if foundChannels == 0 {
			b.query.osSpecs = append(b.query.osSpecs, &OSSpecifier{
				Name:             d.Name(),
				MajorVersion:     d.MajorVersion(),
				MinorVersion:     d.MinorVersion(),
				RemainingVersion: d.RemainingVersion(),
				LabelVersion:     d.Codename,
				DisableAliasing:  true,
			})
		}
	}
}

// setDefaultOS sets default OS if none specified
func (b *searchQueryBuilder) setDefaultOS() {
	if len(b.query.osSpecs) == 0 {
		// we don't want to search across all distros, instead if the user did not specify a distro we should assume that
		// they want to search across affected packages not associated with any distro.
		b.query.osSpecs = append(b.query.osSpecs, NoOSSpecified)
	}
}

// normalizePackageName normalizes package name if needed
func (b *searchQueryBuilder) normalizePackageName() {
	if b.query.pkgType != "" && b.query.pkgSpec != nil && b.query.pkgSpec.Name != "" {
		b.query.pkgSpec.Name = name.Normalize(b.query.pkgSpec.Name, b.query.pkgType)
	}
}

// extractVersionMatcher extracts version constraints from remaining criteria
func (b *searchQueryBuilder) extractVersionMatcher() {
	var remaining []vulnerability.Criteria
	var matcher search.VersionConstraintMatcher

	for _, c := range b.remainingCriteria {
		if nextMatcher, ok := c.(search.VersionConstraintMatcher); ok {
			if matcher == nil {
				matcher = nextMatcher
			} else {
				matcher = search.MultiConstraintMatcher(matcher, nextMatcher)
			}
		} else {
			remaining = append(remaining, c)
		}
	}

	b.query.versionMatcher = matcher
	b.remainingCriteria = remaining
}

// Build returns the final query and remaining criteria
func (b *searchQueryBuilder) Build() (*searchQuery, []vulnerability.Criteria, error) {
	b.setDefaultOS()
	b.normalizePackageName()
	b.extractVersionMatcher()

	return b.query, b.remainingCriteria, nil
}
