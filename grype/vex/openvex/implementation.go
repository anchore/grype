package openvex

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	openvex "github.com/openvex/go-vex/pkg/vex"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/source"
)

type Processor struct{}

func New() *Processor {
	return &Processor{}
}

// Match captures the criteria that caused a vulnerability to match
type Match struct {
	Statement openvex.Statement
}

// SearchedBy captures the prameters used to search through the VEX data
type SearchedBy struct {
	Vulnerability string
	Product       string
	Subcomponents []string
}

// augmentStatuses are the VEX statuses that augment results
var augmentStatuses = []openvex.Status{
	openvex.StatusAffected,
	openvex.StatusUnderInvestigation,
}

// filterStatuses are the VEX statuses that filter matched to the ignore list
var ignoreStatuses = []openvex.Status{
	openvex.StatusNotAffected,
	openvex.StatusFixed,
}

// ReadVexDocuments reads and merges VEX documents
func (ovm *Processor) ReadVexDocuments(docs []string) (interface{}, error) {
	// Combine all VEX documents into a single VEX document
	vexdata, err := openvex.MergeFiles(docs)
	if err != nil {
		return nil, fmt.Errorf("merging vex documents: %w", err)
	}

	return vexdata, nil
}

// productIdentifiersFromContext reads the package context and returns software
// identifiers identifying the scanned image.
func productIdentifiersFromContext(pkgContext *pkg.Context) ([]string, error) {
	switch v := pkgContext.Source.Metadata.(type) {
	case source.ImageMetadata:
		tagIdentifiers := identifiersFromTags(v.Tags, pkgContext.Source.Name)
		digestIdentifiers := identifiersFromDigests(v.RepoDigests)
		identifiers := slices.Concat(tagIdentifiers, digestIdentifiers)
		return identifiers, nil
	default:
		// Fail for now
		return nil, errors.New("source type not supported for VEX")
	}
}

func identifiersFromTags(tags []string, name string) []string {
	identifiers := []string{}

	for _, tag := range tags {
		identifiers = append(identifiers, tag)

		tagMap := map[string]string{}
		_, splitTag, found := strings.Cut(tag, ":")
		if found {
			tagMap["tag"] = splitTag
			qualifiers := packageurl.QualifiersFromMap(tagMap)

			identifiers = append(identifiers, packageurl.NewPackageURL("oci", "", name, "", qualifiers, "").String())
		}
	}

	return identifiers
}

func identifiersFromDigests(digests []string) []string {
	identifiers := []string{}

	for _, d := range digests {
		// The first identifier is the original image reference:
		identifiers = append(identifiers, d)

		// Not an image reference, skip
		ref, err := name.ParseReference(d)
		if err != nil {
			continue
		}

		var repoURL string
		shaString := ref.Identifier()

		// If not a digest, we can't form a purl, so skip it
		if !strings.HasPrefix(shaString, "sha256:") {
			continue
		}

		pts := strings.Split(ref.Context().RepositoryStr(), "/")
		name := pts[len(pts)-1]
		repoURL = strings.TrimSuffix(
			ref.Context().RegistryStr()+"/"+ref.Context().RepositoryStr(),
			fmt.Sprintf("/%s", name),
		)

		qMap := map[string]string{}

		if repoURL != "" {
			qMap["repository_url"] = repoURL
		}
		qs := packageurl.QualifiersFromMap(qMap)
		identifiers = append(identifiers, packageurl.NewPackageURL(
			"oci", "", name, shaString, qs, "",
		).String())

		// Add a hash to the identifier list in case people want to vex
		// using the value of the image digest
		identifiers = append(identifiers, strings.TrimPrefix(shaString, "sha256:"))
	}
	return identifiers
}

// subcomponentIdentifiersFromMatch returns the list of identifiers from the
// package where grype did the match.
func subcomponentIdentifiersFromMatch(m *match.Match) []string {
	ret := []string{}
	if m.Package.PURL != "" {
		ret = append(ret, m.Package.PURL)
	}

	// TODO(puerco):Implement CPE matching in openvex/go-vex
	/*
		for _, c := range m.Package.CPEs {
			ret = append(ret, c.String())
		}
	*/
	return ret
}

// FilterMatches takes a set of scanning results and moves any results marked in
// the VEX data as fixed or not_affected to the ignored list.
func (ovm *Processor) FilterMatches(
	docRaw interface{}, ignoreRules []match.IgnoreRule, pkgContext *pkg.Context, matches *match.Matches, ignoredMatches []match.IgnoredMatch,
) (*match.Matches, []match.IgnoredMatch, error) {
	doc, ok := docRaw.(*openvex.VEX)
	if !ok {
		return nil, nil, errors.New("unable to cast vex document as openvex")
	}

	remainingMatches := match.NewMatches()

	products, err := productIdentifiersFromContext(pkgContext)
	if err != nil {
		return nil, nil, fmt.Errorf("reading product identifiers from context: %w", err)
	}

	// TODO(alex): should we apply the vex ignore rules to the already ignored matches?
	// that way the end user sees all of the reasons a match was ignored in case multiple apply

	// Now, let's go through grype's matches
	sorted := matches.Sorted()
	for i := range sorted {
		var statement *openvex.Statement
		subcmp := subcomponentIdentifiersFromMatch(&sorted[i])

		// Range through the product's different names
		for _, product := range products {
			if matchingStatements := doc.Matches(sorted[i].Vulnerability.ID, product, subcmp); len(matchingStatements) != 0 {
				statement = &matchingStatements[0]
				break
			}
		}

		// No data about this match's component. Next.
		if statement == nil {
			remainingMatches.Add(sorted[i])
			continue
		}

		rule := matchingRule(ignoreRules, sorted[i], statement, ignoreStatuses)
		if rule == nil {
			remainingMatches.Add(sorted[i])
			continue
		}

		// Filtering only applies to not_affected and fixed statuses
		if statement.Status != openvex.StatusNotAffected && statement.Status != openvex.StatusFixed {
			remainingMatches.Add(sorted[i])
			continue
		}

		ignoredMatches = append(ignoredMatches, match.IgnoredMatch{
			Match:              sorted[i],
			AppliedIgnoreRules: []match.IgnoreRule{*rule},
		})
	}
	return &remainingMatches, ignoredMatches, nil
}

// matchingRule cycles through a set of ignore rules and returns the first
// one that matches the statement and the match. Returns nil if none match.
func matchingRule(ignoreRules []match.IgnoreRule, m match.Match, statement *openvex.Statement, allowedStatuses []openvex.Status) *match.IgnoreRule {
	ms := match.NewMatches()
	ms.Add(m)

	revStatuses := map[string]struct{}{}
	for _, s := range allowedStatuses {
		revStatuses[string(s)] = struct{}{}
	}

	for _, rule := range ignoreRules {
		// If the rule has more conditions than just the VEX statement, check if
		// it applies to the current match.
		if rule.HasConditions() {
			r := rule
			r.VexStatus = ""
			if _, ignored := match.ApplyIgnoreRules(ms, []match.IgnoreRule{r}); len(ignored) == 0 {
				continue
			}
		}

		// If the status in the statement is not the same in the rule
		// and the vex statement, it does not apply
		if string(statement.Status) != rule.VexStatus {
			continue
		}

		// If the rule has a statement other than the allowed ones, skip:
		if len(revStatuses) > 0 && rule.VexStatus != "" {
			if _, ok := revStatuses[rule.VexStatus]; !ok {
				continue
			}
		}

		// If the rule applies to a VEX justification it needs to match the
		// statement, note that justifications only apply to not_affected:
		if statement.Status == openvex.StatusNotAffected && rule.VexJustification != "" &&
			rule.VexJustification != string(statement.Justification) {
			continue
		}

		// If the vulnerability is blank in the rule it means we will honor
		// any status with any vulnerability.
		if rule.Vulnerability == "" {
			return &rule
		}

		// If the vulnerability is set, the rule applies if it is the same
		// in the statement and the rule.
		if statement.Vulnerability.Matches(rule.Vulnerability) {
			return &rule
		}
	}
	return nil
}

// AugmentMatches adds results to the match.Matches array when matching data
// about an affected VEX product is found on loaded VEX documents. Matches
// are moved from the ignore list or synthesized when no previous data is found.
func (ovm *Processor) AugmentMatches(
	docRaw interface{}, ignoreRules []match.IgnoreRule, pkgContext *pkg.Context, remainingMatches *match.Matches, ignoredMatches []match.IgnoredMatch,
) (*match.Matches, []match.IgnoredMatch, error) {
	doc, ok := docRaw.(*openvex.VEX)
	if !ok {
		return nil, nil, errors.New("unable to cast vex document as openvex")
	}

	additionalIgnoredMatches := []match.IgnoredMatch{}

	products, err := productIdentifiersFromContext(pkgContext)
	if err != nil {
		return nil, nil, fmt.Errorf("reading product identifiers from context: %w", err)
	}

	// Now, let's go through grype's matches
	for i := range ignoredMatches {
		var statement *openvex.Statement
		var searchedBy *SearchedBy
		subcmp := subcomponentIdentifiersFromMatch(&ignoredMatches[i].Match)

		// Range through the product's different names to see if they match the
		// statement data
		for _, product := range products {
			if matchingStatements := doc.Matches(ignoredMatches[i].Vulnerability.ID, product, subcmp); len(matchingStatements) != 0 {
				if matchingStatements[0].Status != openvex.StatusAffected &&
					matchingStatements[0].Status != openvex.StatusUnderInvestigation {
					break
				}
				statement = &matchingStatements[0]
				searchedBy = &SearchedBy{
					Vulnerability: ignoredMatches[i].Vulnerability.ID,
					Product:       product,
					Subcomponents: subcmp,
				}
				break
			}
		}

		// No data about this match's component. Next.
		if statement == nil {
			additionalIgnoredMatches = append(additionalIgnoredMatches, ignoredMatches[i])
			continue
		}

		// Only match if rules to augment are configured
		rule := matchingRule(ignoreRules, ignoredMatches[i].Match, statement, augmentStatuses)
		if rule == nil {
			additionalIgnoredMatches = append(additionalIgnoredMatches, ignoredMatches[i])
			continue
		}

		newMatch := ignoredMatches[i].Match
		newMatch.Details = append(newMatch.Details, match.Detail{
			Type:       match.ExactDirectMatch,
			SearchedBy: searchedBy,
			Found: Match{
				Statement: *statement,
			},
			Matcher: match.OpenVexMatcher,
		})

		remainingMatches.Add(newMatch)
	}

	return remainingMatches, additionalIgnoredMatches, nil
}
