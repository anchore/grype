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
	vexStatus "github.com/anchore/grype/grype/vex/status"
	"github.com/anchore/grype/grype/vulnerability"
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

// SearchedBy captures the parameters used to search through the VEX data
type SearchedBy struct {
	Vulnerability string
	Product       string
	Subcomponents []string
}

// IsOpenVex checks if the provided document is a VEX document
func IsOpenVex(document string) bool {
	if _, err := openvex.Load(document); err == nil {
		return true
	}
	return false
}

// ReadVexDocuments reads and merges VEX documents
func (ovm *Processor) ReadVexDocuments(docs []string) (any, error) {
	// Combine all VEX documents into a single VEX document
	vexdata, err := openvex.MergeFiles(docs)
	if err != nil {
		return nil, fmt.Errorf("merging vex documents: %w", err)
	}

	return vexdata, nil
}

// productIdentifiersFromContext reads the package context and returns software
// identifiers identifying the scanned image.
func productIdentifiersFromContext(pkgContext *pkg.Context) []string {
	switch v := pkgContext.Source.Metadata.(type) {
	case source.ImageMetadata:
		tagIdentifiers := identifiersFromTags(v.Tags, pkgContext.Source.Name)
		digestIdentifiers := identifiersFromDigests(v.RepoDigests)
		identifiers := slices.Concat(tagIdentifiers, digestIdentifiers)
		return identifiers
	default:
		if pkgContext.Source.Name != "" && pkgContext.Source.Version != "" {
			return []string{"pkg:generic/" + strings.ToLower(pkgContext.Source.Name) + "@" + pkgContext.Source.Version}
		}
		// return an empty list so matching can be attempted using the
		// package's own identifiers as the product
		return []string{}
	}
}

func normalizeDockerHubRepositoryURL(repoURL string) string {
	repoURL = strings.TrimSpace(repoURL)
	if repoURL == "" {
		return repoURL
	}

	repoURL = strings.TrimPrefix(repoURL, "https://")
	repoURL = strings.TrimPrefix(repoURL, "http://")

	repoURL = strings.TrimSuffix(repoURL, "/")

	host, rest, hasSlash := strings.Cut(repoURL, "/")

	switch strings.ToLower(host) {
	case "docker.io", "index.docker.io", "registry-1.docker.io":
		host = "index.docker.io"
	}

	if !hasSlash || rest == "" {
		return host
	}
	return host + "/" + rest
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

		repoURL = normalizeDockerHubRepositoryURL(repoURL)

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

// findMatchingStatement searches a VEX document for a statement matching the
// given vulnerability. It performs a two-pass search:
//  1. Try SBOM/context product identifiers (handles image-as-product cases)
//  2. Try the match's own package identifiers as the product (handles
//     package-as-product cases, where the VEX product is a package PURL)
func findMatchingStatement(doc *openvex.VEX, vulnID string, products []string, subcmp []string) (stmt *openvex.Statement, product string, subcomponents []string) {
	for _, product := range products {
		if stmts := doc.Matches(vulnID, product, subcmp); len(stmts) != 0 {
			return &stmts[0], product, subcmp
		}
	}

	for _, pkgID := range subcmp {
		if stmts := doc.Matches(vulnID, pkgID, nil); len(stmts) != 0 {
			return &stmts[0], pkgID, nil
		}
	}

	return nil, "", nil
}

// FilterMatches takes a set of scanning results and moves any results marked in
// the VEX data as fixed or not_affected to the ignored list.
func (ovm *Processor) FilterMatches(
	docRaw any, ignoreRules []match.IgnoreRule, pkgContext *pkg.Context, matches *match.Matches, ignoredMatches []match.IgnoredMatch,
) (*match.Matches, []match.IgnoredMatch, error) {
	doc, ok := docRaw.(*openvex.VEX)
	if !ok {
		return nil, nil, errors.New("unable to cast vex document as openvex")
	}

	remainingMatches := match.NewMatches()

	products := productIdentifiersFromContext(pkgContext)

	// TODO(alex): should we apply the vex ignore rules to the already ignored matches?
	// that way the end user sees all of the reasons a match was ignored in case multiple apply

	// Now, let's go through grype's matches
	sorted := matches.Sorted()
	for i := range sorted {
		subcmp := subcomponentIdentifiersFromMatch(&sorted[i])
		statement, _, _ := findMatchingStatement(doc, sorted[i].Vulnerability.ID, products, subcmp)

		// No data about this match's component. Next.
		if statement == nil {
			remainingMatches.Add(sorted[i])
			continue
		}

		rule := matchingRule(ignoreRules, sorted[i], statement, vexStatus.IgnoreList())
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
func matchingRule(ignoreRules []match.IgnoreRule, m match.Match, statement *openvex.Statement, allowedStatuses []vexStatus.Status) *match.IgnoreRule {
	ms := match.NewMatches()
	ms.Add(m)

	// By default, if there are no ignore rules (which means the user didn't provide
	// any custom VEX rule), a matching rule should be returned if the statement
	// status is one of the allowed statuses.
	if len(ignoreRules) == 0 && slices.Contains(allowedStatuses, vexStatus.Status(statement.Status)) {
		return &match.IgnoreRule{
			Namespace:        "vex",
			Vulnerability:    statement.Vulnerability.ID,
			VexJustification: string(statement.Justification),
			VexStatus:        string(statement.Status),
		}
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
		if rule.VexStatus != "" && !slices.Contains(allowedStatuses, vexStatus.Status(rule.VexStatus)) {
			continue
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
// are moved from the ignore list back to active matches, or synthesized from
// the package catalog when the vulnerability database has no record of the
// affected (vulnerability, package) pair.
func (ovm *Processor) AugmentMatches(
	docRaw any, ignoreRules []match.IgnoreRule, pkgContext *pkg.Context, pkgs []pkg.Package, remainingMatches *match.Matches, ignoredMatches []match.IgnoredMatch,
) (*match.Matches, []match.IgnoredMatch, error) {
	doc, ok := docRaw.(*openvex.VEX)
	if !ok {
		return nil, nil, errors.New("unable to cast vex document as openvex")
	}

	additionalIgnoredMatches := []match.IgnoredMatch{}

	products := productIdentifiersFromContext(pkgContext)

	// Now, let's go through grype's matches
	for i := range ignoredMatches {
		subcmp := subcomponentIdentifiersFromMatch(&ignoredMatches[i].Match)

		statement, matchedProduct, matchedSubcmp := findMatchingStatement(doc, ignoredMatches[i].Vulnerability.ID, products, subcmp)

		// Only augment for affected or under_investigation statuses
		if statement == nil || (statement.Status != openvex.StatusAffected && statement.Status != openvex.StatusUnderInvestigation) {
			additionalIgnoredMatches = append(additionalIgnoredMatches, ignoredMatches[i])
			continue
		}

		// Only match if rules to augment are configured
		rule := matchingRule(ignoreRules, ignoredMatches[i].Match, statement, vexStatus.AugmentList())
		if rule == nil {
			additionalIgnoredMatches = append(additionalIgnoredMatches, ignoredMatches[i])
			continue
		}

		newMatch := ignoredMatches[i].Match
		newMatch.Details = append(newMatch.Details, match.Detail{
			Type: match.ExactDirectMatch,
			SearchedBy: &SearchedBy{
				Vulnerability: ignoredMatches[i].Vulnerability.ID,
				Product:       matchedProduct,
				Subcomponents: matchedSubcmp,
			},
			Found: Match{
				Statement: *statement,
			},
			Matcher: match.OpenVexMatcher,
		})

		remainingMatches.Add(newMatch)
	}

	synthesizeFromCatalog(doc, ignoreRules, products, pkgs, remainingMatches, additionalIgnoredMatches)

	return remainingMatches, additionalIgnoredMatches, nil
}

// synthesizeFromCatalog walks the package catalog and, for each VEX statement
// that names a package as affected or under_investigation but has no corresponding
// match in either the remaining or ignored match sets, creates a new match.Match.
// This covers vulnerabilities that are present in the VEX document but absent from
// grype's vulnerability database for the given package.
func synthesizeFromCatalog(
	doc *openvex.VEX,
	ignoreRules []match.IgnoreRule,
	products []string,
	pkgs []pkg.Package,
	remainingMatches *match.Matches,
	ignoredMatches []match.IgnoredMatch,
) {
	if len(pkgs) == 0 || len(doc.Statements) == 0 {
		return
	}

	known := existingVulnPackageKeys(remainingMatches, ignoredMatches)
	index := buildPackageIndex(pkgs)

	for stmtIdx := range doc.Statements {
		stmt := &doc.Statements[stmtIdx]
		if stmt.Status != openvex.StatusAffected && stmt.Status != openvex.StatusUnderInvestigation {
			continue
		}

		vulnID := string(stmt.Vulnerability.Name)
		if vulnID == "" {
			continue
		}

		for _, pi := range candidatePackages(stmt, products, pkgs, index) {
			p := &pkgs[pi]
			if p.PURL == "" {
				continue
			}
			if _, seen := known[vulnPackageKey(vulnID, p.PURL)]; seen {
				continue
			}

			matchedProduct, matchedSubcmp := matchPackageAgainstStatement(stmt, products, p.PURL)
			if matchedProduct == "" {
				continue
			}

			synthesized := buildSynthesizedMatch(*p, vulnID, stmt, matchedProduct, matchedSubcmp)
			if rule := matchingRule(ignoreRules, synthesized, stmt, vexStatus.AugmentList()); rule == nil {
				continue
			}

			remainingMatches.Add(synthesized)
			known[vulnPackageKey(vulnID, p.PURL)] = struct{}{}
		}
	}
}

// buildPackageIndex parses every package purl once and buckets the package
// indices by their (type, namespace, name) identity. A statement can only
// synthesize a match for a package whose purl shares this identity (see
// PurlMatches), so the index lets each statement consider just the relevant
// packages rather than the whole catalog.
func buildPackageIndex(pkgs []pkg.Package) map[string][]int {
	index := make(map[string][]int)
	for i := range pkgs {
		if pkgs[i].PURL == "" {
			continue
		}
		parsed, err := packageurl.FromString(pkgs[i].PURL)
		if err != nil {
			continue
		}
		key := purlIdentityKey(parsed)
		index[key] = append(index[key], i)
	}
	return index
}

func purlIdentityKey(p packageurl.PackageURL) string {
	return p.Type + "\x00" + p.Namespace + "\x00" + p.Name
}

// candidatePackages returns the indices of packages that could match the given
// statement. For statements that name packages by purl (as a product or as a
// subcomponent) only packages sharing a purl identity with one of those purls
// are returned. Image-wide statements (an image/context product with no
// subcomponents) apply to every package, matching the behavior of
// matchPackageAgainstStatement, so the whole catalog is returned in that case.
func candidatePackages(stmt *openvex.Statement, products []string, pkgs []pkg.Package, index map[string][]int) []int {
	if statementIsImageWide(stmt, products) {
		all := make([]int, len(pkgs))
		for i := range pkgs {
			all[i] = i
		}
		return all
	}

	var out []int
	seen := map[int]struct{}{}
	for _, sp := range statementPurls(stmt) {
		parsed, err := packageurl.FromString(sp)
		if err != nil {
			continue
		}
		for _, pi := range index[purlIdentityKey(parsed)] {
			if _, ok := seen[pi]; ok {
				continue
			}
			seen[pi] = struct{}{}
			out = append(out, pi)
		}
	}
	return out
}

// statementPurls collects every purl referenced by a statement, both as a
// product component and as a subcomponent.
func statementPurls(stmt *openvex.Statement) []string {
	var out []string
	add := func(s string) {
		if strings.HasPrefix(s, "pkg:") {
			out = append(out, s)
		}
	}
	addComponent := func(c openvex.Component) {
		add(c.ID)
		for t, id := range c.Identifiers {
			if t == openvex.PURL {
				add(id)
			}
		}
	}
	for i := range stmt.Products {
		addComponent(stmt.Products[i].Component)
		for j := range stmt.Products[i].Subcomponents {
			addComponent(stmt.Products[i].Subcomponents[j].Component)
		}
	}
	return out
}

// statementIsImageWide reports whether the statement names an image/context
// product with no subcomponents, in which case matchPackageAgainstStatement
// matches every package in the catalog.
func statementIsImageWide(stmt *openvex.Statement, products []string) bool {
	for i := range stmt.Products {
		if len(stmt.Products[i].Subcomponents) != 0 {
			continue
		}
		for _, prod := range products {
			if stmt.Products[i].Component.Matches(prod) {
				return true
			}
		}
	}
	return false
}

func existingVulnPackageKeys(remainingMatches *match.Matches, ignoredMatches []match.IgnoredMatch) map[string]struct{} {
	known := map[string]struct{}{}
	for m := range remainingMatches.Enumerate() {
		known[vulnPackageKey(m.Vulnerability.ID, m.Package.PURL)] = struct{}{}
	}
	for _, m := range ignoredMatches {
		known[vulnPackageKey(m.Vulnerability.ID, m.Package.PURL)] = struct{}{}
	}
	return known
}

func vulnPackageKey(vulnID, purl string) string {
	return vulnID + "\x00" + purl
}

// matchPackageAgainstStatement returns the matched product identifier and the
// subcomponents that satisfied the match, or empty strings/nil when the
// statement does not name the given package.
func matchPackageAgainstStatement(stmt *openvex.Statement, products []string, pkgPURL string) (string, []string) {
	// Image/context as product, package as subcomponent.
	for _, product := range products {
		if stmt.MatchesProduct(product, pkgPURL) {
			return product, []string{pkgPURL}
		}
	}
	// Package itself as product.
	if stmt.MatchesProduct(pkgPURL, "") {
		return pkgPURL, nil
	}
	return "", nil
}

func buildSynthesizedMatch(p pkg.Package, vulnID string, stmt *openvex.Statement, matchedProduct string, matchedSubcmp []string) match.Match {
	return match.Match{
		Vulnerability: vulnerability.Vulnerability{
			Reference: vulnerability.Reference{
				ID:        vulnID,
				Namespace: "vex",
			},
		},
		Package: p,
		Details: []match.Detail{
			{
				Type: match.ExactDirectMatch,
				SearchedBy: &SearchedBy{
					Vulnerability: vulnID,
					Product:       matchedProduct,
					Subcomponents: matchedSubcmp,
				},
				Found: Match{
					Statement: *stmt,
				},
				Matcher:    match.OpenVexMatcher,
				Confidence: 1,
			},
		},
	}
}
