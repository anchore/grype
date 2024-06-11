package openvex

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sort"
	"strings"
	"sync/atomic"

	"github.com/openvex/discovery/pkg/discovery"
	"github.com/openvex/discovery/pkg/oci"
	openvex "github.com/openvex/go-vex/pkg/vex"
	"github.com/scylladb/go-set/strset"
	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/go-progress"
	"golang.org/x/sync/errgroup"

	"github.com/anchore/grype/grype/event"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/internal/bus"
	"github.com/anchore/grype/internal/log"
	"github.com/anchore/syft/syft/source"
)

type Processor struct {
	// we always merge all discovered / read vex documents into a single document
	documents *openvex.VEX
}

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
func (ovm *Processor) ReadVexDocuments(docRefs []string) error {
	if len(docRefs) == 0 {
		return nil
	}

	// combine all VEX documents into a single VEX document
	vexdata, err := openvex.MergeFiles(docRefs)
	if err != nil {
		return fmt.Errorf("merging vex documents: %w", err)
	}

	ovm.documents = vexdata

	return nil
}

// productIdentifiersFromContext reads the package context and returns software
// identifiers identifying the scanned image.
func productIdentifiersFromContext(pkgContext pkg.Context) ([]string, error) {
	if pkgContext.Source == nil || pkgContext.Source.Metadata == nil {
		return nil, nil
	}

	var ret []string

	switch v := pkgContext.Source.Metadata.(type) {
	case source.ImageMetadata:
		// call the OpenVEX OCI module to generate the identifiers from the
		// image reference specified by the user.
		refs := []string{v.UserInput}
		refs = append(refs, v.RepoDigests...)

		set := strset.New()
		for _, ref := range refs {
			bundle, err := oci.GenerateReferenceIdentifiers(ref, v.OS, v.Architecture)
			if err != nil {
				log.WithFields("error", err).Trace("unable to generate OCI identifiers from image reference")
				continue
			}
			set.Add(bundle.ToStringSlice()...)
		}

		ret = set.List()

	default:
		// Fail as we only support VEXing container images for now
		return nil, errors.New("source type not supported for VEX")
	}

	sort.Strings(ret)
	return ret, nil
}

// subcomponentIdentifiersFromMatch returns the list of identifiers from the
// package where grype did the match.
func subcomponentIdentifiersFromMatch(m *match.Match) []string {
	if m == nil {
		return nil
	}

	var ret []string
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
	ignoreRules []match.IgnoreRule, pkgContext pkg.Context, matches *match.Matches, ignoredMatches []match.IgnoredMatch,
) (*match.Matches, []match.IgnoredMatch, error) {
	if ovm.documents == nil {
		return matches, ignoredMatches, nil
	}

	doc := ovm.documents

	remainingMatches := match.NewMatches()

	products, err := productIdentifiersFromContext(pkgContext)
	if err != nil {
		return nil, nil, err
	}

	if len(products) == 0 {
		log.Trace("no product identifiers found to use for filtering with vex data")
		return matches, ignoredMatches, nil
	}
	log.WithFields("products", len(products)).Trace("using product identifiers to filter with vex data")

	// TODO(alex): should we apply the vex ignore rules to the already ignored matches?
	// that way the end user sees all of the reasons a match was ignored in case multiple apply

	// Now, let's go through grype's matches
	sorted := matches.Sorted()
	for i := range sorted {
		var statement *openvex.Statement
		mat := sorted[i]

		subcmp := subcomponentIdentifiersFromMatch(&mat)

		// Range through the product's different names
		for _, product := range products {
			if matchingStatements := doc.Matches(mat.Vulnerability.ID, product, subcmp); len(matchingStatements) != 0 {
				statement = &matchingStatements[0]
				break
			}
		}

		// No data about this match's component. Next.
		if statement == nil {
			remainingMatches.Add(mat)
			continue
		}

		rule := matchingRule(ignoreRules, mat, statement, ignoreStatuses)
		if rule == nil {
			remainingMatches.Add(mat)
			continue
		}

		// Filtering only applies to not_affected and fixed statuses
		if statement.Status != openvex.StatusNotAffected && statement.Status != openvex.StatusFixed {
			remainingMatches.Add(mat)
			continue
		}

		log.WithFields("vulnerability", mat.Vulnerability.ID, "package", mat.Package.String(), "vex-status", statement.Status).Debug("filtered out match")

		ignoredMatches = append(ignoredMatches, match.IgnoredMatch{
			Match:              mat,
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
	ignoreRules []match.IgnoreRule, pkgContext pkg.Context, remainingMatches *match.Matches, ignoredMatches []match.IgnoredMatch,
) (*match.Matches, []match.IgnoredMatch, error) {
	if ovm.documents == nil {
		return remainingMatches, ignoredMatches, nil
	}

	doc := ovm.documents

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

// DiscoverVexDocuments uses the OpenVEX discovery module to look for vex data
// associated to the scanned object. If any data is found, the data will be
// added to the existing vex data
func (ovm *Processor) DiscoverVexDocuments(ctx context.Context, pkgContext pkg.Context) error {
	// Extract the identifiers from the package context
	identifiers, err := productIdentifiersFromContext(pkgContext)
	if err != nil {
		return fmt.Errorf("extracting identifiers from context")
	}

	searchTargets := searchableIdentifiers(identifiers)
	log.WithFields("identifiers", len(identifiers), "usable", searchTargets).Debug("searching remotely for vex documents")

	discoveredDocs, err := findVexDocuments(ctx, searchTargets)
	if err != nil {
		return err
	}

	var allDocs []*openvex.VEX
	for _, doc := range discoveredDocs {
		allDocs = append(allDocs, doc)
	}

	if len(allDocs) == 0 {
		return nil
	}

	vexdata, err := openvex.MergeDocuments(allDocs)
	if err != nil {
		return fmt.Errorf("unable to merge discovered vex documents: %w", err)
	}

	if ovm.documents != nil {
		vexdata, err := openvex.MergeDocuments([]*openvex.VEX{ovm.documents, vexdata})
		if err != nil {
			return fmt.Errorf("unable to merge existing vex documents with discovered documents: %w", err)
		}
		ovm.documents = vexdata
	} else {
		ovm.documents = vexdata
	}

	return nil
}

func findVexDocuments(ctx context.Context, identifiers []string) (map[string]*openvex.VEX, error) {
	allDiscoveredDocs := make(chan *openvex.VEX)

	prog, stage := trackVexDiscovery(identifiers)
	defer prog.SetCompleted()

	agent := discovery.NewAgent()

	grp, ctx := errgroup.WithContext(ctx)

	identifierQueue := produceSearchableIdentifiers(ctx, grp, identifiers)

	workers := int32(maxParallelism())
	for workerNum := int32(0); workerNum < workers; workerNum++ {
		grp.Go(func() error {
			defer func() {
				if atomic.AddInt32(&workers, -1) == 0 {
					close(allDiscoveredDocs)
				}
			}()

			for i := range identifierQueue {
				stage.Set(fmt.Sprintf("searching %s", i))
				log.WithFields("identifier", i).Trace("searching remotely for vex documents")

				discoveredDocs, err := agent.ProbePurl(i)
				if err != nil {
					prog.SetError(err)
					return fmt.Errorf("probing package url or vex data: %w", err)
				}

				prog.Add(1)

				if len(discoveredDocs) > 0 {
					log.WithFields("documents", len(discoveredDocs), "identifier", i).Debug("discovered vex documents")
				}

				for _, doc := range discoveredDocs {
					select {
					case <-ctx.Done():
						return ctx.Err()
					case allDiscoveredDocs <- doc:
					}
				}
			}
			return nil
		})
	}

	return reduceVexDocuments(grp, stage, allDiscoveredDocs)
}

func reduceVexDocuments(grp *errgroup.Group, stage *progress.AtomicStage, allDiscoveredDocs <-chan *openvex.VEX) (map[string]*openvex.VEX, error) {
	finalDiscoveredDocs := make(map[string]*openvex.VEX)
	grp.Go(func() error {
		for doc := range allDiscoveredDocs {
			if _, ok := finalDiscoveredDocs[doc.ID]; ok {
				continue
			}
			finalDiscoveredDocs[doc.ID] = doc
		}
		return nil
	})

	if err := grp.Wait(); err != nil {
		return nil, fmt.Errorf("searching remotely for vex documents: %w", err)
	}

	if len(finalDiscoveredDocs) > 0 {
		log.WithFields("documents", len(finalDiscoveredDocs)).Debug("total vex documents discovered remotely")
	} else {
		log.Debug("no vex documents discovered remotely")
	}

	stage.Set(fmt.Sprintf("%d documents discovered", len(finalDiscoveredDocs)))

	return finalDiscoveredDocs, nil
}

func maxParallelism() int {
	// from docs: "If n < 1, it does not change the current setting."
	maxProcs := runtime.GOMAXPROCS(0)
	numCPU := runtime.NumCPU()
	if maxProcs < numCPU {
		return maxProcs
	}
	return numCPU
}

func produceSearchableIdentifiers(ctx context.Context, g *errgroup.Group, identifiers []string) chan string {
	ids := make(chan string)

	g.Go(func() error {
		defer close(ids)
		for _, i := range identifiers {
			i := i

			if !strings.HasPrefix(i, "pkg:") {
				continue
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case ids <- i:
			}
		}

		return nil
	})
	return ids
}

func searchableIdentifiers(identifiers []string) []string {
	var ids []string
	for _, i := range identifiers {
		if !strings.HasPrefix(i, "pkg:") {
			continue
		}
		ids = append(ids, i)
	}
	return ids
}

func trackVexDiscovery(identifiers []string) (*progress.Manual, *progress.AtomicStage) {
	stage := progress.NewAtomicStage("")
	prog := progress.NewManual(int64(len(identifiers)))

	bus.Publish(partybus.Event{
		Type:   event.VexDocumentDiscoveryStarted,
		Source: identifiers,
		Value: progress.StagedProgressable(struct {
			progress.Stager
			progress.Progressable
		}{
			Stager:       stage,
			Progressable: prog,
		}),
		Error: nil,
	})

	return prog, stage
}
