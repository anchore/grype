package matcher

import (
	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/go-progress"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/event"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher/apk"
	"github.com/anchore/grype/grype/matcher/dotnet"
	"github.com/anchore/grype/grype/matcher/dpkg"
	"github.com/anchore/grype/grype/matcher/golang"
	"github.com/anchore/grype/grype/matcher/java"
	"github.com/anchore/grype/grype/matcher/javascript"
	"github.com/anchore/grype/grype/matcher/msrc"
	"github.com/anchore/grype/grype/matcher/python"
	"github.com/anchore/grype/grype/matcher/rpmdb"
	"github.com/anchore/grype/grype/matcher/ruby"
	"github.com/anchore/grype/grype/matcher/stock"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/bus"
	"github.com/anchore/grype/internal/log"
	"github.com/anchore/syft/syft/linux"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

type Monitor struct {
	PackagesProcessed         progress.Monitorable
	VulnerabilitiesDiscovered progress.Monitorable
}

// Config contains values used by individual matcher structs for advanced configuration
type Config struct {
	Java java.MatcherConfig
}

func NewDefaultMatchers(mc Config) []Matcher {
	return []Matcher{
		&dpkg.Matcher{},
		&ruby.Matcher{},
		&python.Matcher{},
		&dotnet.Matcher{},
		&rpmdb.Matcher{},
		java.NewJavaMatcher(mc.Java),
		&javascript.Matcher{},
		&apk.Matcher{},
		&golang.Matcher{},
		&msrc.Matcher{},
	}
}

func trackMatcher() (*progress.Manual, *progress.Manual) {
	packagesProcessed := progress.Manual{}
	vulnerabilitiesDiscovered := progress.Manual{}

	bus.Publish(partybus.Event{
		Type: event.VulnerabilityScanningStarted,
		Value: Monitor{
			PackagesProcessed:         progress.Monitorable(&packagesProcessed),
			VulnerabilitiesDiscovered: progress.Monitorable(&vulnerabilitiesDiscovered),
		},
	})
	return &packagesProcessed, &vulnerabilitiesDiscovered
}

func newMatcherIndex(matchers []Matcher) map[syftPkg.Type][]Matcher {
	matcherIndex := make(map[syftPkg.Type][]Matcher)
	for _, m := range matchers {
		for _, t := range m.PackageTypes() {
			if _, ok := matcherIndex[t]; !ok {
				matcherIndex[t] = make([]Matcher, 0)
			}

			matcherIndex[t] = append(matcherIndex[t], m)
			log.Debugf("adding matcher: %+v", t)
		}
	}

	return matcherIndex
}

func FindMatches(store interface {
	vulnerability.Provider
	match.ExclusionProvider
}, release *linux.Release, matchers []Matcher, packages []pkg.Package) match.Matches {
	var err error
	res := match.NewMatches()
	matcherIndex := newMatcherIndex(matchers)

	var d *distro.Distro
	if release != nil {
		d, err = distro.NewFromRelease(*release)
		if err != nil {
			log.Warnf("unable to determine linux distribution: %+v", err)
		}
	}

	packagesProcessed, vulnerabilitiesDiscovered := trackMatcher()

	defaultMatcher := &stock.Matcher{}
	for _, p := range packages {
		packagesProcessed.N++
		log.Debugf("searching for vulnerability matches for pkg=%s", p)

		matchers, ok := matcherIndex[p.Type]
		if !ok {
			matchers = []Matcher{defaultMatcher}
		}
		for _, m := range matchers {
			matches, err := m.Match(store, d, p)
			if err != nil {
				log.Warnf("matcher failed for pkg=%s: %+v", p, err)
			} else {
				logMatches(p, matches)
				res.Add(matches...)
				vulnerabilitiesDiscovered.N += int64(len(matches))
			}
		}
	}

	packagesProcessed.SetCompleted()
	vulnerabilitiesDiscovered.SetCompleted()

	// Filter out matches based off of the records in the exclusion table in the database or from the old hard-coded rules
	res = match.ApplyExplicitIgnoreRules(store, res)

	return res
}

func logMatches(p pkg.Package, matches []match.Match) {
	if len(matches) > 0 {
		log.Debugf("found %d vulnerabilities for pkg=%s", len(matches), p)
		for idx, m := range matches {
			var branch = "├──"
			if idx == len(matches)-1 {
				branch = "└──"
			}
			log.Debugf("  %s %s", branch, m.Summary())
		}
	}
}
