package matcher

import (
	"github.com/anchore/grype/grype/event"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher/apk"
	"github.com/anchore/grype/grype/matcher/dpkg"
	"github.com/anchore/grype/grype/matcher/java"
	"github.com/anchore/grype/grype/matcher/javascript"
	"github.com/anchore/grype/grype/matcher/python"
	"github.com/anchore/grype/grype/matcher/rpmdb"
	"github.com/anchore/grype/grype/matcher/ruby"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/bus"
	"github.com/anchore/grype/internal/log"
	"github.com/anchore/syft/syft/distro"
	syftPkg "github.com/anchore/syft/syft/pkg"
	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/go-progress"
)

var controllerInstance controller

type Monitor struct {
	PackagesProcessed         progress.Monitorable
	VulnerabilitiesDiscovered progress.Monitorable
}

func init() {
	controllerInstance = newController()
}

type controller struct {
	matchers map[syftPkg.Type][]Matcher
}

func newController() controller {
	ctrlr := controller{
		matchers: make(map[syftPkg.Type][]Matcher),
	}
	ctrlr.add(&dpkg.Matcher{})
	ctrlr.add(&ruby.Matcher{})
	ctrlr.add(&python.Matcher{})
	ctrlr.add(&rpmdb.Matcher{})
	ctrlr.add(&java.Matcher{})
	ctrlr.add(&javascript.Matcher{})
	ctrlr.add(&apk.Matcher{})
	return ctrlr
}

func (c *controller) add(matchers ...Matcher) {
	for _, m := range matchers {
		for _, t := range m.PackageTypes() {
			if _, ok := c.matchers[t]; ok {
				c.matchers[t] = make([]Matcher, 0)
			}

			c.matchers[t] = append(c.matchers[t], m)
			log.Debugf("adding matcher: %+v", t)
		}
	}
}

func (c *controller) trackMatcher() (*progress.Manual, *progress.Manual) {
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

func (c *controller) findMatches(provider vulnerability.Provider, d *distro.Distro, packages ...pkg.Package) match.Matches {
	res := match.NewMatches()

	packagesProcessed, vulnerabilitiesDiscovered := c.trackMatcher()

	for _, p := range packages {
		packagesProcessed.N++
		log.Debugf("searching for vulnerability matches for pkg=%s", p)

		matchers, ok := c.matchers[p.Type]
		if !ok {
			log.Warnf("no matchers available for package pkg=%s", p)
		}
		for _, m := range matchers {
			matches, err := m.Match(provider, d, p)
			if err != nil {
				log.Errorf("matcher failed for pkg=%s: %+v", p, err)
			} else {
				logMatches(p, matches)
				res.Add(p, matches...)
				vulnerabilitiesDiscovered.N += int64(len(matches))
			}
		}
	}

	packagesProcessed.SetCompleted()
	vulnerabilitiesDiscovered.SetCompleted()

	return res
}

func FindMatches(provider vulnerability.Provider, d *distro.Distro, packages ...pkg.Package) match.Matches {
	return controllerInstance.findMatches(provider, d, packages...)
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
