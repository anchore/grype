package matcher

import (
	"github.com/anchore/imgbom/imgbom/distro"
	"github.com/anchore/imgbom/imgbom/pkg"
	"github.com/anchore/vulnscan/internal/log"
	"github.com/anchore/vulnscan/vulnscan/match"
	"github.com/anchore/vulnscan/vulnscan/matcher/bundler"
	"github.com/anchore/vulnscan/vulnscan/matcher/dpkg"
	"github.com/anchore/vulnscan/vulnscan/matcher/java"
	"github.com/anchore/vulnscan/vulnscan/matcher/python"
	"github.com/anchore/vulnscan/vulnscan/matcher/rpmdb"
	"github.com/anchore/vulnscan/vulnscan/result"
	"github.com/anchore/vulnscan/vulnscan/vulnerability"
)

var controllerInstance controller

func init() {
	controllerInstance = newController()
}

type controller struct {
	matchers map[pkg.Type][]Matcher
}

func newController() controller {
	ctrlr := controller{
		matchers: make(map[pkg.Type][]Matcher),
	}
	ctrlr.add(&dpkg.Matcher{})
	ctrlr.add(&bundler.Matcher{})
	ctrlr.add(&python.Matcher{})
	ctrlr.add(&rpmdb.Matcher{})
	ctrlr.add(&java.Matcher{})
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

func (c *controller) findMatches(provider vulnerability.Provider, d distro.Distro, packages ...*pkg.Package) result.Result {
	res := result.NewResult()
	for _, p := range packages {
		log.Debugf("searching for vulnerability matches for pkg=%s", p)

		matchers, ok := c.matchers[p.Type]
		if !ok {
			log.Errorf("no matchers available for package pkg=%s", p)
		}
		for _, m := range matchers {
			matches, err := m.Match(provider, d, p)
			if err != nil {
				log.Errorf("matcher failed for pkg=%s: %+v", p, err)
			} else {
				logMatches(p, matches)
				res.Add(p, matches...)
			}
		}
	}
	return res
}

func FindMatches(provider vulnerability.Provider, d distro.Distro, packages ...*pkg.Package) result.Result {
	return controllerInstance.findMatches(provider, d, packages...)
}

func logMatches(p *pkg.Package, matches []match.Match) {
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
