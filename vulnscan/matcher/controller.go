package matcher

import (
	"github.com/anchore/imgbom/imgbom/distro"
	"github.com/anchore/imgbom/imgbom/pkg"
	"github.com/anchore/vulnscan/internal/log"
	"github.com/anchore/vulnscan/vulnscan/matcher/dpkg"
	"github.com/anchore/vulnscan/vulnscan/result"
	"github.com/anchore/vulnscan/vulnscan/vulnerability"
)

var controllerInstance controller

func init() {
	controllerInstance = controller{
		matchers: make(map[pkg.Type][]Matcher),
	}
	controllerInstance.add(&dpkg.Matcher{})
}

type controller struct {
	matchers map[pkg.Type][]Matcher
}

func (c *controller) add(matchers ...Matcher) {
	for _, m := range matchers {
		for _, t := range m.Types() {
			if _, ok := c.matchers[t]; ok {
				c.matchers[t] = make([]Matcher, 0)
			}

			c.matchers[t] = append(c.matchers[t], m)
			log.Debugf("adding matcher: %+v", t)
		}
	}
}

func (c *controller) findMatches(s vulnerability.Provider, o distro.Distro, packages ...*pkg.Package) result.Result {
	res := result.NewResult()
	for _, p := range packages {
		matchers, ok := c.matchers[p.Type]
		if !ok {
			log.Errorf("no matchers available for package type=%s pkg=%s", p.Type, p)
		}
		for _, m := range matchers {
			matches, err := m.Match(s, o, p)
			if err != nil {
				log.Errorf("matcher failed for pkg=%s: %+v", p, err)
			} else {
				res.Add(p, matches...)
			}
		}
	}
	return res
}

func FindMatches(s vulnerability.Provider, o distro.Distro, packages ...*pkg.Package) result.Result {
	return controllerInstance.findMatches(s, o, packages...)
}
