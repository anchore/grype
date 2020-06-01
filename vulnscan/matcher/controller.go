package matcher

import (
	"github.com/anchore/imgbom/imgbom/distro"
	"github.com/anchore/imgbom/imgbom/pkg"
	"github.com/anchore/vulnscan/internal/log"
	_distro "github.com/anchore/vulnscan/vulnscan/matcher/distro"
	"github.com/anchore/vulnscan/vulnscan/result"
	"github.com/anchore/vulnscan/vulnscan/vulnerability"
)

var controllerInstance controller

func init() {
	controllerInstance = controller{
		matchers: make(map[pkg.Type][]Matcher),
	}
	controllerInstance.add(&_distro.Matcher{})
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
		for _, matchers := range c.matchers {
			for _, m := range matchers {
				matches, err := m.Match(s, o, p)
				if err != nil {
					log.Errorf("matcher failed for pkg=%s: %w", p, err)
				} else {
					res.Add(p, matches...)
				}
			}
		}
	}
	return res
}

func FindMatches(s vulnerability.Provider, o distro.Distro, packages ...*pkg.Package) result.Result {
	return controllerInstance.findMatches(s, o, packages...)
}
