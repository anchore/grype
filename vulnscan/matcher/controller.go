package matcher

import (
	"github.com/anchore/imgbom/imgbom/pkg"
	"github.com/anchore/vulnscan/internal/log"
	"github.com/anchore/vulnscan/vulnscan/match"
	"github.com/anchore/vulnscan/vulnscan/matcher/dummy"
	"github.com/anchore/vulnscan/vulnscan/result"
)

var controllerInstance controller

func init() {
	controllerInstance = controller{
		matchers: make(map[pkg.Type][]Matcher),
	}
	controllerInstance.add(&dummy.Matcher{})
}

type controller struct {
	matchers map[pkg.Type][]Matcher
}

func (c *controller) add(matchers ...Matcher) {
	for _, m := range matchers {
		if _, ok := c.matchers[m.Type()]; ok {
			c.matchers[m.Type()] = make([]Matcher, 0)
		}

		c.matchers[m.Type()] = append(c.matchers[m.Type()], m)
		log.Debugf("adding matcher: %+v", m.Type())
	}
}

// TODO: do we need to pass the entire store? or just a reader interface subset?
func (c *controller) findMatches(s match.Store, packages ...pkg.Package) result.Result {
	res := result.NewResult()
	for _, p := range packages {
		for _, matchers := range c.matchers {
			for _, m := range matchers {
				res.Add(p, m.Match(s, p)...)
			}
		}
	}
	return res
}

func FindMatches(s match.Store, packages ...pkg.Package) result.Result {
	return controllerInstance.findMatches(s, packages...)
}
