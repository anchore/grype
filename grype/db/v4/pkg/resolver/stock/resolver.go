package stock

import (
	grypePkg "github.com/anchore/grype/grype/pkg"
	"strings"
)

type Resolver struct {
}

func (r *Resolver) Normalize(name string) string {
	return strings.ToLower(name)
}

func (r *Resolver) Resolve(p grypePkg.Package) []string {
	return []string{r.Normalize(p.Name)}
}
