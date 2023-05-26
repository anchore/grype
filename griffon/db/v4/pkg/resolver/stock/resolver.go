package stock

import (
	"strings"

	griffonPkg "github.com/nextlinux/griffon/griffon/pkg"
)

type Resolver struct {
}

func (r *Resolver) Normalize(name string) string {
	return strings.ToLower(name)
}

func (r *Resolver) Resolve(p griffonPkg.Package) []string {
	return []string{r.Normalize(p.Name)}
}
