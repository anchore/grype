package python

import (
	"regexp"
	"strings"

	grypePkg "github.com/anchore/grype/grype/pkg"
)

type Resolver struct {
}

func (r *Resolver) Normalize(name string) string {
	// Canonical naming of packages within python is defined by PEP 503 at
	// https://peps.python.org/pep-0503/#normalized-names, and this code is derived from
	// the official python implementation of canonical naming at
	// https://packaging.pypa.io/en/latest/_modules/packaging/utils.html#canonicalize_name

	return strings.ToLower(regexp.MustCompile(`[-_.]+`).ReplaceAllString(name, "-"))
}

func (r *Resolver) Resolve(p grypePkg.Package) []string {
	// Canonical naming of packages within python is defined by PEP 503 at
	// https://peps.python.org/pep-0503/#normalized-names, and this code is derived from
	// the official python implementation of canonical naming at
	// https://packaging.pypa.io/en/latest/_modules/packaging/utils.html#canonicalize_name

	return []string{r.Normalize(p.Name)}
}
