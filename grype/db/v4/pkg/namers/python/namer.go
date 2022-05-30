package python

import (
	"github.com/anchore/grype/grype/db/v4/pkg/namers"
	syftPkg "github.com/anchore/syft/syft/pkg"
	"regexp"
	"strings"
)

type Namer struct {
}

func (m *Namer) LanguageTypes() []syftPkg.Language {
	return []syftPkg.Language{syftPkg.Python}
}

func (m *Namer) PackageTypes() []syftPkg.Type {
	return []syftPkg.Type{syftPkg.PythonPkg}
}

func (m *Namer) Type() namers.NamerType {
	return namers.PythonNamer
}

func (m *Namer) Normalize(packageName string) (string, error) {
	// Canonical naming of packages within python is defined by PEP 503 at
	// https://peps.python.org/pep-0503/#normalized-names, and this code is derived from
	// the official python implementation of canonical naming at
	// https://packaging.pypa.io/en/latest/_modules/packaging/utils.html#canonicalize_name

	return strings.ToLower(regexp.MustCompile(`[-_.]+`).ReplaceAllString(packageName, "-")), nil
}
