package stock

import (
	"github.com/anchore/grype/grype/db/v4/pkg/namers"
	syftPkg "github.com/anchore/syft/syft/pkg"
	"strings"
)

type Namer struct {
}

func (m *Namer) LanguageTypes() []syftPkg.Language {
	return []syftPkg.Language{}
}

func (m *Namer) PackageTypes() []syftPkg.Type {
	return []syftPkg.Type{}
}

func (m *Namer) Type() namers.NamerType {
	return namers.StockNamer
}

func (m *Namer) Normalize(packageName string) (string, error) {
	return strings.ToLower(packageName), nil
}
