package namers

import (
	syftPkg "github.com/anchore/syft/syft/pkg"
)

type Namer interface {
	LanguageTypes() []syftPkg.Language
	PackageTypes() []syftPkg.Type
	Type() NamerType
	Normalize(string) (string, error)
}
