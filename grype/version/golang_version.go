package version

import (
	hashiVer "github.com/anchore/go-version"
	"strings"
)

type golangVersion struct {
	verObj           *hashiVer.Version
	incompatibleFlag bool
}

func newGolangVersion(v string) (*golangVersion, error) {
	if strings.HasSuffix(v, "+incompatible") {

	}
	return &golangVersion{}, nil
}
