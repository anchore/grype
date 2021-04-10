package grype

import (
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
)

type Analysis struct {
	Matches          match.Matches
	Packages         []pkg.Package
	Context          pkg.Context
	MetadataProvider vulnerability.MetadataProvider
	AppConfig        interface{}
}
