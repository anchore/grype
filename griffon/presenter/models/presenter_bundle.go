package models

import (
	"github.com/anchore/syft/syft/sbom"
	"github.com/nextlinux/griffon/griffon/match"
	"github.com/nextlinux/griffon/griffon/pkg"
	"github.com/nextlinux/griffon/griffon/vulnerability"
)

type PresenterConfig struct {
	Matches          match.Matches
	IgnoredMatches   []match.IgnoredMatch
	Packages         []pkg.Package
	Context          pkg.Context
	MetadataProvider vulnerability.MetadataProvider
	SBOM             *sbom.SBOM
	AppConfig        interface{}
	DBStatus         interface{}
}
