package models

import (
	"github.com/anchore/clio"
	"github.com/anchore/syft/syft/sbom"
)

type PresenterConfig struct {
	ID       clio.Identification
	Document Document
	SBOM     *sbom.SBOM
	Pretty   bool
}
