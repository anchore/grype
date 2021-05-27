package models

import (
	"fmt"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal"
	"github.com/anchore/grype/internal/version"
)

// Document represents the JSON document to be presented
type Document struct {
	Matches    []Match      `json:"matches"`
	Source     *source      `json:"source"`
	Distro     distribution `json:"distro"`
	Descriptor descriptor   `json:"descriptor"`
}

// NewDocument creates and populates a new Document struct, representing the populated JSON document.
func NewDocument(packages []pkg.Package, context pkg.Context, matches match.Matches,
	metadataProvider vulnerability.MetadataProvider, appConfig interface{}, dbStatus interface{}) (Document, error) {
	// we must preallocate the findings to ensure the JSON document does not show "null" when no matches are found
	var findings = make([]Match, 0)
	for _, m := range matches.Sorted() {
		p := pkg.ByID(m.Package.ID(), packages)
		if p == nil {
			return Document{}, fmt.Errorf("unable to find package in collection: %+v", p)
		}

		matchModel, err := newMatch(m, *p, metadataProvider)
		if err != nil {
			return Document{}, err
		}

		findings = append(findings, *matchModel)
	}

	var src *source
	if context.Source != nil {
		theSrc, err := newSource(*context.Source)
		if err != nil {
			return Document{}, err
		}
		src = &theSrc
	}

	return Document{
		Matches: findings,
		Source:  src,
		Distro:  newDistribution(context.Distro),
		Descriptor: descriptor{
			Name:                  internal.ApplicationName,
			Version:               version.FromBuild().Version,
			Configuration:         appConfig,
			VulnerabilityDbStatus: dbStatus,
		},
	}, nil
}
