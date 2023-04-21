package models

import (
	"fmt"
	"time"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal"
	"github.com/anchore/grype/internal/version"
)

// Document represents the JSON document to be presented
type Document struct {
	Matches        []Match        `json:"matches"`
	IgnoredMatches []IgnoredMatch `json:"ignoredMatches,omitempty"`
	Source         *source        `json:"source"`
	Distro         distribution   `json:"distro"`
	Descriptor     descriptor     `json:"descriptor"`
}

// NewDocument creates and populates a new Document struct, representing the populated JSON document.
func NewDocument(packages []pkg.Package, context pkg.Context, matches match.Matches, ignoredMatches []match.IgnoredMatch, metadataProvider vulnerability.MetadataProvider, appConfig interface{}, dbStatus interface{}) (Document, error) {
	timestamp, timestampErr := time.Now().Local().MarshalText()
	if timestampErr != nil {
		return Document{}, timestampErr
	}

	// we must preallocate the findings to ensure the JSON document does not show "null" when no matches are found
	var findings = make([]Match, 0)
	for _, m := range matches.Sorted() {
		p := pkg.ByID(m.Package.ID, packages)
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

	var ignoredMatchModels []IgnoredMatch
	for _, m := range ignoredMatches {
		p := pkg.ByID(m.Package.ID, packages)
		if p == nil {
			return Document{}, fmt.Errorf("unable to find package in collection: %+v", p)
		}

		matchModel, err := newMatch(m.Match, *p, metadataProvider)
		if err != nil {
			return Document{}, err
		}

		ignoredMatch := IgnoredMatch{
			Match:              *matchModel,
			AppliedIgnoreRules: mapIgnoreRules(m.AppliedIgnoreRules),
		}
		ignoredMatchModels = append(ignoredMatchModels, ignoredMatch)
	}

	return Document{
		Matches:        findings,
		IgnoredMatches: ignoredMatchModels,
		Source:         src,
		Distro:         newDistribution(context.Distro),
		Descriptor: descriptor{
			Name:                  internal.ApplicationName,
			Version:               version.FromBuild().Version,
			Configuration:         appConfig,
			VulnerabilityDBStatus: dbStatus,
			Timestamp:             string(timestamp),
		},
	}, nil
}
