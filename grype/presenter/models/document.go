package models

import (
	"fmt"
	"sort"
	"time"

	"github.com/anchore/clio"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
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
func NewDocument(id clio.Identification, packages []pkg.Package, context pkg.Context, matches match.Matches, ignoredMatches []match.IgnoredMatch, metadataProvider vulnerability.MetadataProvider, appConfig interface{}, dbStatus interface{}) (Document, error) {
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

	sort.Sort(MatchSort(findings))

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
			Name:                  id.Name,
			Version:               id.Version,
			Configuration:         appConfig,
			VulnerabilityDBStatus: dbStatus,
			Timestamp:             string(timestamp),
		},
	}, nil
}
