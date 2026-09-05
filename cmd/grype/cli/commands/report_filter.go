package commands

import (
	"slices"

	"github.com/anchore/grype/grype/presenter/models"
	"github.com/anchore/grype/grype/vulnerability"
)

func filterDocumentByMinSeverity(doc *models.Document, minSeverity *vulnerability.Severity) {
	if minSeverity == nil {
		return
	}

	doc.Matches = slices.DeleteFunc(doc.Matches, func(m models.Match) bool {
		return vulnerability.ParseSeverity(m.Vulnerability.Severity) < *minSeverity
	})
	if doc.Matches == nil {
		doc.Matches = make([]models.Match, 0)
	}

	doc.IgnoredMatches = slices.DeleteFunc(doc.IgnoredMatches, func(m models.IgnoredMatch) bool {
		return vulnerability.ParseSeverity(m.Vulnerability.Severity) < *minSeverity
	})
	if doc.IgnoredMatches == nil {
		doc.IgnoredMatches = make([]models.IgnoredMatch, 0)
	}
}
