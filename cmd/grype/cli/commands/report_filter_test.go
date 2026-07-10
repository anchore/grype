package commands

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/clio"
	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/presenter/models"
	"github.com/anchore/grype/grype/vulnerability"
	syftSource "github.com/anchore/syft/syft/source"
)

func TestFilterDocumentByMinSeverity(t *testing.T) {
	severities := []string{"Unknown", "Negligible", "Low", "Medium", "High", "Critical"}
	tests := []struct {
		name     string
		min      *vulnerability.Severity
		expected []string
	}{
		{
			name:     "unset leaves the document unchanged",
			expected: severities,
		},
		{
			name:     "negligible is inclusive and excludes unknown",
			min:      severityPointer(vulnerability.NegligibleSeverity),
			expected: []string{"Negligible", "Low", "Medium", "High", "Critical"},
		},
		{
			name:     "low is inclusive",
			min:      severityPointer(vulnerability.LowSeverity),
			expected: []string{"Low", "Medium", "High", "Critical"},
		},
		{
			name:     "medium is inclusive",
			min:      severityPointer(vulnerability.MediumSeverity),
			expected: []string{"Medium", "High", "Critical"},
		},
		{
			name:     "high is inclusive",
			min:      severityPointer(vulnerability.HighSeverity),
			expected: []string{"High", "Critical"},
		},
		{
			name:     "critical is inclusive",
			min:      severityPointer(vulnerability.CriticalSeverity),
			expected: []string{"Critical"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := newReportFilterTestDocument(t, severities)
			metadataBefore := documentWithoutVulnerabilities(doc)

			filterDocumentByMinSeverity(&doc, tt.min)

			assert.Equal(t, tt.expected, matchSeverities(doc.Matches))
			assert.Equal(t, tt.expected, ignoredMatchSeverities(doc.IgnoredMatches))
			assert.Equal(t, metadataBefore, documentWithoutVulnerabilities(doc))

			for _, ignored := range doc.IgnoredMatches {
				require.Len(t, ignored.AppliedIgnoreRules, 1)
				assert.Equal(t, "preserve this rule", ignored.AppliedIgnoreRules[0].Reason)
			}
		})
	}
}

func TestFilterDocumentByMinSeverityFullyFiltered(t *testing.T) {
	doc := newReportFilterTestDocument(t, []string{"Unknown", "Low"})
	metadataBefore := documentWithoutVulnerabilities(doc)

	filterDocumentByMinSeverity(&doc, severityPointer(vulnerability.CriticalSeverity))

	assert.Empty(t, doc.Matches)
	assert.NotNil(t, doc.Matches)
	assert.Empty(t, doc.IgnoredMatches)
	assert.NotNil(t, doc.IgnoredMatches)
	assert.Equal(t, metadataBefore, documentWithoutVulnerabilities(doc))
}

func newReportFilterTestDocument(t *testing.T, severities []string) models.Document {
	t.Helper()

	d := &distro.Distro{
		Type:    "ubuntu",
		Version: "22.04",
		IDLike:  []string{"debian"},
	}
	p := pkg.Package{
		ID:      "package-id",
		Name:    "package",
		Version: "1.0.0",
		Distro:  d,
	}
	ctx := pkg.Context{
		Source: &syftSource.Description{
			Name:     "test-source",
			Version:  "1.0.0",
			Metadata: syftSource.DirectoryMetadata{Path: "/test/source"},
		},
		Distro: d,
	}
	doc, err := models.NewDocument(
		clio.Identification{Name: "grype", Version: "test"},
		[]pkg.Package{p},
		ctx,
		match.NewMatches(),
		nil,
		nil,
		map[string]any{"configuration": "preserve"},
		map[string]any{"database": "preserve"},
		models.SortByPackage,
		false,
		&models.DistroAlertData{EOLDistroPackages: []pkg.Package{p}},
	)
	require.NoError(t, err)

	for idx, severity := range severities {
		m := reportModelMatch(idx, severity)
		doc.Matches = append(doc.Matches, m)
		doc.IgnoredMatches = append(doc.IgnoredMatches, models.IgnoredMatch{
			Match: m,
			AppliedIgnoreRules: []models.IgnoreRule{
				{
					Reason:    "preserve this rule",
					Namespace: "vex",
					VexStatus: "not_affected",
				},
			},
		})
	}

	return doc
}

func reportModelMatch(idx int, severity string) models.Match {
	id := fmt.Sprintf("CVE-%d-%s", idx, strings.ToLower(severity))
	return models.Match{
		Vulnerability: models.Vulnerability{
			VulnerabilityMetadata: models.VulnerabilityMetadata{
				ID:       id,
				Severity: severity,
			},
		},
		Artifact: models.Package{
			ID:      fmt.Sprintf("package-%d", idx),
			Name:    fmt.Sprintf("package-%d", idx),
			Version: "1.0.0",
		},
	}
}

func matchSeverities(matches []models.Match) []string {
	result := make([]string, 0, len(matches))
	for _, m := range matches {
		result = append(result, m.Vulnerability.Severity)
	}
	return result
}

func ignoredMatchSeverities(matches []models.IgnoredMatch) []string {
	result := make([]string, 0, len(matches))
	for _, m := range matches {
		result = append(result, m.Vulnerability.Severity)
	}
	return result
}

func documentWithoutVulnerabilities(doc models.Document) models.Document {
	doc.Matches = nil
	doc.IgnoredMatches = nil
	return doc
}

func severityPointer(severity vulnerability.Severity) *vulnerability.Severity {
	return &severity
}
