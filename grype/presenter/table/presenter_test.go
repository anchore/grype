package table

import (
	"bytes"
	"testing"

	"github.com/gkampitakis/go-snaps/snaps"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/clio"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/presenter/internal"
	"github.com/anchore/grype/grype/presenter/models"
	"github.com/anchore/grype/grype/vulnerability"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

func TestCreateRow(t *testing.T) {
	pkg1 := models.Package{
		ID:      "package-1-id",
		Name:    "package-1",
		Version: "1.0.1",
		Type:    syftPkg.DebPkg,
	}
	match1 := models.Match{
		Vulnerability: models.Vulnerability{
			VulnerabilityMetadata: models.VulnerabilityMetadata{
				ID:          "CVE-1999-0001",
				Namespace:   "source-1",
				Description: "1999-01 description",
				Severity:    "Low",
				Cvss: []models.Cvss{
					{
						Metrics: models.CvssMetrics{
							BaseScore: 4,
						},
						Vector:  "another vector",
						Version: "3.0",
					},
				},
			},
		},
		Artifact: pkg1,
		MatchDetails: []models.MatchDetails{
			{
				Type:    match.ExactDirectMatch.String(),
				Matcher: match.DpkgMatcher.String(),
			},
		},
	}
	cases := []struct {
		name           string
		match          models.Match
		severitySuffix string
		expectedRow    []string
	}{
		{
			name:           "create row for vulnerability",
			match:          match1,
			severitySuffix: "",
			expectedRow:    []string{match1.Artifact.Name, match1.Artifact.Version, "", string(match1.Artifact.Type), match1.Vulnerability.ID, "Low"},
		},
		{
			name:           "create row for suppressed vulnerability",
			match:          match1,
			severitySuffix: appendSuppressed,
			expectedRow:    []string{match1.Artifact.Name, match1.Artifact.Version, "", string(match1.Artifact.Type), match1.Vulnerability.ID, "Low (suppressed)"},
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			row := newRow(testCase.match, testCase.severitySuffix)
			cols := rows{row}.Render()[0]

			assert.Equal(t, testCase.expectedRow, cols)
		})
	}
}

func TestTablePresenter(t *testing.T) {
	pb := internal.GeneratePresenterConfig(t, internal.ImageSource)
	pres := NewPresenter(pb, false)

	t.Run("no color", func(t *testing.T) {
		var buffer bytes.Buffer
		pres.withColor = false

		err := pres.Present(&buffer)
		require.NoError(t, err)

		actual := buffer.String()
		snaps.MatchSnapshot(t, actual)
	})

	t.Run("with color", func(t *testing.T) {
		var buffer bytes.Buffer
		pres.withColor = true

		err := pres.Present(&buffer)
		require.NoError(t, err)

		actual := buffer.String()
		snaps.MatchSnapshot(t, actual)
	})
}

func TestEmptyTablePresenter(t *testing.T) {
	// Expected to have no output

	var buffer bytes.Buffer

	doc, err := models.NewDocument(clio.Identification{}, nil, pkg.Context{}, match.NewMatches(), nil, nil, nil, nil, models.SortByPackage)
	require.NoError(t, err)
	pb := models.PresenterConfig{
		Document: doc,
	}

	pres := NewPresenter(pb, false)

	// run presenter
	err = pres.Present(&buffer)
	require.NoError(t, err)

	actual := buffer.String()
	snaps.MatchSnapshot(t, actual)
}

func TestHidesIgnoredMatches(t *testing.T) {
	var buffer bytes.Buffer

	pb := models.PresenterConfig{
		Document: internal.GenerateAnalysisWithIgnoredMatches(t, internal.ImageSource),
	}

	pres := NewPresenter(pb, false)

	err := pres.Present(&buffer)
	require.NoError(t, err)

	actual := buffer.String()
	snaps.MatchSnapshot(t, actual)
}

func TestDisplaysIgnoredMatches(t *testing.T) {
	var buffer bytes.Buffer
	pb := models.PresenterConfig{
		Document: internal.GenerateAnalysisWithIgnoredMatches(t, internal.ImageSource),
	}

	pres := NewPresenter(pb, true)

	err := pres.Present(&buffer)
	require.NoError(t, err)

	actual := buffer.String()
	snaps.MatchSnapshot(t, actual)
}

func TestRowsRender(t *testing.T) {

	t.Run("empty rows returns empty slice", func(t *testing.T) {
		var rs rows
		result := rs.Render()
		assert.Empty(t, result)
	})

	t.Run("deduplicates identical rows", func(t *testing.T) {
		rs := rows{
			mustRow(t, "pkg1", "1.0.0", "1.1.0", "os", "CVE-2023-1234", "critical", vulnerability.FixStateFixed),
			mustRow(t, "pkg1", "1.0.0", "1.1.0", "os", "CVE-2023-1234", "critical", vulnerability.FixStateFixed),
		}
		result := rs.Render()

		expected := [][]string{
			{"pkg1", "1.0.0", "1.1.0", "os", "CVE-2023-1234", "critical"},
		}

		if diff := cmp.Diff(expected, result); diff != "" {
			t.Errorf("Render() mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("renders won't fix and empty fix versions correctly", func(t *testing.T) {
		// Create rows with different fix states
		row1 := mustRow(t, "pkgA", "1.0.0", "", "os", "CVE-2023-1234", "critical", vulnerability.FixStateUnknown)
		row2 := mustRow(t, "pkgB", "2.0.0", "", "os", "CVE-2023-5678", "high", vulnerability.FixStateWontFix)
		row3 := mustRow(t, "pkgC", "3.0.0", "3.1.0", "os", "CVE-2023-9012", "medium", vulnerability.FixStateFixed)

		rs := rows{row1, row2, row3}
		result := rs.Render()

		expected := [][]string{
			{"pkgA", "1.0.0", "", "os", "CVE-2023-1234", "critical"},
			{"pkgB", "2.0.0", "(won't fix)", "os", "CVE-2023-5678", "high"},
			{"pkgC", "3.0.0", "3.1.0", "os", "CVE-2023-9012", "medium"},
		}

		if diff := cmp.Diff(expected, result); diff != "" {
			t.Errorf("Render() mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("column count matches expectations", func(t *testing.T) {
		rs := rows{
			mustRow(t, "pkg1", "1.0.0", "1.1.0", "os", "CVE-2023-1234", "critical", vulnerability.FixStateFixed),
		}
		result := rs.Render()

		expected := [][]string{
			{"pkg1", "1.0.0", "1.1.0", "os", "CVE-2023-1234", "critical"},
		}

		if diff := cmp.Diff(expected, result); diff != "" {
			t.Errorf("Render() mismatch (-want +got):\n%s", diff)
		}

		// should have 7 columns: name, version, fix, packageType, vulnID, severity
		if len(result[0]) != 6 {
			t.Errorf("Expected 7 columns, got %d", len(result[0]))
		}

	})
}

// Helper function to create a test row
func createTestRow(name, version, fix, pkgType, vulnID, severity string, fixState vulnerability.FixState) (row, error) {
	m := models.Match{
		Vulnerability: models.Vulnerability{
			Fix: models.Fix{
				Versions: []string{fix},
				State:    fixState.String(),
			},
			VulnerabilityMetadata: models.VulnerabilityMetadata{
				ID:       vulnID,
				Severity: severity,
			},
		},
		Artifact: models.Package{
			Name:    name,
			Version: version,
			Type:    syftPkg.Type(pkgType),
		},
	}

	r := newRow(m, "")

	return r, nil
}

func mustRow(t *testing.T, name, version, fix, pkgType, vulnID, severity string, fixState vulnerability.FixState) row {
	r, err := createTestRow(name, version, fix, pkgType, vulnID, severity, fixState)
	if err != nil {
		t.Fatalf("failed to create test row: %v", err)
	}
	return r
}
