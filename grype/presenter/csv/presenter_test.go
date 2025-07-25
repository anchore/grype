package csv

import (
	"bytes"
	"encoding/csv"
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
		Version: "2.0.0",
		Type:    syftPkg.DebPkg,
	}
	match1 := models.Match{
		Vulnerability: models.Vulnerability{
			Fix: models.Fix{
				Versions: []string{"1.0.2", "2.0.1", "3.0.4"},
				State:    vulnerability.FixStateFixed.String(),
			},
			Risk: 87.2,
			VulnerabilityMetadata: models.VulnerabilityMetadata{
				ID:          "CVE-1999-0001",
				Namespace:   "source-1",
				Description: "1999-01 description",
				Severity:    "Medium",
				EPSS: []models.EPSS{
					{
						CVE:        "CVE-1999-0001",
						EPSS:       0.3,
						Percentile: 0.5,
					},
				},
			},
		},
		Artifact: pkg1,
		MatchDetails: []models.MatchDetails{
			{
				Type:    match.ExactDirectMatch.String(),
				Matcher: match.DpkgMatcher.String(),
				Fix: &models.FixDetails{
					SuggestedVersion: "2.0.1",
				},
			},
		},
	}

	matchWithKev := match1
	matchWithKev.Vulnerability.KnownExploited = append(matchWithKev.Vulnerability.KnownExploited, models.KnownExploited{
		CVE:                        "CVE-1999-0001",
		KnownRansomwareCampaignUse: "Known",
	})

	cases := []struct {
		name            string
		match           models.Match
		extraAnnotation string
		expectedRow     []string
	}{
		{
			name:            "create row for vulnerability",
			match:           match1,
			extraAnnotation: "",
			expectedRow:     []string{match1.Artifact.Name, match1.Artifact.Version, "1.0.2, 2.0.1, 3.0.4", string(match1.Artifact.Type), match1.Vulnerability.ID, "Medium", "50.00%", "87.2", ""},
		},
		{
			name:            "create row for suppressed vulnerability",
			match:           match1,
			extraAnnotation: appendSuppressed,
			expectedRow:     []string{match1.Artifact.Name, match1.Artifact.Version, "1.0.2, 2.0.1, 3.0.4", string(match1.Artifact.Type), match1.Vulnerability.ID, "Medium", "50.00%", "87.2", "(suppressed)"},
		},
		{
			name:            "create row for suppressed vulnerability + Kev",
			match:           matchWithKev,
			extraAnnotation: appendSuppressed,
			expectedRow:     []string{match1.Artifact.Name, match1.Artifact.Version, "1.0.2, 2.0.1, 3.0.4", string(match1.Artifact.Type), match1.Vulnerability.ID, "Medium", "50.00%", "87.2", "(kev, suppressed)"},
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			p := NewPresenter(models.PresenterConfig{}, false)
			row := p.newRow(testCase.match, testCase.extraAnnotation, false)
			cols := rows{row}.Render()[0]

			assert.Equal(t, testCase.expectedRow, cols)
		})
	}
}

func TestCSVPresenter(t *testing.T) {
	pb := internal.GeneratePresenterConfig(t, internal.ImageSource)

	var buffer bytes.Buffer
	pres := NewPresenter(pb, false)

	err := pres.Present(&buffer)
	require.NoError(t, err)

	actual := buffer.String()
	snaps.MatchSnapshot(t, actual)
}

func TestEmptyCSVPresenter(t *testing.T) {
	var buffer bytes.Buffer

	doc, err := models.NewDocument(clio.Identification{}, nil, pkg.Context{}, match.NewMatches(), nil, nil, nil, nil, models.SortByPackage)
	require.NoError(t, err)
	pb := models.PresenterConfig{
		Document: doc,
	}

	pres := NewPresenter(pb, false)

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

func TestDisplaysDistro(t *testing.T) {
	var buffer bytes.Buffer
	pb := models.PresenterConfig{
		Document: internal.GenerateAnalysisWithIgnoredMatches(t, internal.ImageSource),
	}

	pb.Document.Matches[0].Vulnerability.Namespace = "ubuntu:distro:ubuntu:2.5"
	pb.Document.Matches[1].Vulnerability.Namespace = "ubuntu:distro:ubuntu:3.5"

	pres := NewPresenter(pb, false)

	err := pres.Present(&buffer)
	require.NoError(t, err)

	actual := buffer.String()
	snaps.MatchSnapshot(t, actual)
}

func TestDisplaysIgnoredMatchesAndDistro(t *testing.T) {
	var buffer bytes.Buffer
	pb := models.PresenterConfig{
		Document: internal.GenerateAnalysisWithIgnoredMatches(t, internal.ImageSource),
	}

	pb.Document.Matches[0].Vulnerability.Namespace = "ubuntu:distro:ubuntu:2.5"
	pb.Document.Matches[1].Vulnerability.Namespace = "ubuntu:distro:ubuntu:3.5"

	pb.Document.IgnoredMatches[0].Vulnerability.Namespace = "ubuntu:distro:ubuntu:2.5"
	pb.Document.IgnoredMatches[1].Vulnerability.Namespace = "ubuntu:distro:ubuntu:3.5"

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
			{"pkg1", "1.0.0", "1.1.0", "os", "CVE-2023-1234", "critical", "75.00%", "N/A", ""},
		}

		if diff := cmp.Diff(expected, result); diff != "" {
			t.Errorf("Render() mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("renders won't fix and empty fix versions correctly", func(t *testing.T) {
		row1 := mustRow(t, "pkgA", "1.0.0", "", "os", "CVE-2023-1234", "critical", vulnerability.FixStateUnknown)
		row2 := mustRow(t, "pkgB", "2.0.0", "", "os", "CVE-2023-5678", "high", vulnerability.FixStateWontFix)
		row3 := mustRow(t, "pkgC", "3.0.0", "3.1.0", "os", "CVE-2023-9012", "medium", vulnerability.FixStateFixed)

		rs := rows{row1, row2, row3}
		result := rs.Render()

		expected := [][]string{
			{"pkgA", "1.0.0", "", "os", "CVE-2023-1234", "critical", "75.00%", "N/A", ""},
			{"pkgB", "2.0.0", "(won't fix)", "os", "CVE-2023-5678", "high", "75.00%", "N/A", ""},
			{"pkgC", "3.0.0", "3.1.0", "os", "CVE-2023-9012", "medium", "75.00%", "N/A", ""},
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
			{"pkg1", "1.0.0", "1.1.0", "os", "CVE-2023-1234", "critical", "75.00%", "N/A", ""},
		}

		if diff := cmp.Diff(expected, result); diff != "" {
			t.Errorf("Render() mismatch (-want +got):\n%s", diff)
		}

		assert.Len(t, result[0], 9)
	})
}

func TestStripANSI(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "removes basic ANSI codes",
			input:    "\x1b[31mred text\x1b[0m",
			expected: "red text",
		},
		{
			name:     "removes complex ANSI codes",
			input:    "\x1b[1;38;5;198mCritical\x1b[0m",
			expected: "Critical",
		},
		{
			name:     "handles text without ANSI codes",
			input:    "plain text",
			expected: "plain text",
		},
		{
			name:     "handles empty string",
			input:    "",
			expected: "",
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			result := stripANSI(testCase.input)
			assert.Equal(t, testCase.expected, result)
		})
	}
}

func TestCSVFieldsWithCommas(t *testing.T) {
	var buffer bytes.Buffer

	p := NewPresenter(models.PresenterConfig{}, false)
	testMatch := models.Match{
		Vulnerability: models.Vulnerability{
			VulnerabilityMetadata: models.VulnerabilityMetadata{
				ID:          "CVE-2023-0001",
				Description: "A vulnerability with, commas, in description",
				Severity:    "High",
			},
		},
		Artifact: models.Package{
			Name:    "test,package",
			Version: "1.0.0",
			Type:    syftPkg.DebPkg,
		},
	}

	row := p.newRow(testMatch, "", false)
	cols := row.Columns()

	assert.Equal(t, "test,package", cols[0])

	writer := csv.NewWriter(&buffer)
	err := writer.Write(cols)
	require.NoError(t, err)
	writer.Flush()

	reader := csv.NewReader(&buffer)
	records, err := reader.ReadAll()
	require.NoError(t, err)

	assert.Len(t, records, 1)
	assert.Equal(t, "test,package", records[0][0])
}

func TestCSVFieldsWithQuotes(t *testing.T) {
	var buffer bytes.Buffer

	p := NewPresenter(models.PresenterConfig{}, false)
	testMatch := models.Match{
		Vulnerability: models.Vulnerability{
			VulnerabilityMetadata: models.VulnerabilityMetadata{
				ID:          "CVE-2023-0001",
				Description: `A vulnerability with "quotes" in description`,
				Severity:    "High",
			},
		},
		Artifact: models.Package{
			Name:    `test"package`,
			Version: "1.0.0",
			Type:    syftPkg.DebPkg,
		},
	}

	row := p.newRow(testMatch, "", false)
	cols := row.Columns()

	assert.Equal(t, `test"package`, cols[0])

	writer := csv.NewWriter(&buffer)
	err := writer.Write(cols)
	require.NoError(t, err)
	writer.Flush()

	reader := csv.NewReader(&buffer)
	records, err := reader.ReadAll()
	require.NoError(t, err)

	assert.Len(t, records, 1)
	assert.Equal(t, `test"package`, records[0][0])
}

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
				EPSS: []models.EPSS{
					{
						CVE:        vulnID,
						EPSS:       0.03,
						Percentile: 0.75,
					},
				},
			},
		},
		Artifact: models.Package{
			Name:    name,
			Version: version,
			Type:    syftPkg.Type(pkgType),
		},
	}

	p := NewPresenter(models.PresenterConfig{}, false)
	r := p.newRow(m, "", false)

	return r, nil
}

func mustRow(t *testing.T, name, version, fix, pkgType, vulnID, severity string, fixState vulnerability.FixState) row {
	r, err := createTestRow(name, version, fix, pkgType, vulnID, severity, fixState)
	if err != nil {
		t.Fatalf("failed to create test row: %v", err)
	}
	return r
}
