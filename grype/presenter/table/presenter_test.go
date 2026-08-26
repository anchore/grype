package table

import (
	"bytes"
	"testing"

	"github.com/charmbracelet/lipgloss"
	"github.com/gkampitakis/go-snaps/snaps"
	"github.com/google/go-cmp/cmp"
	"github.com/muesli/termenv"
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
				Cvss: []models.Cvss{
					{
						Metrics: models.CvssMetrics{
							BaseScore: 7,
						},
						Vector:  "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:H",
						Version: "3.1",
					},
				},
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
			expectedRow:     []string{match1.Artifact.Name, match1.Artifact.Version, "1.0.2, *2.0.1, 3.0.4", string(match1.Artifact.Type), match1.Vulnerability.ID, "Medium", "30.0% (50th)", " 87.2"},
		},
		{
			name:            "create row for suppressed vulnerability",
			match:           match1,
			extraAnnotation: appendSuppressed,
			expectedRow:     []string{match1.Artifact.Name, match1.Artifact.Version, "1.0.2, *2.0.1, 3.0.4", string(match1.Artifact.Type), match1.Vulnerability.ID, "Medium", "30.0% (50th)", " 87.2", "(suppressed)"},
		},
		{
			name:            "create row for suppressed vulnerability + Kev",
			match:           matchWithKev,
			extraAnnotation: appendSuppressed,
			expectedRow:     []string{match1.Artifact.Name, match1.Artifact.Version, "1.0.2, *2.0.1, 3.0.4", string(match1.Artifact.Type), match1.Vulnerability.ID, "Medium", "30.0% (50th)", " 87.2", "(kev, suppressed)"},
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			p := NewPresenter(models.PresenterConfig{}, false, nil)
			row := p.newRow(testCase.match, testCase.extraAnnotation, false)
			cols := rows{row}.Render()[0]

			assert.Equal(t, testCase.expectedRow, cols)
		})
	}
}

func TestTablePresenter(t *testing.T) {
	pb := internal.GeneratePresenterConfig(t, internal.ImageSource)

	t.Run("no color", func(t *testing.T) {
		var buffer bytes.Buffer
		lipgloss.SetColorProfile(termenv.Ascii)
		pres := NewPresenter(pb, false, nil)

		err := pres.Present(&buffer)
		require.NoError(t, err)

		actual := buffer.String()
		snaps.MatchSnapshot(t, actual)
	})

	t.Run("with color", func(t *testing.T) {
		var buffer bytes.Buffer
		lipgloss.SetColorProfile(termenv.TrueColor)
		t.Cleanup(func() {
			// don't affect other tests
			lipgloss.SetColorProfile(termenv.Ascii)
		})
		pres := NewPresenter(pb, false, nil)

		err := pres.Present(&buffer)
		require.NoError(t, err)

		actual := buffer.String()
		snaps.MatchSnapshot(t, actual)
	})
}

func TestEmptyTablePresenter(t *testing.T) {
	// Expected to have no output

	var buffer bytes.Buffer

	doc, err := models.NewDocument(clio.Identification{}, nil, pkg.Context{}, match.NewMatches(), nil, nil, nil, nil, models.SortByPackage, true, nil)
	require.NoError(t, err)
	pb := models.PresenterConfig{
		Document: doc,
	}

	pres := NewPresenter(pb, false, nil)

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

	pres := NewPresenter(pb, false, nil)

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

	pres := NewPresenter(pb, true, nil)

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

	pres := NewPresenter(pb, false, nil)

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

	pres := NewPresenter(pb, true, nil)

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
			{"pkg1", "1.0.0", "1.1.0", "os", "CVE-2023-1234", "critical", "3.0% (75th)", "  N/A"},
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
			{"pkgA", "1.0.0", "", "os", "CVE-2023-1234", "critical", "3.0% (75th)", "  N/A"},
			{"pkgB", "2.0.0", "(won't fix)", "os", "CVE-2023-5678", "high", "3.0% (75th)", "  N/A"},
			{"pkgC", "3.0.0", "3.1.0", "os", "CVE-2023-9012", "medium", "3.0% (75th)", "  N/A"},
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
			{"pkg1", "1.0.0", "1.1.0", "os", "CVE-2023-1234", "critical", "3.0% (75th)", "  N/A"},
		}

		if diff := cmp.Diff(expected, result); diff != "" {
			t.Errorf("Render() mismatch (-want +got):\n%s", diff)
		}

		// expected columns: name, version, fix, packageType, vulnID, severity, epss, risk
		assert.Len(t, result[0], 8)

	})
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
				Cvss: []models.Cvss{
					{
						Source:  "nvd",
						Type:    "CVSS",
						Version: "3.1",
						Vector:  "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:L/A:L",
						Metrics: models.CvssMetrics{
							BaseScore: 7.2,
						},
					},
				},
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

	p := NewPresenter(models.PresenterConfig{}, false, nil)
	r := p.newRow(m, "", false)

	return r, nil
}

func TestEPSS_String(t *testing.T) {
	tests := []struct {
		name       string
		score      float64
		percentile float64
		expected   string
	}{
		{
			name:       "zero percentile should return N/A",
			score:      0.0,
			percentile: 0.0,
			expected:   "N/A",
		},
		{
			name:       "very low probability less than 0.1%",
			score:      0.0005,
			percentile: 0.15,
			expected:   "< 0.1% (15th)",
		},
		{
			name:       "low probability with 1st percentile",
			score:      0.02,
			percentile: 0.01,
			expected:   "2.0% (1st)",
		},
		{
			name:       "medium probability with 2nd percentile",
			score:      0.153,
			percentile: 0.92,
			expected:   "15.3% (92nd)",
		},
		{
			name:       "high probability with 3rd percentile",
			score:      0.456,
			percentile: 0.93,
			expected:   "45.6% (93rd)",
		},
		{
			name:       "probability with 4th percentile",
			score:      0.234,
			percentile: 0.84,
			expected:   "23.4% (84th)",
		},
		{
			name:       "probability with 11th percentile (special case)",
			score:      0.125,
			percentile: 0.11,
			expected:   "12.5% (11th)",
		},
		{
			name:       "probability with 12th percentile (special case)",
			score:      0.187,
			percentile: 0.12,
			expected:   "18.7% (12th)",
		},
		{
			name:       "probability with 13th percentile (special case)",
			score:      0.203,
			percentile: 0.13,
			expected:   "20.3% (13th)",
		},
		{
			name:       "probability with 21st percentile",
			score:      0.312,
			percentile: 0.21,
			expected:   "31.2% (21st)",
		},
		{
			name:       "probability with 22nd percentile",
			score:      0.345,
			percentile: 0.22,
			expected:   "34.5% (22nd)",
		},
		{
			name:       "probability with 23rd percentile",
			score:      0.378,
			percentile: 0.23,
			expected:   "37.8% (23rd)",
		},
		{
			name:       "high percentile with 99th",
			score:      0.789,
			percentile: 0.99,
			expected:   "78.9% (99th)",
		},
		{
			name:       "maximum probability and percentile",
			score:      1.0,
			percentile: 1.0,
			expected:   "100.0% (100th)",
		},
		{
			name:       "very small non-zero probability",
			score:      0.001,
			percentile: 0.05,
			expected:   "0.1% (5th)",
		},
		{
			name:       "edge case: exactly 0.1% probability",
			score:      0.001,
			percentile: 0.08,
			expected:   "0.1% (8th)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := epss{
				Score:      tt.score,
				Percentile: tt.percentile,
			}
			result := e.String()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func mustRow(t *testing.T, name, version, fix, pkgType, vulnID, severity string, fixState vulnerability.FixState) row {
	r, err := createTestRow(name, version, fix, pkgType, vulnID, severity, fixState)
	if err != nil {
		t.Fatalf("failed to create test row: %v", err)
	}
	return r
}

func TestSuppressedSourceAllows(t *testing.T) {
	tests := []struct {
		name         string
		matchSources []string
		requested    []string
		want         bool
	}{
		{
			name:         "empty requested renders everything",
			matchSources: []string{"distro-fixed"},
			requested:    nil,
			want:         true,
		},
		{
			name:         "single-value requested that matches",
			matchSources: []string{"distro-fixed"},
			requested:    []string{"distro-fixed"},
			want:         true,
		},
		{
			name:         "single-value requested that does not match",
			matchSources: []string{"user-rule"},
			requested:    []string{"distro-fixed"},
			want:         false,
		},
		{
			name:         "multi-value requested with one matching entry",
			matchSources: []string{"vex"},
			requested:    []string{"distro-fixed", "vex"},
			want:         true,
		},
		{
			name:         "multi-value requested, none matching",
			matchSources: []string{"user-rule"},
			requested:    []string{"distro-fixed", "vex"},
			want:         false,
		},
		{
			name:         "match has multiple sources, one in requested",
			matchSources: []string{"explicit-exclusion", "distro-fixed"},
			requested:    []string{"vex", "distro-fixed"},
			want:         true,
		},
		{
			name:         "match has no sources, filter is active",
			matchSources: nil,
			requested:    []string{"distro-fixed"},
			want:         false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := suppressedSourceAllows(tt.matchSources, tt.requested)
			if got != tt.want {
				t.Errorf("suppressedSourceAllows(%v, %v) = %v, want %v", tt.matchSources, tt.requested, got, tt.want)
			}
		})
	}
}

func TestDisplaysIgnoredMatches_FilteredBySuppressedSource(t *testing.T) {
	// Base document with two IgnoredMatch entries produced by the shared
	// fixture. Tag each with a distinct Source so the filter can distinguish
	// them.
	build := func() models.Document {
		d := internal.GenerateAnalysisWithIgnoredMatches(t, internal.ImageSource)
		require.GreaterOrEqual(t, len(d.IgnoredMatches), 2, "fixture must supply at least two ignored matches for this test")
		d.IgnoredMatches[0].Sources = []string{string(match.IgnoreSourceDistroFixed)}
		d.IgnoredMatches[1].Sources = []string{string(match.IgnoreSourceUserRule)}
		return d
	}

	t.Run("nil filter renders every ignored entry", func(t *testing.T) {
		var buffer bytes.Buffer
		pres := NewPresenter(models.PresenterConfig{Document: build()}, true, nil)
		require.NoError(t, pres.Present(&buffer))

		out := buffer.String()
		assert.Contains(t, out, "CVE-1999-0001")
		assert.Contains(t, out, "CVE-1999-0002")
	})

	t.Run("distro-fixed filter drops the user-rule entry", func(t *testing.T) {
		var buffer bytes.Buffer
		pres := NewPresenter(models.PresenterConfig{Document: build()}, true, []string{string(match.IgnoreSourceDistroFixed)})
		require.NoError(t, pres.Present(&buffer))

		out := buffer.String()
		assert.Contains(t, out, "CVE-1999-0001", "distro-fixed entry should render")
		// CVE-1999-0002 is the user-rule entry in this test fixture; it must be
		// filtered out. Note: it also appears as a top-level Match in the same
		// document (Sources filter is scoped to IgnoredMatches only), so we
		// assert on the suppressed-annotation row instead.
		assert.NotContains(t, out, "CVE-1999-0002  Low       suppressed", "user-rule entry should be filtered out under --suppressed-sources=distro-fixed")
	})

	t.Run("multi-value filter renders every matching entry", func(t *testing.T) {
		var buffer bytes.Buffer
		pres := NewPresenter(
			models.PresenterConfig{Document: build()},
			true,
			[]string{string(match.IgnoreSourceDistroFixed), string(match.IgnoreSourceUserRule)},
		)
		require.NoError(t, pres.Present(&buffer))

		out := buffer.String()
		assert.Contains(t, out, "CVE-1999-0001")
		assert.Contains(t, out, "CVE-1999-0002")
	})
}
