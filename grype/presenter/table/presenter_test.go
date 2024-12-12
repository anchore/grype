package table

import (
	"bytes"
	"testing"

	"github.com/gkampitakis/go-snaps/snaps"
	"github.com/go-test/deep"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/presenter/internal"
	"github.com/anchore/grype/grype/presenter/models"
	"github.com/anchore/grype/grype/vulnerability"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

func TestCreateRow(t *testing.T) {
	pkg1 := pkg.Package{
		ID:      "package-1-id",
		Name:    "package-1",
		Version: "1.0.1",
		Type:    syftPkg.DebPkg,
	}
	match1 := match.Match{
		Vulnerability: vulnerability.Vulnerability{
			Reference: vulnerability.Reference{
				ID:        "CVE-1999-0001",
				Namespace: "source-1",
			},
		},
		Package: pkg1,
		Details: []match.Detail{
			{
				Type:    match.ExactDirectMatch,
				Matcher: match.DpkgMatcher,
			},
		},
	}
	cases := []struct {
		name           string
		match          match.Match
		severitySuffix string
		expectedErr    error
		expectedRow    []string
	}{
		{
			name:           "create row for vulnerability",
			match:          match1,
			severitySuffix: "",
			expectedErr:    nil,
			expectedRow:    []string{match1.Package.Name, match1.Package.Version, "", string(match1.Package.Type), match1.Vulnerability.ID, "Low"},
		},
		{
			name:           "create row for suppressed vulnerability",
			match:          match1,
			severitySuffix: appendSuppressed,
			expectedErr:    nil,
			expectedRow:    []string{match1.Package.Name, match1.Package.Version, "", string(match1.Package.Type), match1.Vulnerability.ID, "Low (suppressed)"},
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			row, err := createRow(testCase.match, models.NewMetadataMock(), testCase.severitySuffix)

			assert.Equal(t, testCase.expectedErr, err)
			assert.Equal(t, testCase.expectedRow, row)
		})
	}
}

func TestTablePresenter(t *testing.T) {
	var buffer bytes.Buffer
	_, matches, packages, _, metadataProvider, _, _ := internal.GenerateAnalysis(t, internal.ImageSource)

	pb := models.PresenterConfig{
		Matches:          matches,
		Packages:         packages,
		MetadataProvider: metadataProvider,
	}

	pres := NewPresenter(pb, false)

	t.Run("no color", func(t *testing.T) {
		pres.withColor = true

		err := pres.Present(&buffer)
		require.NoError(t, err)

		actual := buffer.String()
		snaps.MatchSnapshot(t, actual)
	})

	t.Run("with color", func(t *testing.T) {
		pres.withColor = false

		err := pres.Present(&buffer)
		require.NoError(t, err)

		actual := buffer.String()
		snaps.MatchSnapshot(t, actual)
	})

	// TODO: add me back in when there is a JSON schema
	// validateAgainstDbSchema(t, string(actual))
}

func TestEmptyTablePresenter(t *testing.T) {
	// Expected to have no output

	var buffer bytes.Buffer

	matches := match.NewMatches()

	pb := models.PresenterConfig{
		Matches:          matches,
		Packages:         nil,
		MetadataProvider: nil,
	}

	pres := NewPresenter(pb, false)

	// run presenter
	err := pres.Present(&buffer)
	require.NoError(t, err)

	actual := buffer.String()
	snaps.MatchSnapshot(t, actual)
}

func TestRemoveDuplicateRows(t *testing.T) {
	data := [][]string{
		{"1", "2", "3"},
		{"a", "b", "c"},
		{"1", "2", "3"},
		{"a", "b", "c"},
		{"1", "2", "3"},
		{"4", "5", "6"},
		{"1", "2", "1"},
	}

	expected := [][]string{
		{"1", "2", "3"},
		{"a", "b", "c"},
		{"4", "5", "6"},
		{"1", "2", "1"},
	}

	actual := removeDuplicateRows(data)

	if diffs := deep.Equal(expected, actual); len(diffs) > 0 {
		t.Errorf("found diffs!")
		for _, d := range diffs {
			t.Errorf("   diff: %+v", d)
		}
	}
}

func TestSortRows(t *testing.T) {
	data := [][]string{
		{"a", "v0.1.0", "", "deb", "CVE-2019-9996", "Critical"},
		{"a", "v0.1.0", "", "deb", "CVE-2018-9996", "Critical"},
		{"a", "v0.2.0", "", "deb", "CVE-2010-9996", "High"},
		{"b", "v0.2.0", "", "deb", "CVE-2010-9996", "Medium"},
		{"b", "v0.2.0", "2.0.0", "deb", "CVE-2019-9996", "High"},
		{"b", "v0.2.0", "1.0.0", "deb", "CVE-2019-9996", "High"},
		{"d", "v0.4.0", "", "node", "CVE-2011-9996", "Low"},
		{"d", "v0.4.0", "", "node", "CVE-2012-9996", "Negligible"},
		{"c", "v0.6.0", "", "node", "CVE-2013-9996", "Critical"},
	}

	expected := [][]string{
		{"a", "v0.1.0", "", "deb", "CVE-2019-9996", "Critical"},
		{"a", "v0.1.0", "", "deb", "CVE-2018-9996", "Critical"},
		{"a", "v0.2.0", "", "deb", "CVE-2010-9996", "High"},
		{"b", "v0.2.0", "1.0.0", "deb", "CVE-2019-9996", "High"},
		{"b", "v0.2.0", "2.0.0", "deb", "CVE-2019-9996", "High"},
		{"b", "v0.2.0", "", "deb", "CVE-2010-9996", "Medium"},
		{"c", "v0.6.0", "", "node", "CVE-2013-9996", "Critical"},
		{"d", "v0.4.0", "", "node", "CVE-2011-9996", "Low"},
		{"d", "v0.4.0", "", "node", "CVE-2012-9996", "Negligible"},
	}

	actual := sortRows(data)

	if diff := cmp.Diff(expected, actual); diff != "" {
		t.Errorf("sortRows() mismatch (-want +got):\n%s", diff)
	}
}

func TestHidesIgnoredMatches(t *testing.T) {
	var buffer bytes.Buffer
	matches, ignoredMatches, packages, _, metadataProvider, _, _ := internal.GenerateAnalysisWithIgnoredMatches(t, internal.ImageSource)

	pb := models.PresenterConfig{
		Matches:          matches,
		IgnoredMatches:   ignoredMatches,
		Packages:         packages,
		MetadataProvider: metadataProvider,
	}

	pres := NewPresenter(pb, false)

	err := pres.Present(&buffer)
	require.NoError(t, err)

	actual := buffer.String()
	snaps.MatchSnapshot(t, actual)
}

func TestDisplaysIgnoredMatches(t *testing.T) {
	var buffer bytes.Buffer
	matches, ignoredMatches, packages, _, metadataProvider, _, _ := internal.GenerateAnalysisWithIgnoredMatches(t, internal.ImageSource)

	pb := models.PresenterConfig{
		Matches:          matches,
		IgnoredMatches:   ignoredMatches,
		Packages:         packages,
		MetadataProvider: metadataProvider,
	}

	pres := NewPresenter(pb, true)

	err := pres.Present(&buffer)
	require.NoError(t, err)

	actual := buffer.String()
	snaps.MatchSnapshot(t, actual)
}
