package dbsearch

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	v6 "github.com/anchore/grype/grype/db/v6"
)

func TestExpandAliases_AliasLinks(t *testing.T) {
	db := newAliasTestDB(t,
		vulnWithAliases("CVE-2024-0001", "nvd"),
		vulnWithAliases("CVE-2024-0002", "nvd"),
		vulnWithAliases("GHSA-aaaa-aaaa-aaaa", "github", "CVE-2024-0001"),
		vulnWithAliases("GHSA-bbbb-bbbb-bbbb", "github", "CVE-2024-0002"),
		// a rejected duplicate advisory, which has no aliases
		vulnWithAliases("GHSA-dupe-dupe-dupe", "github"),
		// a chainguard libraries record, also referencing the duplicate advisory
		vulnWithAliases("CGA-aaaa-aaaa-aaaa", "chainguard-libraries", "CVE-2024-0001", "GHSA-aaaa-aaaa-aaaa", "GHSA-dupe-dupe-dupe"),
		// a GO record only referencing the GHSA
		vulnWithAliases("GO-2024-0001", "govulndb", "GHSA-aaaa-aaaa-aaaa"),
		// a bundled distro advisory referencing multiple CVEs
		vulnWithAliases("ELSA-2024-0001", "oracle", "CVE-2024-0001", "CVE-2024-0002"),
		// records only referencing the bundled distro advisory
		vulnWithAliases("CGA-bbbb-bbbb-bbbb", "chainguard-libraries", "ELSA-2024-0001"),
		vulnWithAliases("CGA-cccc-cccc-cccc", "chainguard-libraries", "ELSA-2024-0001"),
	)

	tests := []struct {
		name     string
		search   string
		expected []string
	}{
		{
			name:   "CVE finds records referencing it, but not other CVEs referenced by a bundled advisory",
			search: "CVE-2024-0001",
			expected: []string{
				"CVE-2024-0001",
				"GHSA-aaaa-aaaa-aaaa",
				"CGA-aaaa-aaaa-aaaa",
				"ELSA-2024-0001",
				"GHSA-dupe-dupe-dupe", // through CGA-aaaa-aaaa-aaaa
				"GO-2024-0001",        // through GHSA-aaaa-aaaa-aaaa
			},
		},
		{
			name:   "GHSA finds records linked by a shared CVE alias",
			search: "GHSA-aaaa-aaaa-aaaa",
			expected: []string{
				"GHSA-aaaa-aaaa-aaaa",
				"CVE-2024-0001",
				"CGA-aaaa-aaaa-aaaa",
				"GO-2024-0001",
				"ELSA-2024-0001",      // through CVE-2024-0001
				"GHSA-dupe-dupe-dupe", // through CGA-aaaa-aaaa-aaaa
			},
		},
		{
			name:   "CGA finds records linked by shared aliases",
			search: "CGA-aaaa-aaaa-aaaa",
			expected: []string{
				"CGA-aaaa-aaaa-aaaa",
				"CVE-2024-0001",
				"GHSA-aaaa-aaaa-aaaa",
				"GHSA-dupe-dupe-dupe",
				"ELSA-2024-0001", // through CVE-2024-0001
				"GO-2024-0001",   // through GHSA-aaaa-aaaa-aaaa
			},
		},
		{
			name:   "duplicate advisory without aliases finds records through the CGA referencing it",
			search: "GHSA-dupe-dupe-dupe",
			expected: []string{
				"GHSA-dupe-dupe-dupe",
				"CGA-aaaa-aaaa-aaaa",
				"CVE-2024-0001",
				"GHSA-aaaa-aaaa-aaaa",
			},
		},
		{
			name:   "GO record finds the CVE through the GHSA it references",
			search: "GO-2024-0001",
			expected: []string{
				"GO-2024-0001",
				"GHSA-aaaa-aaaa-aaaa",
				"CVE-2024-0001",
				"CGA-aaaa-aaaa-aaaa",
			},
		},
		{
			name:   "other CVE in a bundled advisory does not find the first CVE's records",
			search: "CVE-2024-0002",
			expected: []string{
				"CVE-2024-0002",
				"GHSA-bbbb-bbbb-bbbb",
				"ELSA-2024-0001",
			},
		},
		{
			name:   "bundled advisory finds records for all of its CVEs",
			search: "ELSA-2024-0001",
			expected: []string{
				"ELSA-2024-0001",
				"CVE-2024-0001",
				"CVE-2024-0002",
				"GHSA-aaaa-aaaa-aaaa",
				"GHSA-bbbb-bbbb-bbbb",
				"CGA-aaaa-aaaa-aaaa",
				"CGA-bbbb-bbbb-bbbb",
				"CGA-cccc-cccc-cccc",
			},
		},
		{
			name:   "record referencing a bundled advisory does not walk through it",
			search: "CGA-bbbb-bbbb-bbbb",
			expected: []string{
				"CGA-bbbb-bbbb-bbbb",
				"ELSA-2024-0001",
			},
		},
		{
			name:   "search is case insensitive",
			search: "cve-2024-0002",
			expected: []string{
				"CVE-2024-0002",
				"GHSA-bbbb-bbbb-bbbb",
				"ELSA-2024-0001",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.ElementsMatch(t, tt.expected, db.search(t, tt.search))
		})
	}
}

func TestExpandAliases_AliasLinkEdgeCases(t *testing.T) {
	db := newAliasTestDB(t,
		vulnWithAliases("CVE-2024-0001", "nvd"),
		vulnWithAliases("GHSA-aaaa-aaaa-aaaa", "github", "CVE-2024-0001"),
		// references the GHSA in a different case than the GHSA record itself
		vulnWithAliases("GO-2024-0001", "govulndb", "ghsa-aaaa-aaaa-aaaa"),
		// two CVE records sharing an alias with no record of its own, which bundles them from the alias side
		vulnWithAliases("CVE-2024-0003", "nvd", "SHARED-0001"),
		vulnWithAliases("CVE-2024-0004", "nvd", "SHARED-0001"),
	)

	t.Run("second hop is case insensitive", func(t *testing.T) {
		assert.ElementsMatch(t, []string{"CVE-2024-0001", "GHSA-aaaa-aaaa-aaaa", "GO-2024-0001"}, db.search(t, "CVE-2024-0001"))
	})

	t.Run("an ID shared by several CVE records is not walked through", func(t *testing.T) {
		assert.ElementsMatch(t, []string{"CVE-2024-0003"}, db.search(t, "CVE-2024-0003"))
	})
}

func TestRelatedVulnerabilityNames_Truncated(t *testing.T) {
	direct := []v6.VulnerabilityAlias{
		{Name: "GHSA-aaaa-aaaa-aaaa", Alias: "CVE-2024-0001"},
		{Name: "ELSA-2024-0001", Alias: "CVE-2024-0001"},
	}

	t.Run("a truncated second hop keeps only the direct links", func(t *testing.T) {
		m := new(affectedMockReader)
		defer m.AssertExpectations(t)
		m.On("GetVulnerabilityAliases", []string{"CVE-2024-0001"}, maxAliasRows).Return(direct, nil).Once()
		// the bundled ELSA lost its other CVE rows to the limit, so it looks like it links to a single CVE
		m.On("GetVulnerabilityAliases", mock.Anything, maxAliasRows).Return([]v6.VulnerabilityAlias{
			{Name: "ELSA-2024-0001", Alias: "CVE-2024-0001"},
			{Name: "ELSA-2024-0001", Alias: "CVE-2024-9999"},
		}, v6.ErrLimitReached).Once()

		names, err := relatedVulnerabilityNames(m, "CVE-2024-0001")
		require.NoError(t, err)
		assert.Equal(t, []string{"ELSA-2024-0001", "GHSA-AAAA-AAAA-AAAA"}, names)
	})

	t.Run("a truncated first hop still walks the links it found", func(t *testing.T) {
		m := new(affectedMockReader)
		defer m.AssertExpectations(t)
		m.On("GetVulnerabilityAliases", []string{"CVE-2024-0001"}, maxAliasRows).Return(direct[:1], v6.ErrLimitReached).Once()
		m.On("GetVulnerabilityAliases", []string{"GHSA-AAAA-AAAA-AAAA"}, maxAliasRows).Return([]v6.VulnerabilityAlias{
			{Name: "GHSA-aaaa-aaaa-aaaa", Alias: "CVE-2024-0001"},
			{Name: "GO-2024-0001", Alias: "GHSA-aaaa-aaaa-aaaa"},
		}, nil).Once()

		names, err := relatedVulnerabilityNames(m, "CVE-2024-0001")
		require.NoError(t, err)
		assert.Equal(t, []string{"GHSA-AAAA-AAAA-AAAA", "GO-2024-0001"}, names)
	})

	t.Run("direct links come before second hop names", func(t *testing.T) {
		m := new(affectedMockReader)
		defer m.AssertExpectations(t)
		m.On("GetVulnerabilityAliases", []string{"CVE-2024-0001"}, maxAliasRows).Return([]v6.VulnerabilityAlias{
			{Name: "GHSA-aaaa-aaaa-aaaa", Alias: "CVE-2024-0001"},
		}, nil).Once()
		m.On("GetVulnerabilityAliases", []string{"GHSA-AAAA-AAAA-AAAA"}, maxAliasRows).Return([]v6.VulnerabilityAlias{
			{Name: "GHSA-aaaa-aaaa-aaaa", Alias: "CVE-2024-0001"},
			{Name: "ALAS-2024-0001", Alias: "GHSA-aaaa-aaaa-aaaa"},
		}, nil).Once()

		names, err := relatedVulnerabilityNames(m, "CVE-2024-0001")
		require.NoError(t, err)
		// ALAS sorts first, but is only reached through the GHSA
		assert.Equal(t, []string{"GHSA-AAAA-AAAA-AAAA", "ALAS-2024-0001"}, names)
	})

	t.Run("other errors are returned", func(t *testing.T) {
		m := new(affectedMockReader)
		m.On("GetVulnerabilityAliases", mock.Anything, mock.Anything).Return([]v6.VulnerabilityAlias(nil), assert.AnError)

		_, err := relatedVulnerabilityNames(m, "CVE-2024-0001")
		require.ErrorIs(t, err, assert.AnError)
	})
}

func TestExpandAliases(t *testing.T) {
	t.Run("given specs come first, keep their filters, and duplicates are dropped", func(t *testing.T) {
		m := new(affectedMockReader)
		m.On("GetVulnerabilityAliases", []string{"CVE-2024-0001"}, maxAliasRows).Return([]v6.VulnerabilityAlias{
			{Name: "GHSA-aaaa-aaaa-aaaa", Alias: "CVE-2024-0001"},
		}, nil)
		m.On("GetVulnerabilityAliases", []string{"GHSA-AAAA-AAAA-AAAA"}, maxAliasRows).Return([]v6.VulnerabilityAlias{
			{Name: "GHSA-aaaa-aaaa-aaaa", Alias: "CVE-2024-0001"},
		}, nil)
		m.On("GetVulnerabilityAliases", []string{"GHSA-aaaa-aaaa-aaaa"}, maxAliasRows).Return([]v6.VulnerabilityAlias{
			{Name: "GHSA-aaaa-aaaa-aaaa", Alias: "CVE-2024-0001"},
		}, nil)

		expanded, err := expandAliases(m, v6.VulnerabilitySpecifiers{
			{Name: "CVE-2024-0001", Providers: []string{"nvd"}},
			// already related to the first spec, but with a different provider filter
			{Name: "GHSA-aaaa-aaaa-aaaa", Providers: []string{"github"}},
			// specs without a name are kept as they are
			{Providers: []string{"nvd"}},
		})
		require.NoError(t, err)
		assert.Equal(t, v6.VulnerabilitySpecifiers{
			{Name: "CVE-2024-0001", Providers: []string{"nvd"}},
			{Name: "GHSA-aaaa-aaaa-aaaa", Providers: []string{"github"}},
			{Providers: []string{"nvd"}},
			{Name: "GHSA-AAAA-AAAA-AAAA", Providers: []string{"nvd"}},
			{Name: "CVE-2024-0001", Providers: []string{"github"}},
		}, expanded)
	})

	t.Run("expansion is capped without dropping the given names", func(t *testing.T) {
		var rows []v6.VulnerabilityAlias
		for i := range maxExpandedVulnerabilities + 10 {
			rows = append(rows, v6.VulnerabilityAlias{Name: fmt.Sprintf("GHSA-%04d", i), Alias: "CVE-2024-0001"})
		}
		m := new(affectedMockReader)
		m.On("GetVulnerabilityAliases", []string{"CVE-2024-0001"}, maxAliasRows).Return(rows, nil)
		m.On("GetVulnerabilityAliases", mock.Anything, maxAliasRows).Return([]v6.VulnerabilityAlias{}, nil)

		expanded, err := expandAliases(m, v6.VulnerabilitySpecifiers{{Name: "CVE-2024-0001"}})
		require.NoError(t, err)
		require.Len(t, expanded, maxExpandedVulnerabilities)
		assert.Equal(t, "CVE-2024-0001", expanded[0].Name)
	})

	t.Run("the cap drops related names evenly across the given specs", func(t *testing.T) {
		m := new(affectedMockReader)
		for _, cve := range []string{"CVE-2024-0001", "CVE-2024-0002"} {
			var rows []v6.VulnerabilityAlias
			for i := range maxExpandedVulnerabilities {
				rows = append(rows, v6.VulnerabilityAlias{Name: fmt.Sprintf("GHSA-%s-%04d", cve, i), Alias: cve})
			}
			m.On("GetVulnerabilityAliases", []string{cve}, maxAliasRows).Return(rows, nil)
		}
		m.On("GetVulnerabilityAliases", mock.Anything, maxAliasRows).Return([]v6.VulnerabilityAlias{}, nil)

		expanded, err := expandAliases(m, v6.VulnerabilitySpecifiers{{Name: "CVE-2024-0001"}, {Name: "CVE-2024-0002"}})
		require.NoError(t, err)
		require.Len(t, expanded, maxExpandedVulnerabilities)

		perCVE := map[string]int{}
		for _, s := range expanded[2:] {
			perCVE[s.Name[len("GHSA-"):len("GHSA-CVE-2024-0001")]]++
		}
		half := (maxExpandedVulnerabilities - 2) / 2
		assert.Equal(t, map[string]int{"CVE-2024-0001": half, "CVE-2024-0002": half}, perCVE)
	})

	t.Run("a name given twice is only walked once", func(t *testing.T) {
		m := new(affectedMockReader)
		defer m.AssertExpectations(t)
		m.On("GetVulnerabilityAliases", []string{"CVE-2024-0001"}, maxAliasRows).Return([]v6.VulnerabilityAlias{
			{Name: "GHSA-aaaa-aaaa-aaaa", Alias: "CVE-2024-0001"},
		}, nil).Once()
		m.On("GetVulnerabilityAliases", []string{"GHSA-AAAA-AAAA-AAAA"}, maxAliasRows).Return([]v6.VulnerabilityAlias{}, nil).Once()

		expanded, err := expandAliases(m, v6.VulnerabilitySpecifiers{{Name: "CVE-2024-0001"}, {Name: "cve-2024-0001"}})
		require.NoError(t, err)
		assert.Equal(t, v6.VulnerabilitySpecifiers{{Name: "CVE-2024-0001"}, {Name: "GHSA-AAAA-AAAA-AAAA"}}, expanded)
	})

	t.Run("related specs never ask the store for its own alias hop", func(t *testing.T) {
		m := new(affectedMockReader)
		m.On("GetVulnerabilityAliases", []string{"CVE-2024-0001"}, maxAliasRows).Return([]v6.VulnerabilityAlias{
			{Name: "GHSA-aaaa-aaaa-aaaa", Alias: "CVE-2024-0001"},
		}, nil)
		m.On("GetVulnerabilityAliases", mock.Anything, maxAliasRows).Return([]v6.VulnerabilityAlias{}, nil)

		expanded, err := expandAliases(m, v6.VulnerabilitySpecifiers{{Name: "CVE-2024-0001", IncludeAliases: true}})
		require.NoError(t, err)
		assert.Equal(t, v6.VulnerabilitySpecifiers{
			{Name: "CVE-2024-0001", IncludeAliases: true},
			{Name: "GHSA-AAAA-AAAA-AAAA"},
		}, expanded)
	})

	t.Run("empty names in the alias table are never searched for", func(t *testing.T) {
		m := new(affectedMockReader)
		m.On("GetVulnerabilityAliases", []string{"CVE-2024-0001"}, maxAliasRows).Return([]v6.VulnerabilityAlias{
			{Name: "CVE-2024-0001", Alias: ""},
			{Name: "GHSA-aaaa-aaaa-aaaa", Alias: "CVE-2024-0001"},
		}, nil)
		m.On("GetVulnerabilityAliases", []string{"GHSA-AAAA-AAAA-AAAA"}, maxAliasRows).Return([]v6.VulnerabilityAlias{
			{Name: "GHSA-aaaa-aaaa-aaaa", Alias: "CVE-2024-0001"},
			{Name: "", Alias: "GHSA-aaaa-aaaa-aaaa"},
		}, nil)

		// without a name, a spec would match every vulnerability from the provider
		expanded, err := expandAliases(m, v6.VulnerabilitySpecifiers{{Name: "CVE-2024-0001", Providers: []string{"nvd"}}})
		require.NoError(t, err)
		assert.Equal(t, v6.VulnerabilitySpecifiers{
			{Name: "CVE-2024-0001", Providers: []string{"nvd"}},
			{Name: "GHSA-AAAA-AAAA-AAAA", Providers: []string{"nvd"}},
		}, expanded)
	})
}

func TestExpandAliases_CapFitsInOneQuery(t *testing.T) {
	db := newAliasTestDB(t, vulnWithAliases("CVE-2024-0001", "nvd"))

	// a fully expanded search, with the filters the CLI adds to every spec, must still be a valid package and CPE query
	published := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	var specs v6.VulnerabilitySpecifiers
	for i := range maxExpandedVulnerabilities {
		specs = append(specs, v6.VulnerabilitySpecifier{Name: fmt.Sprintf("CVE-2024-%04d", i), PublishedAfter: &published, Providers: []string{"nvd", "github"}})
	}

	_, err := findAffectedPackages(db, AffectedPackagesOptions{Vulnerability: specs}, allRecords)
	require.NoError(t, err)
}

type aliasTestDB struct {
	v6.ReadWriter
}

func vulnWithAliases(name, provider string, aliases ...string) *v6.VulnerabilityHandle {
	return &v6.VulnerabilityHandle{
		Name:      name,
		BlobValue: &v6.VulnerabilityBlob{ID: name, Aliases: aliases},
		Provider:  &v6.Provider{ID: provider},
	}
}

func newAliasTestDB(t *testing.T, vulns ...*v6.VulnerabilityHandle) aliasTestDB {
	t.Helper()
	rw, err := v6.NewWriter(v6.Config{DBDirPath: t.TempDir()})
	require.NoError(t, err)
	t.Cleanup(func() { _ = rw.Close() })
	require.NoError(t, rw.AddVulnerabilities(vulns...))
	return aliasTestDB{ReadWriter: rw}
}

// search returns the names of the vulnerability records found for the name with its aliases expanded
func (db aliasTestDB) search(t *testing.T, name string) []string {
	t.Helper()
	specs, err := expandAliases(db, v6.VulnerabilitySpecifiers{{Name: name}})
	require.NoError(t, err)

	var names []string
	for _, spec := range specs {
		found, err := db.GetVulnerabilities(&spec, nil)
		require.NoError(t, err)
		for _, v := range found {
			names = append(names, v.Name)
		}
	}
	return names
}
