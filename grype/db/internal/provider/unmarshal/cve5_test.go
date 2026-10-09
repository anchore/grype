package unmarshal

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func loadCVE5(t *testing.T, path string) CVE5Record {
	t.Helper()

	f, err := os.Open(path)
	require.NoError(t, err)
	defer func() { require.NoError(t, f.Close()) }()

	entries, err := CVE5Entries(f)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	return entries[0]
}

func TestCVE5Entries_cpeApplicability(t *testing.T) {
	// unmodified cvelistV5 record, as the cve5 provider writes it
	r := loadCVE5(t, "testdata/cve5/CVE-2026-85091.json")

	require.False(t, r.IsEmpty())
	require.Equal(t, "CVE-2026-85091", r.CVEMetadata.CVEID)
	require.Equal(t, "PUBLISHED", r.CVEMetadata.State)
	require.Equal(t, "VulnCheck", r.CVEMetadata.AssignerShortName)
	require.Equal(t, "2026-09-03T01:04:44.460Z", r.CVEMetadata.DatePublished)
	require.Equal(t, "2026-09-03T13:21:30.355Z", r.CVEMetadata.DateUpdated)

	cna := r.Containers.CNA
	require.Len(t, cna.CPEApplicability, 1)
	require.Nil(t, cna.CPEApplicability[0].Operator)
	require.Len(t, cna.CPEApplicability[0].Nodes, 1)

	node := cna.CPEApplicability[0].Nodes[0]
	require.Equal(t, "OR", string(node.Operator))
	require.NotNil(t, node.Negate)
	require.False(t, *node.Negate)
	require.Len(t, node.CpeMatch, 1)

	m := node.CpeMatch[0]
	require.True(t, m.Vulnerable)
	require.Equal(t, "cpe:2.3:a:zlib:zlib:*:*:*:*:*:*:*:*", m.Criteria)
	require.Empty(t, m.MatchCriteriaID, "CVE 5 carries no matchCriteriaId")
	require.NotNil(t, m.VersionStartIncluding)
	require.Equal(t, "1.3.1.2", *m.VersionStartIncluding)
	require.NotNil(t, m.VersionEndIncluding)
	require.Equal(t, "1.3.2", *m.VersionEndIncluding)
	require.Nil(t, m.VersionEndExcluding)

	require.Len(t, cna.Affected, 1)
	a := cna.Affected[0]
	require.Equal(t, "pkg:github/madler/zlib", a.PackageURL)
	require.Equal(t, "unaffected", a.DefaultStatus)
	require.Len(t, a.Versions, 1)
	require.Equal(t, CVE5Version{
		Version:         "1.3.1.2",
		LessThanOrEqual: "1.3.2",
		Status:          "affected",
		VersionType:     "custom",
	}, a.Versions[0])
}

func TestCVE5Entries_affected(t *testing.T) {
	r := loadCVE5(t, "testdata/cve5/CVE-2026-59650.json")

	cna := r.Containers.CNA
	require.Empty(t, cna.CPEApplicability)
	require.NotEmpty(t, cna.References)
	require.NotEmpty(t, cna.Descriptions)
	require.Equal(t, "en", cna.Descriptions[0].Lang)
	require.Contains(t, cna.Descriptions[0].Value, "Bouncy Castle for Java before 1.85")

	require.Len(t, cna.Affected, 2)

	// the purl identifies the package, packageName disagrees with it
	first := cna.Affected[0]
	require.Equal(t, "pkg:maven/org.bouncycastle/bcprov-jdk18on", first.PackageURL)
	require.Equal(t, "bcprov", first.PackageName)
	require.Equal(t, "https://www.bouncycastle.org/download/bouncy-castle-java/", first.CollectionURL)
	require.Equal(t, []CVE5Version{{Version: "0", LessThan: "1.85", Status: "affected", VersionType: first.Versions[0].VersionType}}, first.Versions)

	second := cna.Affected[1]
	require.Equal(t, "pkg:maven/org.bouncycastle/bcprov-lts8on", second.PackageURL)
	require.Equal(t, "2.73.0", second.Versions[0].Version)
	require.Equal(t, "2.73.12", second.Versions[0].LessThan)
}
