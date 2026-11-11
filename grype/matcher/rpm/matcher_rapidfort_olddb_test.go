package rpm

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	v6 "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/internal/dbtest"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// every DB published before 6.1.11 has no search_rules table, but hydrating it (what the curator does on
// import) auto-migrates the current models and so creates the table, empty. A client that took an
// existing table as authoritative would apply no rules to these DBs, losing the built-in base distro
// fallback, and a RapidFort image on a release the feed does not publish would scan clean.
func TestRapidFortRedHat_HydratedPre611DBKeepsBaseDistroFallback(t *testing.T) {
	dbtest.DBs(t, "review-rapidfort-redhat").Run(func(t *testing.T, fixture *dbtest.DB) {
		dir := t.TempDir()
		content, err := os.ReadFile(filepath.Join(fixture.Path, v6.VulnerabilityDBFileName))
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(dir, v6.VulnerabilityDBFileName), content, 0o600)) //nolint:gosec // dir is t.TempDir()

		// make the copy look like a 6.1.10 DB: no search_rules table, addition 10
		gdb, err := v6.NewLowLevelDB(filepath.Join(dir, v6.VulnerabilityDBFileName), false, true, false)
		require.NoError(t, err)
		require.NoError(t, gdb.Migrator().DropTable(&v6.SearchRule{}))
		require.NoError(t, gdb.Model(&v6.DBMetadata{}).Where("true").Update("addition", 10).Error)
		sqlDB, err := gdb.DB()
		require.NoError(t, err)
		require.NoError(t, sqlDB.Close())

		require.NoError(t, v6.Hydrater()(dir))

		// the trap: hydration left an empty table behind
		gdb, err = v6.NewLowLevelDB(filepath.Join(dir, v6.VulnerabilityDBFileName), false, false, false)
		require.NoError(t, err)
		require.True(t, gdb.Migrator().HasTable(&v6.SearchRule{}), "hydration should create the search_rules table")
		var count int64
		require.NoError(t, gdb.Model(&v6.SearchRule{}).Count(&count).Error)
		require.Zero(t, count, "hydration should not seed search rules")
		sqlDB, err = gdb.DB()
		require.NoError(t, err)
		require.NoError(t, sqlDB.Close())

		rdr, err := v6.NewReader(v6.Config{DBDirPath: dir})
		require.NoError(t, err)
		t.Cleanup(func() { _ = rdr.Close() })
		provider := v6.NewVulnerabilityProvider(rdr)

		// rapidfort-redhat:8 has no rows, so only the built-in fallback to rhel:8 can find this
		p := dbtest.NewPackage("curl", "0:7.61.1-22.el8", syftPkg.RpmPkg).WithDistro(distro.New(distro.RapidFortRedHat, "8", "")).Build()
		matches, _, err := NewRpmMatcher(MatcherConfig{}).Match(provider, p)
		require.NoError(t, err)

		var ids []string
		for _, m := range matches {
			ids = append(ids, m.Vulnerability.ID)
		}
		require.Contains(t, ids, "CVE-2023-38546")
	})
}
