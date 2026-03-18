package diff

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"gorm.io/gorm"

	v6 "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/internal/log"
	"github.com/anchore/syft/syft/cpe"
)

const cpeEcosystem = "cpe"

// DBDiffer compares two vulnerability databases using direct SQL comparison.
// The old database is opened as the main connection and the new database is
// attached as "new_db", allowing cross-database SQL queries.
type DBDiffer struct {
	config Config
	db     *gorm.DB
	oldDB  ResolvedDB
	newDB  ResolvedDB
}

// NewDBDiffer creates a new database differ. oldDBDir and newDBDir are directories
// containing a vulnerability.db file.
func NewDBDiffer(cfg Config) (*DBDiffer, error) {
	resolvedOld, resolvedNew, err := parallel[ResolvedDB](func() (ResolvedDB, error) {
		return ResolveDB(cfg.OldDB, cfg.DBRootDir)
	}, func() (ResolvedDB, error) {
		return ResolveDB(cfg.NewDB, cfg.DBRootDir)
	})

	if err != nil {
		return nil, err
	}

	differ, err := newDBDifferDirs(resolvedOld, resolvedNew, cfg)
	if differ == nil {
		defer resolvedOld.Cleanup()
		defer resolvedNew.Cleanup()
		return nil, err
	}
	return differ, err
}

func newDBDifferDirs(oldDB, newDB ResolvedDB, config Config) (*DBDiffer, error) {
	oldDBPath := filepath.Join(oldDB.Dir, v6.VulnerabilityDBFileName)
	newDBPath := filepath.Join(newDB.Dir, v6.VulnerabilityDBFileName)

	writable := config.Debug
	db, err := v6.NewLowLevelDB(oldDBPath, false, writable, config.Debug)
	if err != nil {
		return nil, fmt.Errorf("failed to open old database: %w", err)
	}

	if err := db.Exec("ATTACH DATABASE ? AS new_db", newDBPath).Error; err != nil {
		closeLowLevelDB(db)
		return nil, fmt.Errorf("failed to attach new database: %w", err)
	}

	beforeTime, err := time.Parse(time.RFC3339, oldDB.Info.BuildTimestamp)
	if err != nil {
		return nil, fmt.Errorf("failed to parse build timestamp: %w", err)
	}
	afterTime, err := time.Parse(time.RFC3339, newDB.Info.BuildTimestamp)
	if err != nil {
		return nil, fmt.Errorf("failed to parse build timestamp: %w", err)
	}

	if beforeTime.Equal(afterTime) {
		log.Warn("the provided databases have the same built times")
	}

	// make sure we're always comparing old to new
	if beforeTime.After(afterTime) {
		newDB, oldDB = oldDB, newDB
	}

	return &DBDiffer{
		db:     db,
		oldDB:  oldDB,
		newDB:  newDB,
		config: config,
	}, nil
}

// Close detaches the new database and closes the connection.
func (d *DBDiffer) Close() error {
	if err := d.db.Exec("DETACH DATABASE new_db").Error; err != nil {
		return fmt.Errorf("failed to detach new database: %w", err)
	}
	closeLowLevelDB(d.db)
	return nil
}

type pkgKey struct {
	Ecosystem string
	Name      string
	CPE       string
}

// Diff runs all comparison vectors and returns a Result using the existing output types.
func (d *DBDiffer) Diff() (*Result, error) {
	startTime := time.Now()

	var err error

	var vulns *VulnerabilityDiff
	if d.config.IncludeVulns() {
		vulns, err = d.diffVulns()
		if err != nil {
			return nil, err
		}
	}

	var packages []PackageDiff
	if d.config.IncludePackages() {
		packages, err = d.diffPackages()
		if err != nil {
			return nil, err
		}
	}

	log.Infof("full diff completed in %s", time.Since(startTime))

	return &Result{
		Schema: Schema,
		Databases: DatabaseDiff{
			Before: d.oldDB.Info,
			After:  d.newDB.Info,
		},
		Packages:        packages,
		Vulnerabilities: vulns,
	}, nil
}

func (d *DBDiffer) diffPackages() ([]PackageDiff, error) {
	startTime := time.Now()

	err := d.createPackagesTables()
	if err != nil {
		return nil, err
	}

	// collect all per-package/CPE diff entries
	diffs := map[pkgKey]*PackageDiff{}

	changeTypes := []struct {
		name string
		fn   func(map[pkgKey]*PackageDiff) (int, error)
	}{
		{"added package vulnerabilities", d.findLanguageAndOSVulnsAdded},
		{"removed package vulnerabilities", d.findLanguageAndOSVulnsRemoved},
		{"modified package vulnerabilities", d.findLanguageAndOSVulnsModified},
		{"added CPE vulnerabilities", d.findCPEVulnsAdded},
		{"removed CPE vulnerabilities", d.findCPEVulnsRemoved},
		{"modified CPE vulnerabilities", d.findCPEVulnsModified},
	}

	for _, v := range changeTypes {
		startTime := time.Now()
		count, err := v.fn(diffs)
		if err != nil {
			return nil, fmt.Errorf("%q failed: %w", v.name, err)
		}
		log.Infof("%s found %v records; took %s", v.name, count, time.Since(startTime))
	}

	log.Infof("package diff completed in %s", time.Since(startTime))

	packages := make([]PackageDiff, 0, len(diffs))
	for _, pd := range diffs {
		packages = append(packages, *pd)
	}
	slices.SortFunc(packages, func(a, b PackageDiff) int {
		if a.Name != b.Name {
			return strings.Compare(a.Name, b.Name)
		}
		if a.Ecosystem != b.Ecosystem {
			return strings.Compare(a.Ecosystem, b.Ecosystem)
		}
		return strings.Compare(a.CPE, b.CPE)
	})
	return packages, nil
}

func (d *DBDiffer) createPackagesTables() error {
	startTime := time.Now()
	if err := d.createDiffTablesPackages("old", "main"); err != nil {
		return fmt.Errorf("failed to create old package tables: %w", err)
	}
	if err := d.createDiffTablesPackages("new", "new_db"); err != nil {
		return fmt.Errorf("failed to create new package tables: %w", err)
	}
	if err := d.createDiffViewsPackages(); err != nil {
		return fmt.Errorf("failed to create package views: %w", err)
	}
	log.Infof("created package diff tables in %s", time.Since(startTime))
	return nil
}

func (d *DBDiffer) executeTemplates(templates []string, r *strings.Replacer) error {
	for _, stmt := range d.prepareTemplates(templates, r) {
		startTime := time.Now()
		if err := d.db.Exec(stmt).Error; err != nil {
			return fmt.Errorf("failed to execute: %s: %w", stmt, err)
		}
		log.Infof("%s... took %s", trim(stmt, 32), time.Since(startTime))
	}
	return nil
}

// findLanguageAndOSVulnsAdded gets added vulnerabilities in the new database
func (d *DBDiffer) findLanguageAndOSVulnsAdded(diffs map[pkgKey]*PackageDiff) (int, error) {
	var rows []pkgRow
	err := d.db.Raw(`
		SELECT * FROM pkg_diff_added
	`).Scan(&rows).Error
	if err != nil {
		return 0, err
	}
	for _, r := range rows {
		vulnerabilityAdded(diffs, r.Ecosystem, r.PkgName, "", r.ProviderID, r.VulnName)
	}
	return len(rows), nil
}

// findLanguageAndOSVulnsRemoved gets removed vulnerabilities in the new database
func (d *DBDiffer) findLanguageAndOSVulnsRemoved(diffs map[pkgKey]*PackageDiff) (int, error) {
	var rows []pkgRow
	err := d.db.Raw(`
		SELECT * FROM pkg_diff_removed
	`).Scan(&rows).Error
	if err != nil {
		return 0, err
	}
	for _, r := range rows {
		vulnerabilityRemoved(diffs, r.Ecosystem, r.PkgName, "", r.ProviderID, r.VulnName)
	}
	return len(rows), nil
}

// findLanguageAndOSVulnsModified gets modified packages / vulnerabilities in the new database
func (d *DBDiffer) findLanguageAndOSVulnsModified(diffs map[pkgKey]*PackageDiff) (int, error) {
	var rows []pkgRow
	err := d.db.Raw(`
		SELECT * FROM pkg_diff_modified
	`).Scan(&rows).Error
	if err != nil {
		return 0, err
	}
	for _, r := range rows {
		vulnerabilityModified(diffs, r.Ecosystem, r.PkgName, "", r.ProviderID, r.VulnName)
	}
	return len(rows), nil
}

// findCPEVulnsAdded finds added CPE-based vulnerabilities
func (d *DBDiffer) findCPEVulnsAdded(diffs map[pkgKey]*PackageDiff) (int, error) {
	var rows []cpeRow
	err := d.db.Raw(`
		SELECT * FROM cpe_diff_added
	`).Scan(&rows).Error
	if err != nil {
		return 0, err
	}
	for _, r := range rows {
		vulnerabilityAdded(diffs, cpeEcosystem, r.Product, r.cpeString(), r.ProviderID, r.VulnName)
	}
	return len(rows), nil
}

// findCPEVulnsRemoved finds removed CPE-based vulnerabilities
func (d *DBDiffer) findCPEVulnsRemoved(diffs map[pkgKey]*PackageDiff) (int, error) {
	var rows []cpeRow
	err := d.db.Raw(`
		SELECT * FROM cpe_diff_removed
	`).Scan(&rows).Error
	if err != nil {
		return 0, err
	}
	for _, r := range rows {
		vulnerabilityRemoved(diffs, cpeEcosystem, r.Product, r.cpeString(), r.ProviderID, r.VulnName)
	}
	return len(rows), nil
}

// findCPEVulnsModified finds removed CPE-based vulnerabilities
func (d *DBDiffer) findCPEVulnsModified(diffs map[pkgKey]*PackageDiff) (int, error) {
	var rows []cpeRow
	err := d.db.Raw(`
		SELECT * FROM cpe_diff_modified
	`).Scan(&rows).Error
	if err != nil {
		return 0, err
	}
	for _, r := range rows {
		vulnerabilityModified(diffs, cpeEcosystem, r.Product, r.cpeString(), r.ProviderID, r.VulnName)
	}
	return len(rows), nil
}

func (d *DBDiffer) prepareTemplates(templates []string, r *strings.Replacer) []string {
	var out []string
	for _, template := range templates {
		stmt := r.Replace(template)

		if d.config.Debug {
			if tableCreate.MatchString(stmt) {
				table := tableCreate.FindStringSubmatch(stmt)[1]
				if d.db.Exec(fmt.Sprintf("SELECT 1 from %s", table)).Error == nil {
					log.Debugf("skipping table creation for existing table %s", table)
					continue
				}
				out = append(out,
					"DROP TABLE IF EXISTS "+table,
					strings.Replace(stmt, "TEMP", "", 1),
				)
			}
			if indexCreate.MatchString(stmt) {
				index := indexCreate.FindStringSubmatch(stmt)[1]
				count := 0
				s := d.db.Raw(fmt.Sprintf("SELECT 1 from sqlite_master WHERE type = 'index' AND name = '%s'", index))
				if s.Scan(&count).Error == nil && count > 0 {
					log.Debugf("skipping index creation for existing index %s", index)
					continue
				}
				out = append(out, stmt)
			}
			if viewCreate.MatchString(stmt) {
				view := viewCreate.FindStringSubmatch(stmt)[1]
				if d.db.Exec(fmt.Sprintf("SELECT 1 from %s", view)).Error == nil {
					log.Debugf("skipping view creation for existing view %s", view)
					return nil
				}
				out = append(out,
					"DROP VIEW IF EXISTS "+view,
					strings.Replace(stmt, "TEMP", "", 1),
				)
			}
		} else {
			out = append(out, stmt)
		}
	}
	return out
}

func (d *DBDiffer) createVulnsTables() error {
	startTime := time.Now()
	if err := d.createDiffTablesVulns("old", "main"); err != nil {
		return fmt.Errorf("failed to create old vuln diff tables: %w", err)
	}
	if err := d.createDiffTablesVulns("new", "new_db"); err != nil {
		return fmt.Errorf("failed to create new vuln diff tables: %w", err)
	}
	if err := d.createDiffViewsVulns(); err != nil {
		return fmt.Errorf("failed to create vuln diff views: %w", err)
	}
	log.Infof("created vuln diff tables in %s", time.Since(startTime))
	return nil
}

func (d *DBDiffer) findKevDiffs() (map[string]struct{}, error) {
	startTime := time.Now()
	out := map[string]struct{}{}

	var rows []string

	err := d.db.Raw(`
		SELECT cve from diff_new_kev n
		WHERE NOT EXISTS (
			SELECT 1 from diff_old_kev o where o.cve = n.cve
	    )
		UNION
		SELECT cve from diff_old_kev o
		WHERE NOT EXISTS (
			SELECT 1 from diff_new_kev n where n.cve = o.cve
	    )
	    `).Scan(&rows).Error
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		out[r] = struct{}{}
	}

	log.Infof("found kev diff in %s", time.Since(startTime))
	return out, nil
}

func (d *DBDiffer) findEpssDiffs() (map[string]struct{}, error) {
	err := d.createDiffTablesEPSS("old", "main")
	if err != nil {
		return nil, err
	}

	err = d.createDiffTablesEPSS("new", "new_db")
	if err != nil {
		return nil, err
	}

	startTime := time.Now()
	out := map[string]struct{}{}

	var rows []string

	err = d.db.Raw(`
		SELECT n.cve FROM diff_new_epss n
		WHERE NOT EXISTS (
			SELECT 1 FROM diff_old_epss o where o.cve = n.cve
	    )
		UNION
		SELECT o.cve FROM diff_old_epss o
		WHERE NOT EXISTS (
			SELECT 1 FROM diff_new_epss n where o.cve = n.cve
	    )
		UNION
		SELECT o.cve FROM diff_old_epss o
		JOIN diff_new_epss n ON o.cve = n.cve
		WHERE ABS(n.epss - o.epss) > ?
		OR ABS(n.percentile - o.percentile) > ?
	    `, d.config.EPSSThreshold, d.config.EPSSThreshold).Scan(&rows).Error
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		out[r] = struct{}{}
	}

	log.Infof("found epss diff in %s", time.Since(startTime))
	return out, nil
}

func applyChange(diffs map[pkgKey]*PackageDiff, pkgEcosystem, pkgName, pkgCPE, providerID, vulnName string, applyChangeFn func(*PackageDiff, VulnerabilityID)) {
	key := pkgKey{
		Ecosystem: pkgEcosystem,
		Name:      pkgName,
		CPE:       pkgCPE,
	}
	pd := diffs[key]
	if pd == nil {
		pd = &PackageDiff{
			Ecosystem: pkgEcosystem,
			Name:      pkgName,
			CPE:       pkgCPE,
		}
		diffs[key] = pd
	}
	applyChangeFn(pd, VulnerabilityID{ID: vulnName, Provider: providerID})
}

func vulnerabilityAdded(diffs map[pkgKey]*PackageDiff, pkgEcosystem, pkgName, pkgCPE, providerID, vulnName string) {
	applyChange(diffs, pkgEcosystem, pkgName, pkgCPE, providerID, vulnName, func(pd *PackageDiff, entry VulnerabilityID) {
		pd.Vulnerabilities.Added = appendUniqueEntry(pd.Vulnerabilities.Added, entry)
	})
}

func vulnerabilityModified(diffs map[pkgKey]*PackageDiff, pkgEcosystem, pkgName, pkgCPE, providerID, vulnName string) {
	applyChange(diffs, pkgEcosystem, pkgName, pkgCPE, providerID, vulnName, func(pd *PackageDiff, entry VulnerabilityID) {
		pd.Vulnerabilities.Modified = appendUniqueEntry(pd.Vulnerabilities.Modified, entry)
	})
}

func vulnerabilityRemoved(diffs map[pkgKey]*PackageDiff, pkgEcosystem, pkgName, pkgCPE, providerID, vulnName string) {
	applyChange(diffs, pkgEcosystem, pkgName, pkgCPE, providerID, vulnName, func(pd *PackageDiff, entry VulnerabilityID) {
		pd.Vulnerabilities.Removed = appendUniqueEntry(pd.Vulnerabilities.Removed, entry)
	})
}

func appendUniqueEntry(entries []VulnerabilityID, entry VulnerabilityID) []VulnerabilityID {
	for _, e := range entries {
		if e.ID == entry.ID && e.Provider == entry.Provider {
			return entries
		}
	}
	return append(entries, entry)
}

func parallel[T any](f1 func() (T, error), f2 func() (T, error)) (T, T, error) {
	var out1, out2 T
	var err1, err2 error
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		out1, err1 = f1()
	}()

	go func() {
		defer wg.Done()
		out2, err2 = f2()
	}()

	wg.Wait()

	return out1, out2, errors.Join(err1, err2)
}

func trim(stmt string, maxLen int) string {
	if len(stmt) > maxLen {
		return stmt[:maxLen-2] + ".."
	}
	return stmt
}

type pkgRow struct {
	Ecosystem  string `gorm:"column:ecosystem"`
	PkgName    string `gorm:"column:pkg_name"`
	ProviderID string `gorm:"column:provider_id"`
	VulnName   string `gorm:"column:vuln_name"`
}

type vulnRow struct {
	ProviderID string `gorm:"column:provider_id"`
	VulnName   string `gorm:"column:name"`
}

type cpeRow struct {
	Part      string `gorm:"column:part"`
	Vendor    string `gorm:"column:vendor"`
	Product   string `gorm:"column:product"`
	Edition   string `gorm:"column:edition"`
	Language  string `gorm:"column:language"`
	SWEdition string `gorm:"column:sw_edition"`
	TargetHW  string `gorm:"column:target_hw"`
	TargetSW  string `gorm:"column:target_sw"`
	Other     string `gorm:"column:other"`

	VulnName   string `gorm:"column:vuln_name"`
	ProviderID string `gorm:"column:provider_id"`
}

func (r cpeRow) cpeString() string {
	c := cpe.Attributes{
		Part:      r.Part,
		Vendor:    r.Vendor,
		Product:   r.Product,
		Version:   "",
		Update:    "",
		Edition:   r.Edition,
		SWEdition: r.SWEdition,
		TargetSW:  r.TargetSW,
		TargetHW:  r.TargetHW,
		Other:     r.Other,
		Language:  r.Language,
	}
	return c.String()
}

var (
	tableCreate = regexp.MustCompile(`TEMP\s+TABLE\s+([_a-zA-Z0-9{}]+)\s+`)
	indexCreate = regexp.MustCompile(`CREATE\s+INDEX\s+([_a-zA-Z0-9{}]+)\s+`)
	viewCreate  = regexp.MustCompile(`TEMP\s+VIEW\s+([_a-zA-Z0-9{}]+)\s+`)
)

func closeLowLevelDB(db *gorm.DB) {
	if sqlDB, err := db.DB(); err == nil && sqlDB != nil {
		_ = sqlDB.Close()
	}
}
