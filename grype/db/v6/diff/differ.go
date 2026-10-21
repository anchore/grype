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

// NewDBDiffer resolves the databases from the config and returns a new DBDiffer for database comparison
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

	// the attached database, temp tables, and pragmas are all per-connection, so every statement must run on the same one
	sqlDB, err := db.DB()
	if err != nil {
		closeLowLevelDB(db)
		return nil, fmt.Errorf("failed to configure database: %w", err)
	}
	sqlDB.SetMaxOpenConns(1)

	// allow sqlite to use worker threads when sorting (e.g. to build indexes)
	if err := db.Exec("PRAGMA threads = 4").Error; err != nil {
		closeLowLevelDB(db)
		return nil, fmt.Errorf("failed to configure database: %w", err)
	}

	if err := db.Exec("ATTACH DATABASE ? AS new_db", newDBPath).Error; err != nil {
		closeLowLevelDB(db)
		return nil, fmt.Errorf("failed to attach new database: %w", err)
	}

	beforeTime, err := time.Parse(time.RFC3339, oldDB.Info.BuildTimestamp)
	if err != nil {
		closeLowLevelDB(db)
		return nil, fmt.Errorf("failed to parse build timestamp: %w", err)
	}
	afterTime, err := time.Parse(time.RFC3339, newDB.Info.BuildTimestamp)
	if err != nil {
		closeLowLevelDB(db)
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
	// always release the connection, even if the detach fails (an open handle keeps the db files locked on windows)
	defer closeLowLevelDB(d.db)
	if err := d.db.Exec("DETACH DATABASE new_db").Error; err != nil {
		return fmt.Errorf("failed to detach new database: %w", err)
	}
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
	diffs := newPackageDiffs()

	changeTypes := []struct {
		name string
		fn   func(*packageDiffs) (int, error)
	}{
		{"added package vulnerabilities", d.packageChanges("diff_pkg_added", changeAdded)},
		{"removed package vulnerabilities", d.packageChanges("diff_pkg_removed", changeRemoved)},
		{"modified package vulnerabilities", d.packageChanges("diff_pkg_modified", changeModified)},
		{"added CPE vulnerabilities", d.cpeChanges("diff_cpe_added", changeAdded)},
		{"removed CPE vulnerabilities", d.cpeChanges("diff_cpe_removed", changeRemoved)},
		{"modified CPE vulnerabilities", d.cpeChanges("diff_cpe_modified", changeModified)},
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

	packages := make([]PackageDiff, 0, len(diffs.byKey))
	for _, pd := range diffs.byKey {
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
	if err := d.createDiffKeyTablesPackages(); err != nil {
		return fmt.Errorf("failed to create package key tables: %w", err)
	}
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

func (d *DBDiffer) packageChanges(view string, change changeType) func(*packageDiffs) (int, error) {
	return func(diffs *packageDiffs) (int, error) {
		return d.findPackageChanges(view, change, diffs)
	}
}

func (d *DBDiffer) cpeChanges(view string, change changeType) func(*packageDiffs) (int, error) {
	return func(diffs *packageDiffs) (int, error) {
		return d.findCPEChanges(view, change, diffs)
	}
}

// findPackageChanges adds the changes in the given package view (diff_pkg_added, diff_pkg_removed, or diff_pkg_modified)
func (d *DBDiffer) findPackageChanges(view string, change changeType, diffs *packageDiffs) (int, error) {
	var r pkgRow
	return d.forEachRow(`SELECT COALESCE(ecosystem, ''), COALESCE(pkg_name, ''), provider_id, vuln_name FROM `+view,
		[]any{&r.Ecosystem, &r.PkgName, &r.ProviderID, &r.VulnName},
		func() {
			diffs.add(change, r.Ecosystem, r.PkgName, "", r.ProviderID, r.VulnName)
		})
}

// findCPEChanges adds the changes in the given CPE view (diff_cpe_added, diff_cpe_removed, or diff_cpe_modified)
func (d *DBDiffer) findCPEChanges(view string, change changeType, diffs *packageDiffs) (int, error) {
	var r cpeRow
	return d.forEachRow(`SELECT COALESCE(part, ''), COALESCE(vendor, ''), COALESCE(product, ''), COALESCE(edition, ''),
			COALESCE(language, ''), COALESCE(sw_edition, ''), COALESCE(target_hw, ''), COALESCE(target_sw, ''),
			COALESCE(other, ''), provider_id, vuln_name
		FROM `+view,
		[]any{&r.Part, &r.Vendor, &r.Product, &r.Edition, &r.Language, &r.SWEdition, &r.TargetHW, &r.TargetSW, &r.Other, &r.ProviderID, &r.VulnName},
		func() {
			diffs.add(change, cpeEcosystem, r.Product, r.cpeString(), r.ProviderID, r.VulnName)
		})
}

// forEachRow scans each row of the query into dest and calls fn, without holding all rows in memory at once (a diff
// can contain millions of rows). fn must not query the database: the open rows hold the only connection, so a nested
// query would block forever.
func (d *DBDiffer) forEachRow(query string, dest []any, fn func()) (int, error) {
	rows, err := d.db.Raw(query).Rows()
	if err != nil {
		return 0, err
	}
	defer log.CloseAndLogError(rows, query)

	count := 0
	for rows.Next() {
		if err := rows.Scan(dest...); err != nil {
			return count, err
		}
		fn()
		count++
	}
	return count, rows.Err()
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
				// views are cheap to create, and must remain temporary since they reference the attached new_db
				out = append(out, stmt)
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
		SELECT cve from diff_kev_new n
		WHERE NOT EXISTS (
			SELECT 1 from diff_kev_old o where o.cve = n.cve
	    )
		UNION
		SELECT cve from diff_kev_old o
		WHERE NOT EXISTS (
			SELECT 1 from diff_kev_new n where n.cve = o.cve
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
		SELECT n.cve FROM diff_epss_new n
		WHERE NOT EXISTS (
			SELECT 1 FROM diff_epss_old o where o.cve = n.cve
	    )
		UNION
		SELECT o.cve FROM diff_epss_old o
		WHERE NOT EXISTS (
			SELECT 1 FROM diff_epss_new n where o.cve = n.cve
	    )
		UNION
		SELECT o.cve FROM diff_epss_old o
		JOIN diff_epss_new n ON o.cve = n.cve
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

type changeType int

const (
	changeAdded changeType = iota
	changeRemoved
	changeModified
)

type pkgChange struct {
	pkg    pkgKey
	change changeType
	vuln   VulnerabilityID
}

// packageDiffs collects the per-package/CPE diff entries
type packageDiffs struct {
	byKey map[pkgKey]*PackageDiff
	// seen holds the CPE changes that have been added: rows from the package views are unique (each is a distinct
	// vulnerability + package), but different CPEs may be represented by the same CPE string
	seen map[pkgChange]struct{}
	// strings interns the provider and vulnerability names, which repeat across many packages
	strings map[string]string
}

func newPackageDiffs() *packageDiffs {
	return &packageDiffs{
		byKey:   map[pkgKey]*PackageDiff{},
		seen:    map[pkgChange]struct{}{},
		strings: map[string]string{},
	}
}

func (p *packageDiffs) intern(s string) string {
	if v, ok := p.strings[s]; ok {
		return v
	}
	p.strings[s] = s
	return s
}

func (p *packageDiffs) add(change changeType, pkgEcosystem, pkgName, pkgCPE, providerID, vulnName string) {
	key := pkgKey{
		Ecosystem: pkgEcosystem,
		Name:      pkgName,
		CPE:       pkgCPE,
	}
	entry := VulnerabilityID{ID: p.intern(vulnName), Provider: p.intern(providerID)}

	if pkgCPE != "" {
		c := pkgChange{pkg: key, change: change, vuln: entry}
		if _, ok := p.seen[c]; ok {
			return
		}
		p.seen[c] = struct{}{}
	}

	pd := p.byKey[key]
	if pd == nil {
		pd = &PackageDiff{
			Ecosystem: pkgEcosystem,
			Name:      pkgName,
			CPE:       pkgCPE,
		}
		p.byKey[key] = pd
	}

	switch change {
	case changeAdded:
		pd.Vulnerabilities.Added = append(pd.Vulnerabilities.Added, entry)
	case changeRemoved:
		pd.Vulnerabilities.Removed = append(pd.Vulnerabilities.Removed, entry)
	case changeModified:
		pd.Vulnerabilities.Modified = append(pd.Vulnerabilities.Modified, entry)
	}
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
	Ecosystem  string
	PkgName    string
	ProviderID string
	VulnName   string
}

type vulnRow struct {
	ProviderID string `gorm:"column:provider_id"`
	VulnName   string `gorm:"column:name"`
}

type cpeRow struct {
	Part      string
	Vendor    string
	Product   string
	Edition   string
	Language  string
	SWEdition string
	TargetHW  string
	TargetSW  string
	Other     string

	VulnName   string
	ProviderID string
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
