package gormadapter

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"github.com/anchore/grype/internal/log"
)

var commonStatements = []string{
	`PRAGMA foreign_keys = ON`, // needed for v6+
}

var writerStatements = []string{
	// performance improvements (note: will result in lost data on write interruptions)
	`PRAGMA synchronous = OFF`,     // minimize the amount of syncing to disk, prioritizing write performance over durability
	`PRAGMA journal_mode = MEMORY`, // do not write the journal to disk (maximizing write performance); OFF is faster but less safe in terms of DB consistency
}

var heavyWriteStatements = []string{
	`PRAGMA cache_size = -1073741824`, // ~1 GB (negative means treat as bytes not page count); one caveat is to not pick a value that risks swapping behavior, negating performance gains
	`PRAGMA mmap_size = 1073741824`,   // ~1 GB; the maximum size of the memory-mapped I/O buffer (to access the database file as if it were a part of the process’s virtual memory)
	`PRAGMA defer_foreign_keys = ON`,  // defer enforcement of foreign key constraints until the end of the transaction (to avoid the overhead of checking constraints for each row)
}

var readConnectionOptions = []string{
	"immutable=1",  // indicates that the database file is guaranteed not to change during the connection’s lifetime (slight performance benefit for read-only cases)
	"mode=ro",      // opens the database in as read-only (an enforcement mechanism to allow immutable=1 to be effective)
	"cache=shared", // multiple database connections within the same process share a single page cache
}

type config struct {
	debug                     bool
	path                      string
	writable                  bool
	truncate                  bool
	allowLargeMemoryFootprint bool
	models                    []any
	initialData               []any
	memory                    bool
	statements                []string
}

type Option func(*config)

func WithDebug(debug bool) Option {
	return func(c *config) {
		c.debug = debug
	}
}

func WithTruncate(truncate bool, models []any, initialData []any) Option {
	return func(c *config) {
		c.truncate = truncate
		if truncate {
			c.writable = true
			c.models = models
			c.initialData = initialData
			c.allowLargeMemoryFootprint = true
		}
	}
}

func WithStatements(statements ...string) Option {
	return func(c *config) {
		c.statements = append(c.statements, statements...)
	}
}

func WithModels(models []any) Option {
	return func(c *config) {
		c.models = append(c.models, models...)
	}
}

func WithWritable(write bool, models []any) Option {
	return func(c *config) {
		c.writable = write
		c.models = models
	}
}

func WithLargeMemoryFootprint(largeFootprint bool) Option {
	return func(c *config) {
		c.allowLargeMemoryFootprint = largeFootprint
	}
}

func newConfig(path string, opts []Option) config {
	c := config{}
	c.apply(path, opts)
	return c
}

func (c *config) apply(path string, opts []Option) {
	for _, o := range opts {
		o(c)
	}
	c.memory = len(path) == 0
	c.path = path
}

func (c config) connectionString() string {
	var conn string
	if c.path == "" {
		conn = ":memory:"
	} else {
		conn = fmt.Sprintf("file:%s?cache=shared", c.path)
	}

	if !c.writable && !c.memory {
		if !strings.Contains(conn, "?") {
			conn += "?"
		}
		for _, o := range readConnectionOptions {
			conn += fmt.Sprintf("&%s", o)
		}
	}
	return conn
}

// Open a new connection to a sqlite3 database file
func Open(path string, options ...Option) (*gorm.DB, error) {
	cfg := newConfig(path, options)

	if cfg.truncate && !cfg.writable {
		return nil, fmt.Errorf("cannot truncate a read-only DB")
	}

	if cfg.truncate {
		if err := deleteDB(path); err != nil {
			return nil, err
		}
	}

	dbObj, err := gorm.Open(sqlite.Open(cfg.connectionString()), &gorm.Config{Logger: &logAdapter{
		debug:         cfg.debug,
		slowThreshold: 400 * time.Millisecond,
	}})
	if err != nil {
		return nil, fmt.Errorf("unable to connect to DB: %w", err)
	}

	return cfg.prepareDB(dbObj)
}

func (c config) prepareDB(dbObj *gorm.DB) (*gorm.DB, error) {
	if c.writable {
		log.Debug("using writable DB statements")
		if err := c.applyStatements(dbObj, writerStatements); err != nil {
			return nil, fmt.Errorf("unable to apply DB writer statements: %w", err)
		}
	}

	if c.truncate && c.allowLargeMemoryFootprint {
		log.Debug("using large memory footprint DB statements")
		if err := c.applyStatements(dbObj, heavyWriteStatements); err != nil {
			return nil, fmt.Errorf("unable to apply DB heavy writer statements: %w", err)
		}
	}

	if len(commonStatements) > 0 {
		if err := c.applyStatements(dbObj, commonStatements); err != nil {
			return nil, fmt.Errorf("unable to apply DB common statements: %w", err)
		}
	}

	if len(c.statements) > 0 {
		if err := c.applyStatements(dbObj, c.statements); err != nil {
			return nil, fmt.Errorf("unable to apply DB custom statements: %w", err)
		}
	}

	if len(c.models) > 0 && c.writable {
		log.Debug("applying DB migrations")
		if err := dbObj.AutoMigrate(c.models...); err != nil {
			return nil, fmt.Errorf("unable to migrate: %w", err)
		}
		// now that there are potentially new models and indexes, analyze the DB to ensure the query planner is up-to-date
		if err := dbObj.Exec("ANALYZE").Error; err != nil {
			return nil, fmt.Errorf("unable to analyze DB: %w", err)
		}
	}

	if len(c.initialData) > 0 && c.truncate {
		log.Debug("writing initial data")
		for _, d := range c.initialData {
			if err := dbObj.Create(d).Error; err != nil {
				return nil, fmt.Errorf("unable to create initial data: %w", err)
			}
		}
	}

	if c.debug {
		dbObj = dbObj.Debug()
	}

	return dbObj, nil
}

func (c config) applyStatements(db *gorm.DB, statements []string) error {
	for _, sqlStmt := range statements {
		if err := db.Exec(sqlStmt).Error; err != nil {
			return fmt.Errorf("unable to execute (%s): %w", sqlStmt, err)
		}
		if strings.HasPrefix(sqlStmt, "PRAGMA") {
			name, value, err := c.pragmaNameValue(sqlStmt)
			if err != nil {
				return fmt.Errorf("unable to parse PRAGMA statement: %w", err)
			}

			var result string
			if err := db.Raw("PRAGMA " + name + ";").Scan(&result).Error; err != nil {
				return fmt.Errorf("unable to verify PRAGMA %q: %w", name, err)
			}

			if !strings.EqualFold(result, value) {
				if value == "ON" && result == "1" {
					continue
				}
				if value == "OFF" && result == "0" {
					continue
				}
				return fmt.Errorf("PRAGMA %q was not set to %q (%q)", name, value, result)
			}
		}
	}
	return nil
}

func (c config) pragmaNameValue(sqlStmt string) (string, string, error) {
	sqlStmt = strings.TrimSuffix(strings.TrimSpace(sqlStmt), ";") // remove the trailing semicolon
	if strings.Count(sqlStmt, ";") > 0 {
		return "", "", fmt.Errorf("PRAGMA statements should not contain semicolons: %q", sqlStmt)
	}

	// check if the pragma was set, parse the pragma name and value from the statement. This is because
	// sqlite will not return errors when there are issues with the pragma key or value, but it will
	// be inconsistent with the expected value if you explicitly check
	var name, value string

	clean := strings.TrimPrefix(sqlStmt, "PRAGMA")
	fields := strings.SplitN(clean, "=", 2)
	if len(fields) == 2 {
		name = strings.ToLower(strings.TrimSpace(fields[0]))
		value = strings.TrimSpace(fields[1])
	} else {
		return "", "", fmt.Errorf("unable to parse PRAGMA statement: %q", sqlStmt)
	}

	if c.memory && name == "mmap_size" {
		// memory only DBs do not have mmap capability
		value = ""
	}

	if name == "" {
		return "", "", fmt.Errorf("unable to parse name from PRAGMA statement: %q", sqlStmt)
	}

	return name, value, nil
}

func deleteDB(path string) error {
	if _, err := os.Stat(path); err == nil {
		if err := os.Remove(path); err != nil {
			return fmt.Errorf("unable to remove existing DB file: %w", err)
		}
	}

	parent := filepath.Dir(path)
	if err := os.MkdirAll(parent, 0700); err != nil {
		return fmt.Errorf("unable to create parent directory %q for DB file: %w", parent, err)
	}

	return nil
}
