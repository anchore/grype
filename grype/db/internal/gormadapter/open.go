package gormadapter

import (
	"fmt"
	"os"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

var writerStatements = []string{
	// performance improvements (note: will result in lost data on write interruptions).
	// on my box it reduces the time to write from 10 minutes to 10 seconds (with ~1GB memory utilization spikes)
	`PRAGMA synchronous = OFF`,
	`PRAGMA journal_mode = MEMORY`,
	`PRAGMA cache_size = 100000`,
	`PRAGMA mmap_size = 268435456`, // 256 MB
}

var readOptions = []string{
	"immutable=1",
	"cache=shared",
	"mode=ro",
}

type config struct {
	path   string
	write  bool
	memory bool
}

type Option func(*config)

func WithTruncate(truncate bool) Option {
	return func(c *config) {
		c.write = truncate
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

func (c config) shouldTruncate() bool {
	return c.write && !c.memory
}

func (c config) connectionString() string {
	var conn string
	if c.path == "" {
		conn = ":memory:"
	} else {
		conn = fmt.Sprintf("file:%s?cache=shared", c.path)
	}

	if !c.write && !c.memory {
		// &immutable=1&cache=shared&mode=ro
		for _, o := range readOptions {
			conn += fmt.Sprintf("&%s", o)
		}
	}
	return conn
}

// Open a new connection to a sqlite3 database file
func Open(path string, options ...Option) (*gorm.DB, error) {
	cfg := newConfig(path, options)

	if cfg.shouldTruncate() {
		if _, err := os.Stat(path); err == nil {
			if err := os.Remove(path); err != nil {
				return nil, fmt.Errorf("unable to remove existing DB file: %w", err)
			}
		}
	}

	dbObj, err := gorm.Open(sqlite.Open(cfg.connectionString()), &gorm.Config{Logger: newLogger()})
	if err != nil {
		return nil, fmt.Errorf("unable to connect to DB: %w", err)
	}

	if cfg.write {
		for _, sqlStmt := range writerStatements {
			dbObj.Exec(sqlStmt)
			if dbObj.Error != nil {
				return nil, fmt.Errorf("unable to execute (%s): %w", sqlStmt, dbObj.Error)
			}
		}
	}

	// needed for v6+
	dbObj.Exec("PRAGMA foreign_keys = ON")

	return dbObj, nil
}
