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

// Open a new connection to a sqlite3 database file
func Open(path string, write bool) (*gorm.DB, error) {
	memory := len(path) == 0

	if write && !memory {
		if _, err := os.Stat(path); err == nil {
			if err := os.Remove(path); err != nil {
				return nil, fmt.Errorf("unable to remove existing DB file: %w", err)
			}
		}
	}

	if memory {
		path = ":memory:"
	}

	connStr, err := connectionString(path)
	if err != nil {
		return nil, err
	}

	if !write {
		// &immutable=1&cache=shared&mode=ro
		for _, o := range readOptions {
			connStr += fmt.Sprintf("&%s", o)
		}
	}

	dbObj, err := gorm.Open(sqlite.Open(connStr), &gorm.Config{Logger: newLogger()})
	if err != nil {
		return nil, fmt.Errorf("unable to connect to DB: %w", err)
	}

	if write {
		for _, sqlStmt := range writerStatements {
			dbObj.Exec(sqlStmt)
			if dbObj.Error != nil {
				return nil, fmt.Errorf("unable to execute (%s): %w", sqlStmt, dbObj.Error)
			}
		}
	}

	return dbObj, nil
}

// ConnectionString creates a connection string for sqlite3
func connectionString(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("no db filepath given")
	}
	return fmt.Sprintf("file:%s?cache=shared", path), nil
}
