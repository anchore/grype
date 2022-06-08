package gormadapter

import (
	"fmt"
	"os"

	"gorm.io/gorm"

	"github.com/anchore/sqlite"
)

var connectStatements = []string{
	// performance improvements (note: will result in lost data on write interruptions).
	// on my box it reduces the time to write from 10 minutes to 10 seconds (with ~1GB memory utilization spikes)
	`PRAGMA synchronous = OFF`,
	`PRAGMA journal_mode = MEMORY`,
}

// Open a new connection to a sqlite3 database file
func Open(path string, overwrite bool) (*gorm.DB, error) {
	if overwrite {
		// the file may or may not exist, so we ignore the error explicitly
		_ = os.Remove(path)
	}

	connStr, err := connectionString(path)
	if err != nil {
		return nil, err
	}

	dbObj, err := gorm.Open(sqlite.Open(connStr), &gorm.Config{Logger: newLogger()})
	if err != nil {
		return nil, fmt.Errorf("unable to connect to DB: %w", err)
	}

	for _, sqlStmt := range connectStatements {
		dbObj.Exec(sqlStmt)
		if dbObj.Error != nil {
			return nil, fmt.Errorf("unable to execute (%s): %w", sqlStmt, dbObj.Error)
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
