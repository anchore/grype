package writer

import (
	"fmt"
	"os"

	"github.com/jinzhu/gorm"
)

var connectStatements = []string{
	// performance improvements (note: will result in lost data on write interruptions).
	// on my box it reduces the time to write from 10 minutes to 10 seconds (with ~1GB memory utilization spikes)
	`PRAGMA synchronous = OFF`,
	`PRAGMA journal_mode = MEMORY`,
}

// config defines the information needed to connect and create a sqlite3 database
type config struct {
	DbPath    string
	Overwrite bool
}

// ConnectionString creates a connection string for sqlite3
func (o config) ConnectionString() (string, error) {
	if o.DbPath == "" {
		return "", fmt.Errorf("no db filepath given")
	}
	return fmt.Sprintf("file:%s?cache=shared", o.DbPath), nil
}

// open a new connection to a sqlite3 database file
func open(cfg config) (*gorm.DB, error) {
	if cfg.Overwrite {
		// the file may or may not exist, so we ignore the error explicitly
		_ = os.Remove(cfg.DbPath)
	}

	connStr, err := cfg.ConnectionString()
	if err != nil {
		return nil, err
	}

	dbObj, err := gorm.Open("sqlite3", connStr)
	if err != nil {
		return nil, fmt.Errorf("unable to connect to DB: %w", err)
	}

	dbObj.SetLogger(&logAdapter{})

	for _, sqlStmt := range connectStatements {
		dbObj.Exec(sqlStmt)
		if dbObj.Error != nil {
			return nil, fmt.Errorf("unable to execute (%s): %w", sqlStmt, dbObj.Error)
		}
	}
	return dbObj, nil
}
