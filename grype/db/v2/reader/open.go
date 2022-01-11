package reader

import (
	"os"

	"github.com/alicebob/sqlittle"
)

// Options defines the information needed to connect and create a sqlite3 database
type config struct {
	dbPath    string
	overwrite bool
}

// Open a new connection to the sqlite3 database file
func Open(cfg *config) (*sqlittle.DB, error) {
	if cfg.overwrite {
		// the file may or may not exist, so we ignore the error explicitly
		_ = os.Remove(cfg.dbPath)
	}

	db, err := sqlittle.Open(cfg.dbPath)
	if err != nil {
		return nil, err
	}

	return db, nil
}
