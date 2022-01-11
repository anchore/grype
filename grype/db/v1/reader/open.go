package reader

import (
	"os"

	"github.com/alicebob/sqlittle"
)

// Options defines the information needed to connect and create a sqlite3 database
type config struct {
	DbPath    string
	Overwrite bool
}

// Open a new connection to the sqlite3 database file
func Open(cfg *config) (*sqlittle.DB, error) {
	if cfg.Overwrite {
		// the file may or may not exist, so we ignore the error explicitly
		_ = os.Remove(cfg.DbPath)
	}

	db, err := sqlittle.Open(cfg.DbPath)
	if err != nil {
		return nil, err
	}

	return db, nil
}
