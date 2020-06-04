package db

import "github.com/anchore/vulnscan-db/pkg/db"

func GetStore() db.VulnStore {
	// TODO: add connection options and info
	return db.NewSqliteStore(nil)
}
