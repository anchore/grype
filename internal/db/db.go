package db

import "github.com/anchore/vulnscan-db/pkg/db"

func GetStoreFromSqlite() *db.SqliteStore {
	return db.NewSqliteStore(nil)
}
