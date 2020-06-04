package db

import (
	"github.com/anchore/vulnscan-db/pkg/db"
	"github.com/anchore/vulnscan-db/pkg/sqlite"
)

func GetStore() db.VulnStore {
	// TODO: add connection options and info
	// TODO: we are ignoreing cleanup/close function (not good)
	store, _, err := sqlite.NewStore(nil)
	if err != nil {
		// TODO: replace me
		panic(err)
	}
	return store
}
