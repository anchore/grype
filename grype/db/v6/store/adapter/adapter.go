package adapter

import (
	"database/sql"
	"github.com/anchore/grype/grype/db/v6/store/repository"
)

type Adapter struct {
	db  *sql.DB
	API *repository.Queries
}

func New(db *sql.DB) *Adapter {
	return &Adapter{
		db:  db,
		API: repository.New(db),
	}
}
