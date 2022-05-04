package v4

import (
	"time"
)

// ID represents identifying information for a DB and the data it contains.
type ID struct {
	// BuildTimestamp is the timestamp used to define the age of the DB, ideally including the age of the data
	// contained in the DB, not just when the DB file was created.
	BuildTimestamp time.Time
	SchemaVersion  int
}

type IDReader interface {
	GetID() (*ID, error)
}

type IDWriter interface {
	SetID(ID) error
}

func NewID(age time.Time) ID {
	return ID{
		BuildTimestamp: age.UTC(),
		SchemaVersion:  SchemaVersion,
	}
}
