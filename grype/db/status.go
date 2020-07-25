package db

import "time"

type Status struct {
	Age                   time.Time
	CurrentSchemaVersion  int
	RequiredSchemeVersion int
	Location              string
	Err                   error
}
