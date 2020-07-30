package db

import "time"

type Status struct {
	Age                   time.Time
	CurrentSchemaVersion  int
	RequiredSchemaVersion int
	Location              string
	Err                   error
}
