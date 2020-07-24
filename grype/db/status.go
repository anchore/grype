package db

import "time"

type Status struct {
	Age              time.Time
	SchemaVersion    string
	SchemaConstraint string
	Location         string
	Err              error
}
