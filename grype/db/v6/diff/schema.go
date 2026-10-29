package diff

import "fmt"

// SchemaVersion is the schema version for the `db diff` command
const SchemaVersion = "0.6.0"

var Schema = fmt.Sprintf("anchore.io/schema/grype/db-diff/json/%s/results", SchemaVersion)

// Changelog:
// 0.5.0 - Initial schema
// 0.6.0 - (breaking) before/after follow the order the databases were provided (previously they were sorted
//         chronologically, which disagreed with the diff direction when the newer database was given first)
