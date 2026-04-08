package diff

import "fmt"

// SchemaVersion is the schema version for the `db diff` command
const SchemaVersion = "0.5.0"

var Schema = fmt.Sprintf("anchore.io/schema/grype/db-diff/json/%s/results", SchemaVersion)

// Changelog:
// 0.5.0 - Initial schema
