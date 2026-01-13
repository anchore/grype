package data

// Entry is a data structure responsible for capturing an individual writable entry from a data.Processor (written by a data.Writer).
type Entry struct {
	DBSchemaVersion int
	// Data is the specific payload that should be written (usually a grype-db v*.Entry struct)
	Data interface{}
}
