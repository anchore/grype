package data

// Writer knows how to persist one or more data.Entry objects to a database. Note that the backing implementations
// may take advantage of bulk writes when possible (positively improving performance), which is why multiple
// entries can be written at once.
type Writer interface {
	Write(...Entry) error
	Close() error
}
