package entry

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/anchore/grype/internal/log"
)

var readOptions = []string{
	"immutable=1",
	"cache=shared",
	"mode=ro",
}

// note: the name of the struct is tied to the table name
type results struct {
	ID     string `gorm:"column:id"`
	Record []byte `gorm:"column:record"`
}

type bytesOpener struct {
	contents []byte
	name     string
}

type errorOpener struct {
	err error
}

func sqliteEntryCount(resultPaths []string) (int64, error) {
	var dbPath string
	for _, p := range resultPaths {
		// we should only be validating against a single results DB, not any DB in the output
		if strings.HasSuffix(p, "results.db") {
			dbPath = p
			break
		}
	}

	if dbPath == "" {
		return 0, fmt.Errorf("unable to find DB result file")
	}

	db, err := openDB(dbPath)
	if err != nil {
		return 0, err
	}

	var count int64
	db.Model(&results{}).Count(&count)

	return count, nil
}

func sqliteOpeners(resultPaths []string) (<-chan Opener, int64, error) {
	var dbPath string
	for _, p := range resultPaths {
		if strings.HasSuffix(p, "results.db") {
			dbPath = p
			break
		}
	}

	if dbPath == "" {
		return nil, 0, fmt.Errorf("unable to find DB result file")
	}

	db, err := openDB(dbPath)
	if err != nil {
		return nil, 0, err
	}

	var count int64
	db.Model(&results{}).Count(&count)

	openers := make(chan Opener)
	go func() {
		defer close(openers)

		var models []results

		current := 0
		check := db.FindInBatches(&models, 100, func(_ *gorm.DB, _ int) error {
			for _, result := range models {
				openers <- bytesOpener{
					contents: result.Record,
					name:     result.ID,
				}
			}

			current += len(models)

			// log.WithFields("count", current).Trace("records read from the provider cache DB")

			// note: returning an error will stop future batches
			return nil
		})

		if check.Error != nil {
			openers <- errorOpener{err: check.Error}
		}
	}()
	return openers, count, nil
}

func (e bytesOpener) Open() (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(e.contents)), nil
}

func (e bytesOpener) String() string {
	return e.name
}

func (e errorOpener) Open() (io.ReadCloser, error) {
	return nil, e.err
}

func (e errorOpener) String() string {
	return e.err.Error()
}

// Open a new connection to a sqlite3 database file
func openDB(path string) (*gorm.DB, error) {
	connStr, err := connectionString(path)
	if err != nil {
		return nil, err
	}

	// &immutable=1&cache=shared&mode=ro
	for _, o := range readOptions {
		connStr += fmt.Sprintf("&%s", o)
	}

	dbObj, err := gorm.Open(sqlite.Open(connStr), &gorm.Config{Logger: newLogger()})
	if err != nil {
		return nil, fmt.Errorf("unable to connect to DB: %w", err)
	}

	return dbObj, nil
}

// ConnectionString creates a connection string for sqlite3
func connectionString(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("no db filepath given")
	}
	return fmt.Sprintf("file:%s?cache=shared", path), nil
}

type logAdapter struct{}

func newLogger() logger.Interface {
	return logAdapter{}
}

func (l logAdapter) LogMode(logger.LogLevel) logger.Interface {
	return l
}

func (l logAdapter) Info(_ context.Context, _ string, _ ...interface{}) {
	// unimplemented
}

func (l logAdapter) Warn(_ context.Context, fmt string, v ...interface{}) {
	log.Warnf("gorm: "+fmt, v...)
}

func (l logAdapter) Error(_ context.Context, fmt string, v ...interface{}) {
	log.Errorf("gorm: "+fmt, v...)
}

func (l logAdapter) Trace(_ context.Context, _ time.Time, _ func() (_ string, _ int64), _ error) {
	// unimplemented
}
