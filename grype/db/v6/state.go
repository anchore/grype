package v6

import (
	"fmt"
	"github.com/anchore/grype/internal/log"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	stdlog "log"
	"os"
	"reflect"
	"sync"
	"time"
)

type state struct {
	db           *gorm.DB
	preloadCache *preloadCache
	destination  string
	write        bool
	useMem       bool
}

//type loggerIgnoreRecordNotFound struct {
//	logger.Interface
//}
//
//func (c loggerIgnoreRecordNotFound) Error(ctx context.Context, msg string, data ...interface{}) {
//	if msg == "record not found" {
//		// Suppress "record not found" messages
//		return
//	}
//	c.Interface.Error(ctx, msg, data...)
//}
//
//func (c loggerIgnoreRecordNotFound) Warn(ctx context.Context, msg string, data ...interface{}) {
//	if msg == "record not found" {
//		// Suppress "record not found" messages
//		return
//	}
//	c.Interface.Warn(ctx, msg, data...)
//}

func newState(dbFilePath string, write bool) (*state, error) {
	//db, err := gormadapter.Open(dbFilePath, write)
	//if err != nil {
	//	return nil, err
	//}

	lgr := logger.New(stdlog.New(os.Stdout, "\r\n", stdlog.LstdFlags), logger.Config{
		SlowThreshold:             200 * time.Millisecond,
		LogLevel:                  logger.Warn,
		IgnoreRecordNotFoundError: true,
		Colorful:                  true,
	})

	useMem := false
	location := dbFilePath
	if useMem {
		location = "file::memory:?cache=shared"
	}

	db, err := gorm.Open(sqlite.Open(location), &gorm.Config{
		Logger: lgr,
	})
	if err != nil {
		fmt.Println("Failed to connect to database:", err)
		return nil, err
	}

	db.Exec("PRAGMA foreign_keys = ON")

	if write {
		if err := db.AutoMigrate(WriteModels()...); err != nil {
			return nil, fmt.Errorf("unable to migrate: %w", err)
		}
	}
	//else {
	//	// TODO: do we need the migrate line at all?
	//	if err := db.AutoMigrate(ReadModels()...); err != nil {
	//		return nil, fmt.Errorf("unable to migrate: %w", err)
	//	}
	//}

	db.Exec("PRAGMA synchronous = OFF")
	db.Exec("PRAGMA journal_mode = OFF")
	db.Exec("PRAGMA temp_store = MEMORY")
	db.Exec("PRAGMA cache_size = 100000")
	db.Exec("PRAGMA mmap_size = 268435456") // 256 MB
	db.Exec("PRAGMA auto_vacuum = NONE")

	return &state{
		db:           db,
		preloadCache: newPreloadCache(),
		destination:  dbFilePath,
		write:        write,
		useMem:       useMem,
	}, nil
}

func (s *state) close() error {
	log.Debug("closing store")
	if s.write {
		if err := s.finalizeBlobsTable(); err != nil {
			return fmt.Errorf("unable to finalize blobs table: %w", err)
		}

		if s.useMem {
			return s.db.Exec(fmt.Sprintf("VACUUM main into %q", s.destination)).Error
		}
		return s.db.Exec("VACUUM").Error
	}
	return nil
}

func (s state) finalizeBlobsTable() error {
	log.Debug("finalizing blobs table")
	// create a temporary table without the 'digest' column
	tempTable := `
		CREATE TABLE temp_blobs (
			id INTEGER PRIMARY KEY,
			value TEXT NOT NULL
		);
	`
	if err := s.db.Exec(tempTable).Error; err != nil {
		return fmt.Errorf("unable to create temporary table: %w", err)
	}

	// copy data from the original table to the temporary table
	copyData := `
		INSERT INTO temp_blobs (id, value)
		SELECT id, value FROM blob_with_digests;
	`
	if err := s.db.Exec(copyData).Error; err != nil {
		return fmt.Errorf("unable to copy data to temporary table: %w", err)
	}

	// drop the original table
	if err := s.db.Migrator().DropTable("blob_with_digests"); err != nil {
		return fmt.Errorf("unable to drop original table: %w", err)
	}

	// rename the temporary table to the original table name
	if err := s.db.Migrator().RenameTable("temp_blobs", "blobs"); err != nil {
		return fmt.Errorf("unable to rename temporary table: %w", err)
	}
	return nil
}

func (s *state) getPreloadableFields(model interface{}) []string {
	t := reflect.TypeOf(model).Elem()

	if fields := s.preloadCache.getPreloadFields(t); fields != nil {
		return fields
	}

	var fields []string
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		fieldType := field.Type

		if isPreloadableField(fieldType) {
			fields = append(fields, field.Name)
		}
	}

	s.preloadCache.setPreloadFields(t, fields)
	return fields
}

func isPreloadableField(t reflect.Type) bool {
	for t.Kind() == reflect.Ptr || t.Kind() == reflect.Slice {
		t = t.Elem()
	}

	switch t.Kind() {
	case reflect.Struct:
		return true
	case reflect.Slice, reflect.Pointer:
		return isPreloadableField(t)
	}

	return false
}

type preloadCache struct {
	mu    sync.RWMutex
	cache map[reflect.Type][]string
}

func newPreloadCache() *preloadCache {
	return &preloadCache{
		cache: make(map[reflect.Type][]string),
	}
}

func (pc *preloadCache) getPreloadFields(t reflect.Type) []string {
	pc.mu.RLock()
	defer pc.mu.RUnlock()
	return pc.cache[t]
}

func (pc *preloadCache) setPreloadFields(t reflect.Type, fields []string) {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	pc.cache[t] = fields
}
