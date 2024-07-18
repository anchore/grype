package v6

import (
	"fmt"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"log"
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

func newState(dbFilePath string, overwrite bool) (*state, error) {
	//db, err := gormadapter.Open(dbFilePath, overwrite)
	//if err != nil {
	//	return nil, err
	//}

	lgr := logger.New(log.New(os.Stdout, "\r\n", log.LstdFlags), logger.Config{
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

	if overwrite {
		if err := db.AutoMigrate(All()...); err != nil {
			return nil, fmt.Errorf("unable to migrate: %w", err)
		}
	}

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
		write:        overwrite,
		useMem:       useMem,
	}, nil
}

func (s *state) close() error {
	if s.write {
		if s.useMem {
			return s.db.Exec(fmt.Sprintf("VACUUM main into %q", s.destination)).Error
		}
		return s.db.Exec("VACUUM").Error
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
