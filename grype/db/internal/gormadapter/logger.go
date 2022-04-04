package gormadapter

import (
	"context"
	"time"

	"gorm.io/gorm/logger"

	"github.com/anchore/grype/internal/log"
)

type logAdapter struct {
}

func newLogger() logger.Interface {
	return logAdapter{}
}

func (l logAdapter) LogMode(logger.LogLevel) logger.Interface {
	return l
}

func (l logAdapter) Info(_ context.Context, fmt string, v ...interface{}) {
	// unimplemented
}

func (l logAdapter) Warn(_ context.Context, fmt string, v ...interface{}) {
	log.Warnf("gorm: "+fmt, v...)
}

func (l logAdapter) Error(_ context.Context, fmt string, v ...interface{}) {
	log.Errorf("gorm: "+fmt, v...)
}

func (l logAdapter) Trace(ctx context.Context, begin time.Time, fc func() (sql string, rowsAffected int64), err error) {
	// unimplemented
}
