package gormadapter

import (
	"context"
	"fmt"
	"time"

	"gorm.io/gorm/logger"

	anchoreLogger "github.com/anchore/go-logger"
	"github.com/anchore/grype/internal/log"
)

// logAdapter is meant to adapt the gorm logger interface (see https://github.com/go-gorm/gorm/blob/v1.25.12/logger/logger.go)
// to the anchore logger interface.
type logAdapter struct {
	debug         bool
	slowThreshold time.Duration
	level         logger.LogLevel
}

// LogMode sets the log level for the logger and returns a new instance
func (l *logAdapter) LogMode(level logger.LogLevel) logger.Interface {
	newlogger := *l
	newlogger.level = level
	return &newlogger
}

func (l logAdapter) Info(_ context.Context, fmt string, v ...interface{}) {
	if l.level >= logger.Info {
		if l.debug {
			log.Infof("[sql] "+fmt, v...)
		}
	}
}

func (l logAdapter) Warn(_ context.Context, fmt string, v ...interface{}) {
	if l.level >= logger.Warn {
		log.Warnf("[sql] "+fmt, v...)
	}
}

func (l logAdapter) Error(_ context.Context, fmt string, v ...interface{}) {
	if l.level >= logger.Error {
		log.Errorf("[sql] "+fmt, v...)
	}
}

// Trace logs the SQL statement and the duration it took to run the statement
func (l logAdapter) Trace(_ context.Context, t time.Time, fn func() (sql string, rowsAffected int64), _ error) {
	if l.level <= logger.Silent {
		return
	}

	if l.debug {
		sql, rowsAffected := fn()
		elapsed := time.Since(t)
		fields := anchoreLogger.Fields{
			"rows":     rowsAffected,
			"duration": elapsed,
		}

		isSlow := l.slowThreshold != 0 && elapsed > l.slowThreshold
		if isSlow {
			fields["is-slow"] = isSlow
			fields["slow-threshold"] = fmt.Sprintf("> %s", l.slowThreshold)
			log.WithFields(fields).Warnf("[sql] %s", sql)
		} else {
			log.WithFields(fields).Tracef("[sql] %s", sql)
		}
	}
}
