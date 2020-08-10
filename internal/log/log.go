package log

import "github.com/anchore/grype/grype/logger"

var Log logger.Logger = &nopLogger{}

func Errorf(format string, args ...interface{}) {
	Log.Errorf(format, args...)
}

func Warnf(format string, args ...interface{}) {
	Log.Warnf(format, args...)
}

func Infof(format string, args ...interface{}) {
	Log.Infof(format, args...)
}

func Info(args ...interface{}) {
	Log.Info(args...)
}

func Debugf(format string, args ...interface{}) {
	Log.Debugf(format, args...)
}

func Debug(args ...interface{}) {
	Log.Debug(args...)
}
