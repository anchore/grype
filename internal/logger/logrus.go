package logger

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"github.com/sirupsen/logrus"
	prefixed "github.com/x-cray/logrus-prefixed-formatter"
)

type LogrusConfig struct {
	EnableConsole bool
	EnableFile    bool
	Structured    bool
	Level         logrus.Level
	FileLocation  string
}

type LogrusLogger struct {
	Config LogrusConfig
	Logger *logrus.Logger
}

type LogrusNestedLogger struct {
	Logger *logrus.Entry
}

func NewLogrusLogger(cfg LogrusConfig) *LogrusLogger {
	appLogger := logrus.New()

	var output io.Writer
	switch {
	case cfg.EnableConsole && cfg.EnableFile:
		logFile, err := os.OpenFile(cfg.FileLocation, os.O_WRONLY|os.O_CREATE, 0755)
		if err != nil {
			panic(fmt.Errorf("unable to setup log file: %w", err))
		}
		output = io.MultiWriter(os.Stderr, logFile)
	case cfg.EnableConsole:
		output = os.Stderr
	case cfg.EnableFile:
		logFile, err := os.OpenFile(cfg.FileLocation, os.O_WRONLY|os.O_CREATE, 0755)
		if err != nil {
			panic(fmt.Errorf("unable to setup log file: %w", err))
		}
		output = logFile
	default:
		output = ioutil.Discard
	}

	appLogger.SetOutput(output)
	appLogger.SetLevel(cfg.Level)

	if cfg.Structured {
		appLogger.SetFormatter(&logrus.JSONFormatter{
			TimestampFormat:   "2006-01-02 15:04:05",
			DisableTimestamp:  false,
			DisableHTMLEscape: false,
			PrettyPrint:       false,
		})
	} else {
		appLogger.SetFormatter(&prefixed.TextFormatter{
			TimestampFormat: "2006-01-02 15:04:05",
			ForceColors:     true,
			ForceFormatting: true,
		})
	}

	return &LogrusLogger{
		Config: cfg,
		Logger: appLogger,
	}
}

func (l *LogrusLogger) Debugf(format string, args ...interface{}) {
	l.Logger.Debugf(format, args...)
}

func (l *LogrusLogger) Infof(format string, args ...interface{}) {
	l.Logger.Infof(format, args...)
}

func (l *LogrusLogger) Debug(args ...interface{}) {
	l.Logger.Debug(args...)
}

func (l *LogrusLogger) Info(args ...interface{}) {
	l.Logger.Info(args...)
}

func (l *LogrusLogger) Errorf(format string, args ...interface{}) {
	l.Logger.Errorf(format, args...)
}

func (l *LogrusNestedLogger) Debugf(format string, args ...interface{}) {
	l.Logger.Debugf(format, args...)
}

func (l *LogrusNestedLogger) Infof(format string, args ...interface{}) {
	l.Logger.Infof(format, args...)
}

func (l *LogrusNestedLogger) Debug(args ...interface{}) {
	l.Logger.Debug(args...)
}

func (l *LogrusNestedLogger) Info(args ...interface{}) {
	l.Logger.Info(args...)
}

func (l *LogrusNestedLogger) Errorf(format string, args ...interface{}) {
	l.Logger.Errorf(format, args...)
}
