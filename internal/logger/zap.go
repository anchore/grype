package logger

import (
	"os"

	"github.com/anchore/grype/internal/format"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var levelToColor = map[zapcore.Level]format.Color{
	zapcore.DebugLevel:  format.Magenta,
	zapcore.InfoLevel:   format.Blue,
	zapcore.WarnLevel:   format.Yellow,
	zapcore.ErrorLevel:  format.Red,
	zapcore.DPanicLevel: format.Red,
	zapcore.PanicLevel:  format.Red,
	zapcore.FatalLevel:  format.Red,
}

type LogConfig struct {
	EnableConsole bool
	EnableFile    bool
	Structured    bool
	Level         zapcore.Level
	FileLocation  string
}

type ZapLogger struct {
	Config LogConfig
	Logger *zap.SugaredLogger
}

// TODO: Consider a human readable text encoder for better field handeling:
// - https://github.com/uber-go/zap/issues/570
// - https://github.com/uber-go/zap/pull/123
// - TextEncoder w/ old interface: https://github.com/uber-go/zap/blob/6c2107996402d47d559199b78e1c44747fe732f9/text_encoder.go
// - New interface example: https://github.com/uber-go/zap/blob/c2633d6de2d6e1170ad8f150660e3cf5310067c8/zapcore/json_encoder.go
// - Register the encoder: https://github.com/uber-go/zap/blob/v1.15.0/encoder.go
func NewZapLogger(config LogConfig) *ZapLogger {
	appLogger := ZapLogger{
		Config: config,
	}
	cores := []zapcore.Core{}

	if config.EnableConsole {
		// note: the report should go to stdout, all logs should go to stderr
		writer := zapcore.Lock(os.Stderr)
		core := zapcore.NewCore(appLogger.getConsoleEncoder(config), writer, config.Level)
		cores = append(cores, core)
	}

	if config.EnableFile {
		writer := zapcore.AddSync(appLogger.logFileWriter(config.FileLocation))
		core := zapcore.NewCore(appLogger.fileEncoder(config), writer, config.Level)
		cores = append(cores, core)
	}

	combinedCore := zapcore.NewTee(cores...)

	// AddCallerSkip skips 2 number of callers, this is important else the file that gets
	// logged will always be the wrapped file (In our case logger.go)
	appLogger.Logger = zap.New(
		combinedCore,
		zap.AddCallerSkip(2),
		zap.AddCaller(),
	).Sugar()

	return &appLogger
}

func (l *ZapLogger) GetNamedLogger(name string) *ZapLogger {
	return &ZapLogger{
		Logger: l.Logger.Named(name),
	}
}

func (l *ZapLogger) getConsoleEncoder(config LogConfig) zapcore.Encoder {
	encoderConfig := zap.NewProductionEncoderConfig()
	if config.Structured {
		encoderConfig.EncodeName = zapcore.FullNameEncoder
		encoderConfig.EncodeCaller = zapcore.FullCallerEncoder
		return zapcore.NewJSONEncoder(encoderConfig)
	}
	encoderConfig.EncodeTime = nil
	encoderConfig.EncodeCaller = nil
	encoderConfig.EncodeLevel = l.consoleLevelEncoder
	encoderConfig.EncodeName = l.nameEncoder
	return zapcore.NewConsoleEncoder(encoderConfig)
}

func (l *ZapLogger) nameEncoder(loggerName string, enc zapcore.PrimitiveArrayEncoder) {
	enc.AppendString("[" + loggerName + "]")
}

func (l *ZapLogger) consoleLevelEncoder(level zapcore.Level, enc zapcore.PrimitiveArrayEncoder) {
	if level != zapcore.InfoLevel || l.Config.Level == zapcore.DebugLevel {
		color, ok := levelToColor[level]
		if !ok {
			enc.AppendString("[" + level.CapitalString() + "]")
		} else {
			enc.AppendString("[" + color.Format(level.CapitalString()) + "]")
		}
	}
}

func (l *ZapLogger) fileEncoder(config LogConfig) zapcore.Encoder {
	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	encoderConfig.EncodeName = zapcore.FullNameEncoder
	encoderConfig.EncodeCaller = zapcore.FullCallerEncoder
	if config.Structured {
		return zapcore.NewJSONEncoder(encoderConfig)
	}
	return zapcore.NewConsoleEncoder(encoderConfig)
}

func (l *ZapLogger) logFileWriter(location string) zapcore.WriteSyncer {
	file, _ := os.Create(location)
	return zapcore.AddSync(file)
}

func (l *ZapLogger) Debugf(format string, args ...interface{}) {
	l.Logger.Debugf(format, args...)
}

func (l *ZapLogger) Infof(format string, args ...interface{}) {
	l.Logger.Infof(format, args...)
}

func (l *ZapLogger) Debug(args ...interface{}) {
	l.Logger.Debug(args...)
}

func (l *ZapLogger) Info(args ...interface{}) {
	l.Logger.Info(args...)
}

func (l *ZapLogger) Errorf(format string, args ...interface{}) {
	l.Logger.Errorf(format, args...)
}
