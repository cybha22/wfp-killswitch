package logger

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/muhsh/advanced-killswitch/internal/config"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Logger wraps zap.SugaredLogger for structured logging.
type Logger struct {
	*zap.SugaredLogger
	underlying *zap.Logger
}

// New creates a new Logger based on config.
func New(cfg config.LoggingConfig) (*Logger, error) {
	level, err := parseLevel(cfg.Level)
	if err != nil {
		return nil, err
	}

	// Ensure log directory exists
	if cfg.File != "" {
		dir := filepath.Dir(cfg.File)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("create log directory: %w", err)
		}
	}

	encoderCfg := zap.NewProductionEncoderConfig()
	encoderCfg.TimeKey = "ts"
	encoderCfg.EncodeTime = zapcore.ISO8601TimeEncoder

	var cores []zapcore.Core

	// Console output (always)
	consoleEncoder := zapcore.NewConsoleEncoder(encoderCfg)
	consoleSyncer := zapcore.AddSync(os.Stdout)
	cores = append(cores, zapcore.NewCore(consoleEncoder, consoleSyncer, level))

	// File output (if configured)
	if cfg.File != "" {
		file, err := os.OpenFile(cfg.File, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			return nil, fmt.Errorf("open log file: %w", err)
		}
		jsonEncoder := zapcore.NewJSONEncoder(encoderCfg)
		fileSyncer := zapcore.AddSync(file)
		cores = append(cores, zapcore.NewCore(jsonEncoder, fileSyncer, level))
	}

	core := zapcore.NewTee(cores...)
	zapLogger := zap.New(core, zap.AddCaller(), zap.AddStacktrace(zapcore.ErrorLevel))

	return &Logger{
		SugaredLogger: zapLogger.Sugar(),
		underlying:    zapLogger,
	}, nil
}

// Sync flushes any buffered log entries.
func (l *Logger) Sync() {
	_ = l.underlying.Sync()
}

func parseLevel(s string) (zapcore.Level, error) {
	switch s {
	case "debug":
		return zapcore.DebugLevel, nil
	case "info":
		return zapcore.InfoLevel, nil
	case "warn":
		return zapcore.WarnLevel, nil
	case "error":
		return zapcore.ErrorLevel, nil
	default:
		return zapcore.InfoLevel, fmt.Errorf("unknown log level: %q", s)
	}
}
