package logger

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"

	"gitlab.apk-group.net/siem/backend/asset-discovery/config"
)

// LogLevel represents the available log levels
type LogLevel string

const (
	LevelDebug LogLevel = "debug"
	LevelInfo  LogLevel = "info"
	LevelWarn  LogLevel = "warn"
	LevelError LogLevel = "error"
)

// OutputType represents the output destination type
type OutputType string

const (
	OutputStdout OutputType = "stdout"
	OutputFile   OutputType = "file"
)

// CoreLogger represents the enhanced logger with additional context
type CoreLogger struct {
	*slog.Logger
	config config.LoggerConfig
}

// LoggerOptions holds configuration options for logger creation
type LoggerOptions struct {
	Level    LogLevel
	Output   OutputType
	FilePath string
}

// NewCoreLogger creates a new core logger instance based on configuration
func NewCoreLogger(cfg config.LoggerConfig) (*CoreLogger, error) {
	// Parse log level
	level, err := parseLogLevel(cfg.Level)
	if err != nil {
		return nil, fmt.Errorf("invalid log level '%s': %w", cfg.Level, err)
	}

	// Determine output destination
	var writer io.Writer
	outputType := parseOutputType(cfg.Output)

	switch outputType {
	case OutputFile:
		if cfg.Path == "" {
			return nil, fmt.Errorf("file path is required when output is set to 'file'")
		}
		file, err := os.OpenFile(cfg.Path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			return nil, fmt.Errorf("failed to open log file '%s': %w", cfg.Path, err)
		}
		writer = file
	default:
		writer = os.Stdout
	}

	// Create JSON handler with appropriate level
	handlerOpts := &slog.HandlerOptions{
		Level: level,
	}

	jsonHandler := slog.NewJSONHandler(writer, handlerOpts)

	baseLogger := slog.New(jsonHandler)

	return &CoreLogger{
		Logger: baseLogger,
		config: cfg,
	}, nil
}

// NewCoreLoggerWithOptions creates a logger with explicit options
func NewCoreLoggerWithOptions(opts LoggerOptions) (*CoreLogger, error) {
	cfg := config.LoggerConfig{
		Level:  string(opts.Level),
		Output: string(opts.Output),
		Path:   opts.FilePath,
	}

	logger, err := NewCoreLogger(cfg)
	if err != nil {
		return nil, err
	}

	return logger, nil
}

// loggerAttributes tracks which attributes have been added to which loggers
var loggerAttributes = make(map[*slog.Logger]map[string]bool)
var loggerAttributesMutex sync.RWMutex

// checkLoggerAttribute checks if a specific attribute has been added to a logger
func checkLoggerAttribute(logger *slog.Logger, key string) bool {
	loggerAttributesMutex.RLock()
	defer loggerAttributesMutex.RUnlock()

	if attrs, exists := loggerAttributes[logger]; exists {
		return attrs[key]
	}
	return false
}

// markLoggerAttribute marks that an attribute has been added to a logger
func markLoggerAttribute(logger *slog.Logger, key string) {
	loggerAttributesMutex.Lock()
	defer loggerAttributesMutex.Unlock()

	if loggerAttributes[logger] == nil {
		loggerAttributes[logger] = make(map[string]bool)
	}
	loggerAttributes[logger][key] = true
}

// WithTraceID creates a new logger instance with the specified trace ID
func (l *CoreLogger) WithTraceID(traceID string) *CoreLogger {
	if traceID == "" {
		return l
	}

	if checkLoggerAttribute(l.Logger, "trace_id") {
		return l
	}

	newLogger := l.Logger.With("trace_id", traceID)
	markLoggerAttribute(newLogger, "trace_id")

	return &CoreLogger{
		Logger: newLogger,
		config: l.config,
	}
}

// WithUserID creates a new logger instance with the specified user ID
func (l *CoreLogger) WithUserID(userID string) *CoreLogger {
	if userID == "" {
		return l
	}

	if checkLoggerAttribute(l.Logger, "user_id") {
		return l
	}

	newLogger := l.Logger.With("user_id", userID)
	markLoggerAttribute(newLogger, "user_id")

	return &CoreLogger{
		Logger: newLogger,
		config: l.config,
	}
}

// WithUsername creates a new logger instance with the specified username
func (l *CoreLogger) WithUsername(username string) *CoreLogger {
	if username == "" {
		return l
	}

	if checkLoggerAttribute(l.Logger, "username") {
		return l
	}

	newLogger := l.Logger.With("username", username)
	markLoggerAttribute(newLogger, "username")

	return &CoreLogger{
		Logger: newLogger,
		config: l.config,
	}
}

// WithContext creates a new logger instance with both trace ID and user ID
func (l *CoreLogger) WithContext(traceID, userID string) *CoreLogger {
	logger := l.Logger

	if traceID != "" && !checkLoggerAttribute(logger, "trace_id") {
		logger = logger.With("trace_id", traceID)
		markLoggerAttribute(logger, "trace_id")
	}
	if userID != "" && !checkLoggerAttribute(logger, "user_id") {
		logger = logger.With("user_id", userID)
		markLoggerAttribute(logger, "user_id")
	}

	return &CoreLogger{
		Logger: logger,
		config: l.config,
	}
}

// WithFullContext creates a new logger instance with trace ID, user ID, and username
func (l *CoreLogger) WithFullContext(traceID, userID, username string) *CoreLogger {
	logger := l.Logger

	if traceID != "" && !checkLoggerAttribute(logger, "trace_id") {
		logger = logger.With("trace_id", traceID)
		markLoggerAttribute(logger, "trace_id")
	}
	if userID != "" && !checkLoggerAttribute(logger, "user_id") {
		logger = logger.With("user_id", userID)
		markLoggerAttribute(logger, "user_id")
	}
	if username != "" && !checkLoggerAttribute(logger, "username") {
		logger = logger.With("username", username)
		markLoggerAttribute(logger, "username")
	}

	return &CoreLogger{
		Logger: logger,
		config: l.config,
	}
}

// WithFields creates a new logger instance with additional fields
func (l *CoreLogger) WithFields(fields map[string]interface{}) *CoreLogger {
	logger := l.Logger
	for key, value := range fields {
		logger = logger.With(key, value)
	}

	return &CoreLogger{
		Logger: logger,
		config: l.config,
	}
}

// Convenience methods for different log levels with consistent formatting

// Debug logs a debug level message
func (l *CoreLogger) Debug(msg string, args ...interface{}) {
	l.Logger.Debug(fmt.Sprintf(msg, args...))
}

// Info logs an info level message
func (l *CoreLogger) Info(msg string, args ...interface{}) {
	l.Logger.Info(fmt.Sprintf(msg, args...))
}

// Warn logs a warning level message
func (l *CoreLogger) Warn(msg string, args ...interface{}) {
	l.Logger.Warn(fmt.Sprintf(msg, args...))
}

// Error logs an error level message
func (l *CoreLogger) Error(msg string, args ...interface{}) {
	l.Logger.Error(fmt.Sprintf(msg, args...))
}

// DebugWithFields logs a debug message with additional fields
func (l *CoreLogger) DebugWithFields(msg string, fields map[string]interface{}) {
	l.WithFields(fields).Logger.Debug(msg)
}

// InfoWithFields logs an info message with additional fields
func (l *CoreLogger) InfoWithFields(msg string, fields map[string]interface{}) {
	l.WithFields(fields).Logger.Info(msg)
}

// WarnWithFields logs a warning message with additional fields
func (l *CoreLogger) WarnWithFields(msg string, fields map[string]interface{}) {
	l.WithFields(fields).Logger.Warn(msg)
}

// ErrorWithFields logs an error message with additional fields
func (l *CoreLogger) ErrorWithFields(msg string, fields map[string]interface{}) {
	l.WithFields(fields).Logger.Error(msg)
}

// Fatal logs a fatal error and exits
func (l *CoreLogger) Fatal(msg string, args ...interface{}) {
	l.Logger.Error(fmt.Sprintf("FATAL: "+msg, args...))
	os.Exit(1)
}

// Helper functions

func parseLogLevel(level string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug", "":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return slog.LevelInfo, fmt.Errorf("unsupported log level: %s", level)
	}
}

func parseOutputType(output string) OutputType {
	switch strings.ToLower(strings.TrimSpace(output)) {
	case "file":
		return OutputFile
	case "stdout", "":
		return OutputStdout
	default:
		return OutputStdout
	}
}
