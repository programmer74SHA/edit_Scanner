package logger

import (
	"log/slog"
	"os"

	"github.com/google/uuid"
)

// NewLogger creates a new slog.Logger instance (backward compatibility)
// Deprecated: Use NewCoreLogger or NewContextLogger instead
func NewLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(os.Stdout, nil)).
		With("trace_id", uuid.NewString())
}

// Global convenience functions (when context is not available)

// Debug logs a debug message using the global logger
func Debug(msg string, args ...interface{}) {
	GetGlobalLogger().CoreLogger.Debug(msg, args...)
}

// Info logs an info message using the global logger
func Info(msg string, args ...interface{}) {
	GetGlobalLogger().CoreLogger.Info(msg, args...)
}

// Warn logs a warning message using the global logger
func Warn(msg string, args ...interface{}) {
	GetGlobalLogger().CoreLogger.Warn(msg, args...)
}

// Error logs an error message using the global logger
func Error(msg string, args ...interface{}) {
	GetGlobalLogger().CoreLogger.Error(msg, args...)
}

// Fatal logs a fatal error using the global logger and exits
func Fatal(msg string, args ...interface{}) {
	GetGlobalLogger().CoreLogger.Fatal(msg, args...)
}

// WithFields logs with additional fields using the global logger
func DebugWithFields(msg string, fields map[string]interface{}) {
	GetGlobalLogger().CoreLogger.DebugWithFields(msg, fields)
}

func InfoWithFields(msg string, fields map[string]interface{}) {
	GetGlobalLogger().CoreLogger.InfoWithFields(msg, fields)
}

func WarnWithFields(msg string, fields map[string]interface{}) {
	GetGlobalLogger().CoreLogger.WarnWithFields(msg, fields)
}

func ErrorWithFields(msg string, fields map[string]interface{}) {
	GetGlobalLogger().CoreLogger.ErrorWithFields(msg, fields)
}
