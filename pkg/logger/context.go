package logger

import (
	"context"
	"log/slog"

	"gitlab.apk-group.net/siem/backend/asset-discovery/config"
	appContext "gitlab.apk-group.net/siem/backend/asset-discovery/pkg/context"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/jwt"
)

// ContextLogger provides context-aware logging functionality
type ContextLogger struct {
	*CoreLogger
}

// NewContextLogger creates a new context-aware logger
func NewContextLogger(cfg config.LoggerConfig) (*ContextLogger, error) {
	coreLogger, err := NewCoreLogger(cfg)
	if err != nil {
		return nil, err
	}

	return &ContextLogger{
		CoreLogger: coreLogger,
	}, nil
}

// FromContext extracts logger from context and enriches it with trace ID and user ID
func (cl *ContextLogger) FromContext(ctx context.Context) *CoreLogger {
	// Get base logger from context if available, otherwise use the core logger
	var baseLogger *slog.Logger
	if ctxLogger := appContext.GetLogger(ctx); ctxLogger != nil {
		baseLogger = ctxLogger
	} else {
		baseLogger = cl.CoreLogger.Logger
	}

	// Extract trace ID, user ID, and username from context
	traceID := extractTraceIDFromContext(ctx)
	userID := extractUserIDFromContext(ctx)
	username := extractUsernameFromContext(ctx)

	// Create new core logger with context information
	logger := &CoreLogger{
		Logger: baseLogger,
		config: cl.config,
	}

	// Add trace ID, user ID, and username to logger ONLY if they don't already exist
	if traceID != "" && !hasAttribute(baseLogger, "trace_id") {
		logger.Logger = logger.Logger.With("trace_id", traceID)
		markLoggerAttribute(logger.Logger, "trace_id")
	}
	if userID != "" && !hasAttribute(baseLogger, "user_id") {
		logger.Logger = logger.Logger.With("user_id", userID)
		markLoggerAttribute(logger.Logger, "user_id")
	}
	if username != "" && username != userID && !hasAttribute(baseLogger, "username") {
		logger.Logger = logger.Logger.With("username", username)
		markLoggerAttribute(logger.Logger, "username")
	}

	return logger
}

func hasAttribute(logger *slog.Logger, key string) bool {
	return checkLoggerAttribute(logger, key)
}

// SetInContext sets the logger in the context
func (cl *ContextLogger) SetInContext(ctx context.Context, logger *CoreLogger) context.Context {
	appContext.SetLogger(ctx, logger.Logger)
	return ctx
}

// WithTraceIDInContext creates a new logger with trace ID and sets it in context
func (cl *ContextLogger) WithTraceIDInContext(ctx context.Context, traceID string) context.Context {
	logger := cl.FromContext(ctx).WithTraceID(traceID)
	return cl.SetInContext(ctx, logger)
}

// WithUserIDInContext creates a new logger with user ID and sets it in context
func (cl *ContextLogger) WithUserIDInContext(ctx context.Context, userID string) context.Context {
	logger := cl.FromContext(ctx).WithUserID(userID)
	return cl.SetInContext(ctx, logger)
}

// Helper functions to extract information from context

func extractTraceIDFromContext(ctx context.Context) string {
	// Try to extract trace ID from context values
	if traceID := ctx.Value("trace_id"); traceID != nil {
		if tid, ok := traceID.(string); ok {
			return tid
		}
	}

	return ""
}

func extractUserIDFromContext(ctx context.Context) string {
	// Try to extract user ID from JWT claims in context
	if userClaims := ctx.Value(jwt.UserClaimKey); userClaims != nil {
		if claims, ok := userClaims.(*jwt.UserClaims); ok {
			return claims.UserID
		}
	}

	// Try to extract from context values
	if userID := ctx.Value("user_id"); userID != nil {
		if uid, ok := userID.(string); ok {
			return uid
		}
	}

	// Try to extract from app context
	if userID := appContext.GetUserID(ctx); userID != "" {
		return userID
	}

	return ""
}

func extractUsernameFromContext(ctx context.Context) string {
	// Try to extract username from context values
	if username := ctx.Value("username"); username != nil {
		if u, ok := username.(string); ok {
			return u
		}
	}
	return extractUserIDFromContext(ctx)
}

// Global instance management

var globalContextLogger *ContextLogger

// InitGlobalLogger initializes the global context logger
func InitGlobalLogger(cfg config.LoggerConfig) error {
	logger, err := NewContextLogger(cfg)
	if err != nil {
		return err
	}
	globalContextLogger = logger
	return nil
}

// GetGlobalLogger returns the global context logger instance
func GetGlobalLogger() *ContextLogger {
	if globalContextLogger == nil {
		// Fallback to default configuration
		cfg := config.LoggerConfig{
			Level:  "info",
			Output: "stdout",
		}
		logger, err := NewContextLogger(cfg)
		if err != nil {
			panic("Failed to create default logger: " + err.Error())
		}
		globalContextLogger = logger
	}
	return globalContextLogger
}

// FromContext is a convenience function to get logger from context using global instance
func FromContext(ctx context.Context) *CoreLogger {
	return GetGlobalLogger().FromContext(ctx)
}

// SetInContext is a convenience function to set logger in context using global instance
func SetInContext(ctx context.Context, logger *CoreLogger) context.Context {
	return GetGlobalLogger().SetInContext(ctx, logger)
}

// Convenience functions for common logging patterns

// DebugContext logs a debug message using context
func DebugContext(ctx context.Context, msg string, args ...interface{}) {
	FromContext(ctx).Debug(msg, args...)
}

// InfoContext logs an info message using context
func InfoContext(ctx context.Context, msg string, args ...interface{}) {
	FromContext(ctx).Info(msg, args...)
}

// WarnContext logs a warning message using context
func WarnContext(ctx context.Context, msg string, args ...interface{}) {
	FromContext(ctx).Warn(msg, args...)
}

// ErrorContext logs an error message using context
func ErrorContext(ctx context.Context, msg string, args ...interface{}) {
	FromContext(ctx).Error(msg, args...)
}

// FatalContext logs a fatal error using context and exits
func FatalContext(ctx context.Context, msg string, args ...interface{}) {
	FromContext(ctx).Fatal(msg, args...)
}

// Convenience functions for logging with additional fields

// DebugContextWithFields logs a debug message with additional fields using context
func DebugContextWithFields(ctx context.Context, msg string, fields map[string]interface{}) {
	FromContext(ctx).DebugWithFields(msg, fields)
}

// InfoContextWithFields logs an info message with additional fields using context
func InfoContextWithFields(ctx context.Context, msg string, fields map[string]interface{}) {
	FromContext(ctx).InfoWithFields(msg, fields)
}

// WarnContextWithFields logs a warning message with additional fields using context
func WarnContextWithFields(ctx context.Context, msg string, fields map[string]interface{}) {
	FromContext(ctx).WarnWithFields(msg, fields)
}

// ErrorContextWithFields logs an error message with additional fields using context
func ErrorContextWithFields(ctx context.Context, msg string, fields map[string]interface{}) {
	FromContext(ctx).ErrorWithFields(msg, fields)
}
