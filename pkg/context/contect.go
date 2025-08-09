package context

import (
	"context"
	"log"
	"log/slog"
	"os"

	"gorm.io/gorm"
)

var defaultLogger *slog.Logger

func init() {
	defaultLogger = slog.New(slog.NewJSONHandler(os.Stdout, nil))
}

// SetDefaultLogger allows setting a configured default logger
func SetDefaultLogger(logger *slog.Logger) {
	defaultLogger = logger
}

type appContext struct {
	context.Context
	db           *gorm.DB
	shouldCommit bool
	logger       *slog.Logger
}

type AppContextOpt func(*appContext) *appContext // option pattern

func WithDB(db *gorm.DB, shouldCommit bool) AppContextOpt {
	return func(ac *appContext) *appContext {
		ac.db = db
		ac.shouldCommit = shouldCommit
		return ac
	}
}

func WithLogger(logger *slog.Logger) AppContextOpt {
	return func(ac *appContext) *appContext {
		ac.logger = logger
		return ac
	}
}

func NewAppContext(parent context.Context, opts ...AppContextOpt) context.Context {
	ctx := &appContext{Context: parent}
	for _, opt := range opts {
		ctx = opt(ctx)
	}

	return ctx
}

func NewAppContextWithTracing(parent context.Context, traceID string, opts ...AppContextOpt) context.Context {
	// Add trace ID to the parent context
	parentWithTrace := context.WithValue(parent, "trace_id", traceID)

	ctx := &appContext{Context: parentWithTrace}
	for _, opt := range opts {
		ctx = opt(ctx)
	}

	return ctx
}

func NewAppContextWithUser(parent context.Context, userID string, opts ...AppContextOpt) context.Context {
	// Add user ID to the parent context
	parentWithUser := context.WithValue(parent, "user_id", userID)

	ctx := &appContext{Context: parentWithUser}
	for _, opt := range opts {
		ctx = opt(ctx)
	}

	return ctx
}

func NewAppContextWithTracingAndUser(parent context.Context, traceID, userID string, opts ...AppContextOpt) context.Context {
	// Add both trace ID and user ID to the parent context
	parentWithTrace := context.WithValue(parent, "trace_id", traceID)
	parentWithUser := context.WithValue(parentWithTrace, "user_id", userID)

	ctx := &appContext{Context: parentWithUser}
	for _, opt := range opts {
		ctx = opt(ctx)
	}

	return ctx
}

func SetDB(ctx context.Context, db *gorm.DB, shouldCommit bool) {
	appCtx, ok := ctx.(*appContext)
	if !ok {
		return
	}

	appCtx.db = db
	appCtx.shouldCommit = shouldCommit
}

func GetDB(ctx context.Context) *gorm.DB {
	appCtx, ok := ctx.(*appContext)
	if !ok {
		return nil
	}

	return appCtx.db
}

func Commit(ctx context.Context) error {
	appCtx, ok := ctx.(*appContext)
	if !ok || !appCtx.shouldCommit {
		return nil
	}

	return appCtx.db.Commit().Error
}

func Rollback(ctx context.Context) error {
	appCtx, ok := ctx.(*appContext)
	if !ok || !appCtx.shouldCommit {
		return nil
	}

	return appCtx.db.Rollback().Error
}

func CommitOrRollback(ctx context.Context, shouldLog bool) error {
	commitErr := Commit(ctx)
	if commitErr == nil {
		return nil
	}

	if shouldLog {
		log.Println("error on committing transaction, err :", commitErr.Error())
	}

	if err := Rollback(ctx); err != nil {
		log.Println("error on rollback transaction, err :", err.Error())
	}

	return commitErr
}

func SetLogger(ctx context.Context, logger *slog.Logger) {
	if appCtx, ok := ctx.(*appContext); ok {
		appCtx.logger = logger
	}
}

func GetLogger(ctx context.Context) *slog.Logger {
	appCtx, ok := ctx.(*appContext)
	if !ok || appCtx.logger == nil {
		return defaultLogger
	}

	return appCtx.logger
}

func GetTraceID(ctx context.Context) string {
	if traceID := ctx.Value("trace_id"); traceID != nil {
		if tid, ok := traceID.(string); ok {
			return tid
		}
	}
	return ""
}

func GetUserID(ctx context.Context) string {
	if userID := ctx.Value("user_id"); userID != nil {
		if uid, ok := userID.(string); ok {
			return uid
		}
	}
	return ""
}
