package http

import (
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/jwt"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/logger"

	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/context"

	jwtware "github.com/gofiber/contrib/jwt"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

func newAuthMiddleware(secret []byte) fiber.Handler {
	return jwtware.New(jwtware.Config{
		SigningKey:  jwtware.SigningKey{Key: secret},
		Claims:      &jwt.UserClaims{},
		TokenLookup: "header:Authorization",
		SuccessHandler: func(ctx *fiber.Ctx) error {
			userClaims := userClaims(ctx)
			if userClaims == nil {
				return fiber.ErrUnauthorized
			}

			// Get trace ID from locals if available
			traceID := ""
			if tid := ctx.Locals("traceID"); tid != nil {
				if tidStr, ok := tid.(string); ok {
					traceID = tidStr
				}
			}

			// Create enhanced context with user ID and trace ID
			userCtx := context.NewAppContextWithTracingAndUser(
				ctx.UserContext(),
				traceID,
				userClaims.UserID,
			)

			// Get the global logger and create context-aware logger
			contextLogger := logger.GetGlobalLogger()
			coreLogger := contextLogger.FromContext(userCtx)

			// Set the enriched logger back in context
			userCtx = contextLogger.SetInContext(userCtx, coreLogger)
			ctx.SetUserContext(userCtx)

			return ctx.Next()
		},
		ErrorHandler: func(ctx *fiber.Ctx, err error) error {
			return fiber.NewError(fiber.StatusUnauthorized, err.Error())
		},
		AuthScheme: "Bearer",
	})
}

func setUserContext(c *fiber.Ctx) error {
	// Get trace ID from locals if available
	traceID := ""
	if tid := c.Locals("traceID"); tid != nil {
		if tidStr, ok := tid.(string); ok {
			traceID = tidStr
		}
	}

	// Create enhanced context with trace ID
	userCtx := context.NewAppContextWithTracing(c.UserContext(), traceID)

	// Initialize logger with context
	contextLogger := logger.GetGlobalLogger()
	coreLogger := contextLogger.FromContext(userCtx)
	userCtx = contextLogger.SetInContext(userCtx, coreLogger)

	c.SetUserContext(userCtx)
	return c.Next()
}

func setTransaction(db *gorm.DB) fiber.Handler {
	return func(c *fiber.Ctx) error {
		tx := db.Begin()

		context.SetDB(c.UserContext(), tx, true)

		err := c.Next()

		if c.Response().StatusCode() >= 300 {
			return context.Rollback(c.UserContext())
		}

		if err := context.CommitOrRollback(c.UserContext(), true); err != nil {
			return err
		}

		return err
	}
}

func TraceMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		traceID := c.Get("X-Trace-ID")
		if traceID == "" {
			traceID = uuid.New().String()
		}
		c.Set("X-Trace-ID", traceID)

		c.Locals("traceID", traceID)

		return c.Next()
	}
}
