package http

import (
	"github.com/gofiber/fiber/v2"
	"gitlab.apk-group.net/siem/backend/asset-discovery/api/pb"
	"gitlab.apk-group.net/siem/backend/asset-discovery/api/service"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/logger"
)

// GetDashboardAssetCount returns the count of all assets with online/offline status
func GetDashboardAssetCount(svcGetter ServiceGetter[*service.AssetService]) fiber.Handler {
	return func(c *fiber.Ctx) error {
		ctx := c.UserContext()
		srv := svcGetter(ctx)

		logger.InfoContext(ctx, "Dashboard asset count request received")

		req := &pb.GetDashboardAssetCountRequest{}
		data, err := srv.GetDashboardAssetCount(ctx, req)
		if err != nil {
			logger.ErrorContext(ctx, "Dashboard asset count failed: %v", err)
			return fiber.NewError(fiber.StatusInternalServerError, err.Error())
		}

		logger.InfoContext(ctx, "Dashboard asset count retrieved successfully")
		return c.JSON(data)
	}
}

// GetDashboardAssetPerScanner returns asset count grouped by scanner type
func GetDashboardAssetPerScanner(svcGetter ServiceGetter[*service.AssetService]) fiber.Handler {
	return func(c *fiber.Ctx) error {
		ctx := c.UserContext()
		srv := svcGetter(ctx)

		logger.InfoContext(ctx, "Dashboard asset per scanner request received")

		req := &pb.GetDashboardAssetPerScannerRequest{}
		data, err := srv.GetDashboardAssetPerScanner(ctx, req)
		if err != nil {
			logger.ErrorContext(ctx, "Dashboard asset per scanner failed: %v", err)
			return fiber.NewError(fiber.StatusInternalServerError, err.Error())
		}

		logger.InfoContext(ctx, "Dashboard asset per scanner retrieved successfully")
		return c.JSON(data)
	}
}

// GetDashboardLoggingCompleted returns logging completion statistics by OS type
func GetDashboardLoggingCompleted(svcGetter ServiceGetter[*service.AssetService]) fiber.Handler {
	return func(c *fiber.Ctx) error {
		ctx := c.UserContext()
		srv := svcGetter(ctx)

		logger.InfoContext(ctx, "Dashboard logging completed request received")

		req := &pb.GetDashboardLoggingCompletedRequest{}
		data, err := srv.GetDashboardLoggingCompleted(ctx, req)
		if err != nil {
			logger.ErrorContext(ctx, "Dashboard logging completed failed: %v", err)
			return fiber.NewError(fiber.StatusInternalServerError, err.Error())
		}

		logger.InfoContext(ctx, "Dashboard logging completed retrieved successfully")
		return c.JSON(data)
	}
}

// GetDashboardAssetsPerSource returns asset distribution by OS source with percentages
func GetDashboardAssetsPerSource(svcGetter ServiceGetter[*service.AssetService]) fiber.Handler {
	return func(c *fiber.Ctx) error {
		ctx := c.UserContext()
		srv := svcGetter(ctx)

		logger.InfoContext(ctx, "Dashboard assets per source request received")

		req := &pb.GetDashboardAssetsPerSourceRequest{}
		data, err := srv.GetDashboardAssetsPerSource(ctx, req)
		if err != nil {
			logger.ErrorContext(ctx, "Dashboard assets per source failed: %v", err)
			return fiber.NewError(fiber.StatusInternalServerError, err.Error())
		}

		logger.InfoContext(ctx, "Dashboard assets per source retrieved successfully")
		return c.JSON(data)
	}
}
