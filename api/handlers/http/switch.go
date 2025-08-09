package http

import (
	"strconv"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"gitlab.apk-group.net/siem/backend/asset-discovery/api/service"
	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/switch/domain"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/context"
)

// GetSwitches handles GET /api/v1/switches - List all switches
func GetSwitches(svcGetter ServiceGetter[*service.SwitchService]) fiber.Handler {
	return func(c *fiber.Ctx) error {
		ctx := c.UserContext()
		srv := svcGetter(ctx)
		logger := context.GetLogger(ctx)

		// Parse query parameters
		req := domain.SwitchListRequest{
			Limit: c.QueryInt("limit", 50),
			Page:  c.QueryInt("page", 0),
			Sort:  c.Query("sort", "name"),
			Order: c.Query("order", "asc"),
		}

		// Parse filters
		req.Filter = domain.SwitchFilter{
			Name:      c.Query("name", ""),
			Brand:     c.Query("brand", ""),
			IPAddress: c.Query("ip", ""),
			Status:    c.Query("status", ""),
		}

		// Parse scanner ID filter if provided
		if scannerIDStr := c.Query("scanner_id", ""); scannerIDStr != "" {
			if scannerID, err := strconv.ParseInt(scannerIDStr, 10, 64); err == nil {
				req.Filter.ScannerID = &scannerID
			}
		}

		// Handle filter[name] style parameters
		if filterName := c.Query("filter[name]", ""); filterName != "" {
			req.Filter.Name = filterName
		}
		if filterBrand := c.Query("filter[brand]", ""); filterBrand != "" {
			req.Filter.Brand = filterBrand
		}
		if filterIP := c.Query("filter[ip]", ""); filterIP != "" {
			req.Filter.IPAddress = filterIP
		}
		if filterStatus := c.Query("filter[status]", ""); filterStatus != "" {
			req.Filter.Status = filterStatus
		}

		logger.InfoContext(ctx, "Listing switches with request: %+v", req)

		// Call service
		response, err := srv.ListSwitches(ctx, req)
		if err != nil {
			logger.ErrorContext(ctx, "Error listing switches: %v", err)
			return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
				Success: false,
				Error:   err.Error(),
			})
		}

		logger.InfoContext(ctx, "Successfully listed %d switches", len(response.Switches))

		// Build response in the format similar to other APIs
		result := map[string]interface{}{
			"data": map[string]interface{}{
				"contents": response.Switches,
				"count":    response.Count,
			},
			"switch": map[string]interface{}{
				"limit": req.Limit,
				"page":  req.Page,
				"sort": []map[string]string{
					{
						"field": req.Sort,
						"order": req.Order,
					},
				},
				"filter": map[string]interface{}{
					"name":       req.Filter.Name,
					"brand":      req.Filter.Brand,
					"ip_address": req.Filter.IPAddress,
					"status":     req.Filter.Status,
				},
			},
			"success": true,
		}

		return c.JSON(result)
	}
}

// GetSwitchByID handles GET /api/v1/switches/:id - Get switch details by ID
func GetSwitchByID(svcGetter ServiceGetter[*service.SwitchService]) fiber.Handler {
	return func(c *fiber.Ctx) error {
		ctx := c.UserContext()
		srv := svcGetter(ctx)
		logger := context.GetLogger(ctx)

		// Get switch ID from path parameter
		switchIDStr := c.Params("id")
		if switchIDStr == "" {
			logger.WarnContext(ctx, "Switch ID is empty")
			return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
				Success: false,
				Error:   "Switch ID is required",
			})
		}

		// Parse switch ID as UUID
		switchID, err := uuid.Parse(switchIDStr)
		if err != nil {
			logger.WarnContext(ctx, "Invalid switch ID format: %s", switchIDStr)
			return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
				Success: false,
				Error:   "Invalid switch ID format",
			})
		}

		logger.InfoContext(ctx, "Getting switch by ID: %s", switchID.String())

		// Call service
		response, err := srv.GetSwitchByID(ctx, switchID)
		if err != nil {
			logger.ErrorContext(ctx, "Error getting switch: %v", err)

			if err == service.ErrSwitchNotFound {
				return c.Status(fiber.StatusNotFound).JSON(ErrorResponse{
					Success: false,
					Error:   "Switch not found",
				})
			}

			return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
				Success: false,
				Error:   err.Error(),
			})
		}

		logger.InfoContext(ctx, "Successfully retrieved switch: %s", response.Switch.Name)
		return c.JSON(response)
	}
}

// GetSwitchByScannerID handles GET /api/v1/switches/scanner/:id - Get switch by scanner ID
func GetSwitchByScannerID(svcGetter ServiceGetter[*service.SwitchService]) fiber.Handler {
	return func(c *fiber.Ctx) error {
		ctx := c.UserContext()
		srv := svcGetter(ctx)
		logger := context.GetLogger(ctx)

		// Get scanner ID from path parameter
		scannerIDStr := c.Params("id")
		if scannerIDStr == "" {
			logger.WarnContext(ctx, "Scanner ID is empty")
			return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
				Success: false,
				Error:   "Scanner ID is required",
			})
		}

		// Parse scanner ID
		scannerID, err := strconv.ParseInt(scannerIDStr, 10, 64)
		if err != nil {
			logger.WarnContext(ctx, "Invalid scanner ID format: %s", scannerIDStr)
			return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
				Success: false,
				Error:   "Invalid scanner ID format",
			})
		}

		logger.InfoContext(ctx, "Getting switch by scanner ID: %d", scannerID)

		// Call service
		response, err := srv.GetSwitchByScannerID(ctx, scannerID)
		if err != nil {
			logger.ErrorContext(ctx, "Error getting switch: %v", err)

			if err == service.ErrSwitchNotFound {
				return c.Status(fiber.StatusNotFound).JSON(ErrorResponse{
					Success: false,
					Error:   "Switch not found",
				})
			}

			return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
				Success: false,
				Error:   err.Error(),
			})
		}

		logger.InfoContext(ctx, "Successfully retrieved switch for scanner: %d", scannerID)
		return c.JSON(response)
	}
}

// GetSwitchInterfaces handles GET /api/v1/switches/:id/interfaces - Get switch interfaces
func GetSwitchInterfaces(svcGetter ServiceGetter[*service.SwitchService]) fiber.Handler {
	return func(c *fiber.Ctx) error {
		ctx := c.UserContext()
		srv := svcGetter(ctx)
		logger := context.GetLogger(ctx)

		// Get switch ID from path parameter
		switchIDStr := c.Params("id")
		if switchIDStr == "" {
			return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
				Success: false,
				Error:   "Switch ID is required",
			})
		}

		// Parse switch ID as UUID
		switchID, err := uuid.Parse(switchIDStr)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
				Success: false,
				Error:   "Invalid switch ID format",
			})
		}

		logger.InfoContext(ctx, "Getting interfaces for switch: %s", switchID.String())

		// Get switch with detailed data
		response, err := srv.GetSwitchByID(ctx, switchID)
		if err != nil {
			logger.ErrorContext(ctx, "Error getting switch: %v", err)

			if err == service.ErrSwitchNotFound {
				return c.Status(fiber.StatusNotFound).JSON(ErrorResponse{
					Success: false,
					Error:   "Switch not found",
				})
			}

			return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
				Success: false,
				Error:   err.Error(),
			})
		}

		return c.JSON(map[string]interface{}{
			"data": map[string]interface{}{
				"interfaces": response.Switch.Interfaces,
				"count":      len(response.Switch.Interfaces),
			},
			"success": true,
		})
	}
}

// GetSwitchVLANs handles GET /api/v1/switches/:id/vlans - Get switch VLANs
func GetSwitchVLANs(svcGetter ServiceGetter[*service.SwitchService]) fiber.Handler {
	return func(c *fiber.Ctx) error {
		ctx := c.UserContext()
		srv := svcGetter(ctx)
		logger := context.GetLogger(ctx)

		// Get switch ID from path parameter
		switchIDStr := c.Params("id")
		if switchIDStr == "" {
			return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
				Success: false,
				Error:   "Switch ID is required",
			})
		}

		// Parse switch ID as UUID
		switchID, err := uuid.Parse(switchIDStr)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
				Success: false,
				Error:   "Invalid switch ID format",
			})
		}

		logger.InfoContext(ctx, "Getting VLANs for switch: %s", switchID.String())

		// Get switch with detailed data
		response, err := srv.GetSwitchByID(ctx, switchID)
		if err != nil {
			logger.ErrorContext(ctx, "Error getting switch: %v", err)

			if err == service.ErrSwitchNotFound {
				return c.Status(fiber.StatusNotFound).JSON(ErrorResponse{
					Success: false,
					Error:   "Switch not found",
				})
			}

			return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
				Success: false,
				Error:   err.Error(),
			})
		}

		return c.JSON(map[string]interface{}{
			"data": map[string]interface{}{
				"vlans": response.Switch.VLANs,
				"count": len(response.Switch.VLANs),
			},
			"success": true,
		})
	}
}

// GetSwitchNeighbors handles GET /api/v1/switches/:id/neighbors - Get switch neighbors
func GetSwitchNeighbors(svcGetter ServiceGetter[*service.SwitchService]) fiber.Handler {
	return func(c *fiber.Ctx) error {
		ctx := c.UserContext()
		srv := svcGetter(ctx)
		logger := context.GetLogger(ctx)

		// Get switch ID from path parameter
		switchIDStr := c.Params("id")
		if switchIDStr == "" {
			return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
				Success: false,
				Error:   "Switch ID is required",
			})
		}

		// Parse switch ID as UUID
		switchID, err := uuid.Parse(switchIDStr)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
				Success: false,
				Error:   "Invalid switch ID format",
			})
		}

		logger.InfoContext(ctx, "Getting neighbors for switch: %s", switchID.String())

		// Get switch with detailed data
		response, err := srv.GetSwitchByID(ctx, switchID)
		if err != nil {
			logger.ErrorContext(ctx, "Error getting switch: %v", err)

			if err == service.ErrSwitchNotFound {
				return c.Status(fiber.StatusNotFound).JSON(ErrorResponse{
					Success: false,
					Error:   "Switch not found",
				})
			}

			return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
				Success: false,
				Error:   err.Error(),
			})
		}

		return c.JSON(map[string]interface{}{
			"data": map[string]interface{}{
				"neighbors": response.Switch.Neighbors,
				"count":     len(response.Switch.Neighbors),
			},
			"success": true,
		})
	}
}

// GetSwitchStats handles GET /api/v1/switches/stats - Get switch statistics
func GetSwitchStats(svcGetter ServiceGetter[*service.SwitchService]) fiber.Handler {
	return func(c *fiber.Ctx) error {
		ctx := c.UserContext()
		srv := svcGetter(ctx)
		logger := context.GetLogger(ctx)

		logger.InfoContext(ctx, "Getting switch statistics")

		// Call service
		stats, err := srv.GetSwitchStats(ctx)
		if err != nil {
			logger.ErrorContext(ctx, "Error getting switch stats: %v", err)
			return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
				Success: false,
				Error:   err.Error(),
			})
		}

		logger.InfoContext(ctx, "Successfully retrieved switch statistics")

		return c.JSON(map[string]interface{}{
			"data":    stats,
			"success": true,
		})
	}
}
