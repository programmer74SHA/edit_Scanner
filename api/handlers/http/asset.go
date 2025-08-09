package http

import (
	"errors"
	"fmt"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"gitlab.apk-group.net/siem/backend/asset-discovery/api/pb"
	"gitlab.apk-group.net/siem/backend/asset-discovery/api/service"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/logger"
)

// CreateAsset handles creation of a new asset via HTTP
func CreateAsset(svcGetter ServiceGetter[*service.AssetService]) fiber.Handler {
	return func(c *fiber.Ctx) error {
		ctx := c.UserContext()
		srv := svcGetter(ctx)

		logger.InfoContext(ctx, "Asset creation request received")

		var req pb.CreateAssetRequest
		if err := c.BodyParser(&req); err != nil {
			logger.WarnContext(ctx, "Failed to parse asset creation request body: %v", err)
			return fiber.ErrBadRequest
		}

		logger.DebugContextWithFields(ctx, "Asset creation request parsed successfully",
			map[string]interface{}{
				"asset_name": req.GetName(),
				"hostname":   req.GetHostname(),
				"ip_count":   len(req.GetAssetIps()),
				"port_count": len(req.GetPorts()),
			})

		resp, err := srv.CreateAsset(ctx, &req)
		if err != nil {
			if errors.Is(err, service.ErrIPAlreadyExists) {
				logger.WarnContext(ctx, "Asset creation failed: IP address already exists for asset %s", req.GetName())
				return fiber.NewError(fiber.StatusConflict, "IP address already exists")
			}
			if errors.Is(err, service.ErrHostnameAlreadyExists) {
				logger.WarnContext(ctx, "Asset creation failed: Hostname already exists for asset %s", req.GetName())
				return fiber.NewError(fiber.StatusConflict, "Hostname already exists")
			}
			logger.ErrorContext(ctx, "Asset creation failed: %v", err)
			return fiber.NewError(fiber.StatusInternalServerError, err.Error())
		}

		logger.InfoContext(ctx, "Asset created successfully with ID: %s", resp.GetId())
		return c.JSON(resp)
	}
}

// UpdateAsset handles updating an existing asset via HTTP
func UpdateAsset(svcGetter ServiceGetter[*service.AssetService]) fiber.Handler {
	return func(c *fiber.Ctx) error {
		ctx := c.UserContext()
		srv := svcGetter(ctx)

		var req pb.UpdateAssetRequest
		req.Id = c.Params("id")
		if req.Id == "" {
			logger.WarnContext(ctx, "Asset update request missing asset ID")
			return fiber.ErrBadRequest
		}

		logger.InfoContext(ctx, "Asset update request received for ID: %s", req.Id)

		if err := c.BodyParser(&req); err != nil {
			logger.WarnContext(ctx, "Failed to parse asset update request body for ID %s: %v", req.Id, err)
			return fiber.ErrBadRequest
		}

		logger.DebugContextWithFields(ctx, "Asset update request parsed successfully",
			map[string]interface{}{
				"asset_id":   req.Id,
				"asset_name": req.GetName(),
				"hostname":   req.GetHostname(),
				"ip_count":   len(req.GetAssetIps()),
				"port_count": len(req.GetPorts()),
			})

		resp, err := srv.UpdateAsset(ctx, &req)
		if err != nil {
			if errors.Is(err, service.ErrInvalidAssetUUID) {
				logger.WarnContext(ctx, "Asset update failed: Invalid asset UUID %s", req.Id)
				return fiber.ErrBadRequest
			}
			if errors.Is(err, service.ErrIPAlreadyExists) {
				logger.WarnContext(ctx, "Asset update failed: IP address already exists for asset %s", req.Id)
				return fiber.NewError(fiber.StatusConflict, "IP address already exists")
			}
			if errors.Is(err, service.ErrHostnameAlreadyExists) {
				logger.WarnContext(ctx, "Asset update failed: Hostname already exists for asset %s", req.Id)
				return fiber.NewError(fiber.StatusConflict, "Hostname already exists")
			}
			logger.ErrorContext(ctx, "Asset update failed for ID %s: %v", req.Id, err)
			return fiber.NewError(fiber.StatusInternalServerError, err.Error())
		}

		logger.InfoContext(ctx, "Asset updated successfully with ID: %s", req.Id)
		return c.JSON(resp)
	}
}

// GetAssetByID retrieves a single asset by its ID from URL parameter
func GetAssetByID(svcGetter ServiceGetter[*service.AssetService]) fiber.Handler {
	return func(c *fiber.Ctx) error {
		ctx := c.UserContext()
		srv := svcGetter(ctx)

		id := c.Params("id")
		if id == "" {
			logger.WarnContext(ctx, "Get asset request missing asset ID")
			return fiber.ErrBadRequest
		}

		logger.InfoContext(ctx, "Get asset request received for ID: %s", id)

		response, err := srv.GetAsset(ctx, &pb.GetAssetByIDRequest{
			Id: id,
		})

		if err != nil {
			if errors.Is(err, service.ErrInvalidAssetUUID) {
				logger.WarnContext(ctx, "Get asset failed: Invalid asset UUID %s", id)
				return fiber.ErrBadRequest
			}
			if errors.Is(err, service.ErrAssetNotFound) {
				logger.InfoContext(ctx, "Asset not found with ID: %s", id)
				return fiber.ErrNotFound
			}
			logger.ErrorContext(ctx, "Get asset failed for ID %s: %v", id, err)
			return fiber.NewError(fiber.StatusInternalServerError, err.Error())
		}

		if response.Asset == nil {
			logger.InfoContext(ctx, "Asset not found with ID: %s", id)
			return fiber.ErrNotFound
		}

		logger.DebugContextWithFields(ctx, "Asset retrieved successfully",
			map[string]interface{}{
				"asset_id":   id,
				"asset_name": response.Asset.GetName(),
				"hostname":   response.Asset.GetHostname(),
			})

		return c.JSON(response)
	}
}

// GetAssets retrieves assets based on filter criteria, pagination, and sorting from URL query parameters
func GetAssets(svcGetter ServiceGetter[*service.AssetService]) fiber.Handler {
	return func(c *fiber.Ctx) error {
		ctx := c.UserContext()
		srv := svcGetter(ctx)

		var req pb.GetAssetsRequest

		// Set pagination parameters
		limit := c.QueryInt("limit", 10)
		req.Limit = int32(limit)

		page := c.QueryInt("page", 0)
		req.Page = int32(page)

		logger.InfoContextWithFields(ctx, "Get assets request received",
			map[string]interface{}{
				"limit": limit,
				"page":  page,
			})

		// Extract sorts and filters from query parameters
		queries := c.Queries()
		req.Sort = extractSorts(queries)
		req.Filter = extractAssetFilters(queries)

		logger.DebugContextWithFields(ctx, "Assets query parameters extracted",
			map[string]interface{}{
				"filter_count": len(req.Filter.String()),
				"sort_count":   len(req.Sort),
			})

		response, err := srv.GetAssets(ctx, &req)
		if err != nil {
			logger.ErrorContext(ctx, "Get assets failed: %v", err)
			return fiber.NewError(fiber.StatusInternalServerError, err.Error())
		}

		logger.InfoContextWithFields(ctx, "Assets retrieved successfully",
			map[string]interface{}{
				"total_count":    response.GetCount(),
				"returned_count": len(response.GetContents()),
			})

		// Transforming the response to add table names as prefixes and convert nested objects to lists
		transformedResponse := transformGetAssetsResponse(response)
		return c.JSON(transformedResponse)
	}
}

// DeleteAsset deletes a single asset by its ID
func DeleteAsset(svcGetter ServiceGetter[*service.AssetService]) fiber.Handler {
	return func(c *fiber.Ctx) error {
		ctx := c.UserContext()
		srv := svcGetter(ctx)

		id := c.Params("id")
		if id == "" {
			logger.WarnContext(ctx, "Delete asset request missing asset ID")
			return fiber.ErrBadRequest
		}

		logger.InfoContext(ctx, "Delete asset request received for ID: %s", id)

		// Convert string ID to UUID
		assetUUID, err := uuid.Parse(id)
		if err != nil {
			logger.WarnContext(ctx, "Delete asset failed: Invalid asset UUID %s", id)
			return fiber.ErrBadRequest
		}

		response, err := srv.DeleteAssets(ctx, &pb.DeleteAssetsRequest{
			Ids: []string{assetUUID.String()},
		})

		if err != nil {
			if errors.Is(err, service.ErrInvalidAssetUUID) {
				logger.WarnContext(ctx, "Delete asset failed: Invalid asset UUID %s", id)
				return fiber.ErrBadRequest
			}
			if errors.Is(err, service.ErrAssetNotFound) {
				logger.InfoContext(ctx, "Delete asset failed: Asset not found with ID %s", id)
				return fiber.ErrNotFound
			}
			logger.ErrorContext(ctx, "Delete asset failed for ID %s: %v", id, err)
			return fiber.NewError(fiber.StatusInternalServerError, err.Error())
		}

		logger.InfoContext(ctx, "Asset deleted successfully with ID: %s", id)
		return c.JSON(response)
	}
}

// DeleteAssets deletes multiple assets by their IDs in the request body
func DeleteAssets(svcGetter ServiceGetter[*service.AssetService]) fiber.Handler {
	return func(c *fiber.Ctx) error {
		ctx := c.UserContext()
		srv := svcGetter(ctx)

		var req pb.DeleteAssetsRequest

		if err := c.BodyParser(&req); err != nil {
			logger.WarnContext(ctx, "Failed to parse delete assets request body: %v", err)
			return fiber.ErrBadRequest
		}

		if len(req.Ids) == 0 {
			logger.WarnContext(ctx, "Delete assets request has empty IDs list")
			return fiber.NewError(fiber.StatusBadRequest, "IDs must not be empty")
		}

		logger.InfoContextWithFields(ctx, "Delete assets request received",
			map[string]interface{}{
				"asset_count": len(req.Ids),
				"has_filter":  req.Filter != nil,
				"exclude":     req.GetExclude(),
			})

		response, err := srv.DeleteAssets(ctx, &req)

		if err != nil {
			if errors.Is(err, service.ErrInvalidAssetUUID) {
				logger.WarnContext(ctx, "Delete assets failed: Invalid asset UUIDs provided")
				return fiber.NewError(fiber.StatusBadRequest, err.Error())
			}
			logger.ErrorContext(ctx, "Delete assets failed: %v", err)
			return fiber.NewError(fiber.StatusInternalServerError, err.Error())
		}

		logger.InfoContext(ctx, "Assets deleted successfully (count: %d)", len(req.Ids))
		return c.JSON(response)
	}
}

// ExportAssets handles the export of assets to CSV format
func ExportAssets(svcGetter ServiceGetter[*service.AssetService]) fiber.Handler {
	return func(c *fiber.Ctx) error {
		ctx := c.UserContext()
		srv := svcGetter(ctx)

		var req pb.ExportAssetsRequest
		if err := c.BodyParser(&req); err != nil {
			logger.WarnContext(ctx, "Failed to parse export assets request body: %v", err)
			return fiber.ErrBadRequest
		}

		logger.InfoContextWithFields(ctx, "Export assets request received", map[string]interface{}{
			"asset_count":            len(req.GetAssetIds()),
			"export_type":            req.GetExportType().String(),
			"selected_columns_count": len(req.GetSelectedColumns()),
		})

		if req.ExportType == pb.ExportType_SELECTED_COLUMNS && len(req.SelectedColumns) == 0 {
			logger.WarnContext(ctx, "Export assets failed: Selected columns must not be empty for SELECTED_COLUMNS export type")
			return fiber.NewError(fiber.StatusBadRequest, "selected columns must not be empty for SELECTED_COLUMNS export type")
		}

		csvData, err := srv.ExportAssets(ctx, &req)
		if err != nil {
			if err == service.ErrInvalidAssetUUID {
				logger.WarnContext(ctx, "Export assets failed: Invalid asset UUIDs provided")
				return fiber.ErrBadRequest
			}
			logger.ErrorContext(ctx, "Export assets failed: %v", err)
			return fiber.NewError(fiber.StatusInternalServerError, err.Error())
		}

		filename := fmt.Sprintf("asset_export_%s.csv", time.Now().Format("20060102_150405"))

		logger.InfoContextWithFields(ctx, "Assets exported successfully", map[string]interface{}{
			"filename":  filename,
			"data_size": len(csvData),
		})

		c.Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
		c.Set("Content-Type", "text/csv")

		return c.Send(csvData)
	}
}

// GetDistinctOSNames returns all distinct OS names from assets
func GetDistinctOSNames(svcGetter ServiceGetter[*service.AssetService]) fiber.Handler {
	return func(c *fiber.Ctx) error {
		ctx := c.UserContext()
		srv := svcGetter(ctx)

		logger.InfoContext(ctx, "Get distinct OS names request received")

		response, err := srv.GetDistinctOSNames(ctx, &pb.GetDistinctOSNamesRequest{})
		if err != nil {
			logger.ErrorContext(ctx, "Get distinct OS names failed: %v", err)
			return fiber.NewError(fiber.StatusInternalServerError, err.Error())
		}

		logger.InfoContext(ctx, "Distinct OS names retrieved successfully")

		return c.JSON(response)
	}
}
