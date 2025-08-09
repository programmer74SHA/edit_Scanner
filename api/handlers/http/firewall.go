package http

import (
	"errors"

	"github.com/gofiber/fiber/v2"
	"gitlab.apk-group.net/siem/backend/asset-discovery/api/pb"
	"gitlab.apk-group.net/siem/backend/asset-discovery/api/service"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/logger"
)

// CreateFirewall handles creation of a new firewall via HTTP
func CreateFirewall(svcGetter ServiceGetter[*service.FirewallService]) fiber.Handler {
	return func(c *fiber.Ctx) error {
		ctx := c.UserContext()
		srv := svcGetter(ctx)

		logger.InfoContext(ctx, "Firewall creation request received")

		var req pb.CreateFirewallRequest
		if err := c.BodyParser(&req); err != nil {
			logger.WarnContext(ctx, "Failed to parse firewall creation request body: %v", err)
			return fiber.ErrBadRequest
		}

		logger.DebugContextWithFields(ctx, "Firewall creation request parsed successfully",
			map[string]interface{}{
				"firewall_name":   req.GetAsset().GetName(),
				"management_ip":   req.GetDetails().GetManagementIp(),
				"vendor_code":     req.GetAsset().GetVendorCode(),
				"zone_count":      len(req.GetZones()),
				"interface_count": len(req.GetInterfaces()),
				"vlan_count":      len(req.GetVlans()),
				"policy_count":    len(req.GetPolicies()),
			})

		resp, err := srv.CreateFirewall(ctx, &req)
		if err != nil {
			if errors.Is(err, service.ErrFirewallManagementIPExists) {
				logger.WarnContext(ctx, "Firewall creation failed: Management IP already exists for firewall %s", req.GetAsset().GetName())
				return fiber.NewError(fiber.StatusConflict, "Management IP already exists")
			}
			if errors.Is(err, service.ErrVendorNotFound) {
				logger.WarnContext(ctx, "Firewall creation failed: Vendor not found for firewall %s", req.GetAsset().GetVendorCode())
				return fiber.NewError(fiber.StatusBadRequest, "Vendor not found")
			}
			if errors.Is(err, service.ErrInvalidFirewallData) {
				logger.WarnContext(ctx, "Firewall creation failed: Invalid data for firewall %s", req.GetAsset().GetName())
				return fiber.NewError(fiber.StatusBadRequest, "Invalid firewall data")
			}
			logger.ErrorContext(ctx, "Firewall creation failed: %v", err)
			return fiber.NewError(fiber.StatusInternalServerError, err.Error())
		}

		logger.InfoContextWithFields(ctx, "Firewall creation completed successfully", map[string]interface{}{
			"firewall_id":   resp.GetId(),
			"firewall_name": req.GetAsset().GetName(),
			"success":       resp.GetSuccess(),
		})

		return c.JSON(resp)
	}
}

// GetFirewallByID handles retrieval of a firewall by ID via HTTP
func GetFirewallByID(svcGetter ServiceGetter[*service.FirewallService]) fiber.Handler {
	return func(c *fiber.Ctx) error {
		ctx := c.UserContext()
		srv := svcGetter(ctx)

		firewallID := c.Params("id")
		logger.InfoContext(ctx, "Get firewall by ID request received for ID: %s", firewallID)

		if firewallID == "" {
			logger.WarnContext(ctx, "Empty firewall ID provided")
			return fiber.NewError(fiber.StatusBadRequest, "Firewall ID is required")
		}

		req := pb.GetFirewallByIDRequest{
			Id: firewallID,
		}

		logger.DebugContextWithFields(ctx, "Get firewall by ID request parsed successfully",
			map[string]interface{}{
				"firewall_id": firewallID,
			})

		resp, err := srv.GetFirewallByID(ctx, &req)
		if err != nil {
			if errors.Is(err, service.ErrFirewallNotFound) {
				logger.WarnContext(ctx, "Firewall not found with ID: %s", firewallID)
				return fiber.NewError(fiber.StatusNotFound, "Firewall not found")
			}
			if errors.Is(err, service.ErrInvalidFirewallUUID) {
				logger.WarnContext(ctx, "Invalid firewall UUID format: %s", firewallID)
				return fiber.NewError(fiber.StatusBadRequest, "Invalid firewall ID format")
			}
			logger.ErrorContext(ctx, "Get firewall by ID failed: %v", err)
			return fiber.NewError(fiber.StatusInternalServerError, err.Error())
		}

		logger.InfoContextWithFields(ctx, "Get firewall by ID completed successfully", map[string]interface{}{
			"firewall_id":   firewallID,
			"firewall_name": resp.GetFirewall().GetAsset().GetName(),
			"success":       resp.GetSuccess(),
		})

		return c.JSON(resp)
	}
}

// UpdateFirewall handles updating an existing firewall via HTTP
func UpdateFirewall(svcGetter ServiceGetter[*service.FirewallService]) fiber.Handler {
	return func(c *fiber.Ctx) error {
		ctx := c.UserContext()
		srv := svcGetter(ctx)

		firewallID := c.Params("id")
		logger.InfoContext(ctx, "Firewall update request received for ID: %s", firewallID)

		if firewallID == "" {
			logger.WarnContext(ctx, "Empty firewall ID provided for update")
			return fiber.NewError(fiber.StatusBadRequest, "Firewall ID is required")
		}

		var req pb.UpdateFirewallRequest
		if err := c.BodyParser(&req); err != nil {
			logger.WarnContext(ctx, "Failed to parse firewall update request body: %v", err)
			return fiber.ErrBadRequest
		}

		req.Id = firewallID

		logger.DebugContextWithFields(ctx, "Firewall update request parsed successfully",
			map[string]interface{}{
				"firewall_id":     firewallID,
				"firewall_name":   req.GetAsset().GetName(),
				"management_ip":   req.GetDetails().GetManagementIp(),
				"vendor_code":     req.GetAsset().GetVendorCode(),
				"zone_count":      len(req.GetZones()),
				"interface_count": len(req.GetInterfaces()),
				"vlan_count":      len(req.GetVlans()),
				"policy_count":    len(req.GetPolicies()),
			})

		resp, err := srv.UpdateFirewall(ctx, &req)
		if err != nil {
			if errors.Is(err, service.ErrFirewallNotFound) {
				logger.WarnContext(ctx, "Firewall update failed: Firewall not found with ID %s", firewallID)
				return fiber.NewError(fiber.StatusNotFound, "Firewall not found")
			}
			if errors.Is(err, service.ErrFirewallManagementIPExists) {
				logger.WarnContext(ctx, "Firewall update failed: Management IP already exists for firewall %s", firewallID)
				return fiber.NewError(fiber.StatusConflict, "Management IP already exists")
			}
			if errors.Is(err, service.ErrVendorNotFound) {
				logger.WarnContext(ctx, "Firewall update failed: Vendor not found for firewall %s", firewallID)
				return fiber.NewError(fiber.StatusBadRequest, "Vendor not found")
			}
			if errors.Is(err, service.ErrInvalidFirewallData) {
				logger.WarnContext(ctx, "Firewall update failed: Invalid data for firewall %s", firewallID)
				return fiber.NewError(fiber.StatusBadRequest, "Invalid firewall data")
			}
			if errors.Is(err, service.ErrInvalidFirewallUUID) {
				logger.WarnContext(ctx, "Firewall update failed: Invalid UUID format for firewall %s", firewallID)
				return fiber.NewError(fiber.StatusBadRequest, "Invalid firewall ID format")
			}
			logger.ErrorContext(ctx, "Firewall update failed: %v", err)
			return fiber.NewError(fiber.StatusInternalServerError, err.Error())
		}

		logger.InfoContextWithFields(ctx, "Firewall update completed successfully", map[string]interface{}{
			"firewall_id": firewallID,
			"success":     resp.GetSuccess(),
		})

		return c.JSON(resp)
	}
}

// DeleteFirewall handles deletion of a firewall
func DeleteFirewall(svcGetter ServiceGetter[*service.FirewallService]) fiber.Handler {
	return func(c *fiber.Ctx) error {
		ctx := c.UserContext()
		srv := svcGetter(ctx)

		firewallID := c.Params("id")
		logger.InfoContext(ctx, "Delete firewall request received for ID: %s", firewallID)

		if firewallID == "" {
			logger.WarnContext(ctx, "Empty firewall ID provided for delete")
			return fiber.NewError(fiber.StatusBadRequest, "Firewall ID is required")
		}

		req := pb.DeleteFirewallRequest{
			Id: firewallID,
		}

		logger.DebugContextWithFields(ctx, "Delete firewall request parsed successfully",
			map[string]interface{}{
				"firewall_id": firewallID,
			})

		resp, err := srv.DeleteFirewall(ctx, &req)
		if err != nil {
			if errors.Is(err, service.ErrFirewallNotFound) {
				logger.WarnContext(ctx, "Firewall delete failed: Firewall not found with ID %s", firewallID)
				return fiber.NewError(fiber.StatusNotFound, "Firewall not found")
			}
			if errors.Is(err, service.ErrInvalidFirewallData) {
				logger.WarnContext(ctx, "Firewall delete failed: Invalid data for firewall %s", firewallID)
				return fiber.NewError(fiber.StatusBadRequest, "Invalid firewall data")
			}
			if errors.Is(err, service.ErrInvalidFirewallUUID) {
				logger.WarnContext(ctx, "Firewall delete failed: Invalid UUID format for firewall %s", firewallID)
				return fiber.NewError(fiber.StatusBadRequest, "Invalid firewall ID format")
			}
			logger.ErrorContext(ctx, "Firewall delete failed: %v", err)
			return fiber.NewError(fiber.StatusInternalServerError, err.Error())
		}

		logger.InfoContextWithFields(ctx, "Firewall delete completed successfully", map[string]interface{}{
			"firewall_id": firewallID,
			"success":     resp.GetSuccess(),
		})

		return c.JSON(resp)
	}
}

// DeleteFirewallBatch handles deletion of multiple firewalls
func DeleteFirewallBatch(svcGetter ServiceGetter[*service.FirewallService]) fiber.Handler {
	return func(c *fiber.Ctx) error {
		ctx := c.UserContext()
		srv := svcGetter(ctx)

		logger.InfoContext(ctx, "Firewall batch delete request received")

		var req pb.DeleteFirewallBatchRequest
		if err := c.BodyParser(&req); err != nil {
			logger.WarnContext(ctx, "Failed to parse firewall batch delete request body: %v", err)
			return fiber.ErrBadRequest
		}

		logger.DebugContextWithFields(ctx, "Firewall batch delete request parsed successfully",
			map[string]interface{}{
				"firewall_count": len(req.GetIds()),
			})

		resp, err := srv.DeleteFirewallBatch(ctx, &req)
		if err != nil {
			if errors.Is(err, service.ErrInvalidFirewallData) {
				logger.WarnContext(ctx, "Firewall batch delete failed: Invalid data")
				return fiber.NewError(fiber.StatusBadRequest, "Invalid firewall data")
			}
			if errors.Is(err, service.ErrInvalidFirewallUUID) {
				logger.WarnContext(ctx, "Firewall batch delete failed: Invalid UUID format")
				return fiber.NewError(fiber.StatusBadRequest, "Invalid firewall ID format")
			}
			logger.ErrorContext(ctx, "Firewall batch delete failed: %v", err)
			return fiber.NewError(fiber.StatusInternalServerError, err.Error())
		}

		logger.InfoContextWithFields(ctx, "Firewall batch delete completed successfully", map[string]interface{}{
			"success": resp.GetSuccess(),
		})

		return c.JSON(resp)
	}
}

// DeleteAllFirewalls handles deletion of all firewalls
func DeleteAllFirewalls(svcGetter ServiceGetter[*service.FirewallService]) fiber.Handler {
	return func(c *fiber.Ctx) error {
		ctx := c.UserContext()
		srv := svcGetter(ctx)

		logger.InfoContext(ctx, "Delete all firewalls request received")

		req := pb.DeleteAllFirewallsRequest{}

		logger.DebugContext(ctx, "Delete all firewalls request parsed successfully")

		resp, err := srv.DeleteAllFirewalls(ctx, &req)
		if err != nil {
			logger.ErrorContext(ctx, "Delete all firewalls failed: %v", err)
			return fiber.NewError(fiber.StatusInternalServerError, err.Error())
		}

		logger.InfoContextWithFields(ctx, "Delete all firewalls completed successfully", map[string]interface{}{
			"success": resp.GetSuccess(),
		})

		return c.JSON(resp)
	}
}

// ListFirewalls handles listing firewalls with pagination via HTTP
func ListFirewalls(svcGetter ServiceGetter[*service.FirewallService]) fiber.Handler {
	return func(c *fiber.Ctx) error {
		ctx := c.UserContext()
		srv := svcGetter(ctx)

		logger.InfoContext(ctx, "List firewalls request received")

		// Parse query parameters
		limit := c.QueryInt("limit", 10)
		page := c.QueryInt("page", 0)

		if limit <= 0 {
			logger.WarnContext(ctx, "Invalid limit provided: %d", limit)
			limit = 10 // Default to 10 if invalid
		}

		if page < 0 {
			logger.WarnContext(ctx, "Invalid page provided: %d", page)
			page = 0 // Default to 0 if invalid
		}

		req := pb.ListFirewallsRequest{
			Limit: int32(limit),
			Page:  int32(page),
		}

		logger.DebugContextWithFields(ctx, "List firewalls request parsed successfully",
			map[string]interface{}{
				"limit": limit,
				"page":  page,
			})

		resp, err := srv.ListFirewalls(ctx, &req)
		if err != nil {
			logger.ErrorContext(ctx, "List firewalls failed: %v", err)
			return fiber.NewError(fiber.StatusInternalServerError, err.Error())
		}

		logger.InfoContextWithFields(ctx, "List firewalls completed successfully", map[string]interface{}{
			"returned_count": len(resp.GetContents()),
			"total_count":    resp.GetCount(),
		})

		return c.JSON(resp)
	}
}
