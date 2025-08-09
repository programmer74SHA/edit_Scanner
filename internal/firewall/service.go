package firewall

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/firewall/domain"
	firewallPort "gitlab.apk-group.net/siem/backend/asset-discovery/internal/firewall/port"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/logger"
)

var (
	ErrFirewallNotFound           = domain.ErrFirewallNotFound
	ErrFirewallCreateFailed       = domain.ErrFirewallCreateFailed
	ErrFirewallUpdateFailed       = domain.ErrFirewallUpdateFailed
	ErrFirewallDeleteFailed       = domain.ErrFirewallDeleteFailed
	ErrInvalidFirewallData        = domain.ErrInvalidFirewallData
	ErrFirewallManagementIPExists = domain.ErrFirewallManagementIPExists
	ErrVendorNotFound             = domain.ErrVendorNotFound
)

type service struct {
	repo firewallPort.Repo
}

// NewFirewallService creates a new firewall service instance
func NewFirewallService(repo firewallPort.Repo) firewallPort.Service {
	return &service{
		repo: repo,
	}
}

// CreateFirewall creates a new firewall with all its related data
func (s *service) CreateFirewall(ctx context.Context, firewall domain.FirewallDomain) (domain.FirewallUUID, error) {
	logger.InfoContextWithFields(ctx, "Internal firewall service: Creating firewall", map[string]interface{}{
		"firewall_name":   firewall.Asset.Name,
		"management_ip":   firewall.Details.ManagementIP,
		"vendor_code":     firewall.Asset.VendorCode,
		"zone_count":      len(firewall.Zones),
		"interface_count": len(firewall.Interfaces),
		"vlan_count":      len(firewall.VLANs),
		"policy_count":    len(firewall.Policies),
	})

	// Validate firewall data
	logger.DebugContext(ctx, "Internal firewall service: Validating firewall data for creation")
	if err := firewall.Validate(); err != nil {
		logger.WarnContextWithFields(ctx, "Internal firewall service: Firewall validation failed", map[string]interface{}{
			"error":          err.Error(),
			"firewall_name":  firewall.Asset.Name,
			"management_ip":  firewall.Details.ManagementIP,
			"asset_id_set":   firewall.Details.AssetID != "",
			"asset_id_value": firewall.Details.AssetID,
		})
		return uuid.Nil, ErrInvalidFirewallData
	}

	// Check if vendor exists
	logger.DebugContext(ctx, "Internal firewall service: Checking if vendor exists: %s", firewall.Asset.VendorCode)
	vendorExists, err := s.repo.CheckVendorExists(ctx, firewall.Asset.VendorCode)
	if err != nil {
		logger.ErrorContext(ctx, "Internal firewall service: Failed to check vendor existence: %v", err)
		return uuid.Nil, err
	}
	if !vendorExists {
		logger.WarnContext(ctx, "Internal firewall service: Vendor not found: %s", firewall.Asset.VendorCode)
		return uuid.Nil, ErrVendorNotFound
	}

	// Check if management IP already exists
	logger.DebugContext(ctx, "Internal firewall service: Checking if management IP exists: %s", firewall.Details.ManagementIP)
	ipExists, err := s.repo.CheckManagementIPExists(ctx, firewall.Details.ManagementIP)
	if err != nil {
		logger.ErrorContext(ctx, "Internal firewall service: Failed to check management IP existence: %v", err)
		return uuid.Nil, err
	}
	if ipExists {
		logger.WarnContext(ctx, "Internal firewall service: Management IP already exists: %s", firewall.Details.ManagementIP)
		return uuid.Nil, ErrFirewallManagementIPExists
	}

	// Call repository to create firewall
	logger.DebugContext(ctx, "Internal firewall service: Calling repository to create firewall")
	firewallID, err := s.repo.Create(ctx, firewall)
	if err != nil {
		if errors.Is(err, domain.ErrFirewallManagementIPExists) {
			logger.WarnContext(ctx, "Internal firewall service: Firewall creation failed - Management IP already exists: %s", firewall.Details.ManagementIP)
			return uuid.Nil, err
		}
		logger.ErrorContext(ctx, "Internal firewall service: Firewall creation failed: %v", err)
		return uuid.Nil, ErrFirewallCreateFailed
	}

	logger.InfoContext(ctx, "Internal firewall service: Successfully created firewall with ID: %s", firewallID.String())
	return firewallID, nil
}

// GetFirewallByID retrieves a firewall by its ID
func (s *service) GetFirewallByID(ctx context.Context, firewallID domain.FirewallUUID) (*domain.FirewallDomain, error) {
	logger.InfoContext(ctx, "Internal firewall service: Getting firewall by ID: %s", firewallID.String())

	// Validate UUID format
	if firewallID == uuid.Nil {
		logger.WarnContext(ctx, "Internal firewall service: Invalid firewall UUID provided")
		return nil, ErrInvalidFirewallData
	}

	// Call repository to get firewall
	logger.DebugContext(ctx, "Internal firewall service: Calling repository to get firewall")
	firewall, err := s.repo.GetByID(ctx, firewallID)
	if err != nil {
		if errors.Is(err, domain.ErrFirewallNotFound) {
			logger.WarnContext(ctx, "Internal firewall service: Firewall not found with ID: %s", firewallID.String())
			return nil, err
		}
		logger.ErrorContext(ctx, "Internal firewall service: Failed to get firewall: %v", err)
		return nil, err
	}

	logger.InfoContextWithFields(ctx, "Internal firewall service: Successfully retrieved firewall", map[string]interface{}{
		"firewall_id":     firewallID.String(),
		"firewall_name":   firewall.Asset.Name,
		"management_ip":   firewall.Details.ManagementIP,
		"vendor_code":     firewall.Asset.VendorCode,
		"zone_count":      len(firewall.Zones),
		"interface_count": len(firewall.Interfaces),
		"vlan_count":      len(firewall.VLANs),
		"policy_count":    len(firewall.Policies),
	})

	return firewall, nil
}

// UpdateFirewall updates an existing firewall with all its related data
func (s *service) UpdateFirewall(ctx context.Context, firewallID domain.FirewallUUID, firewall domain.FirewallDomain) error {
	logger.InfoContextWithFields(ctx, "Internal firewall service: Updating firewall", map[string]interface{}{
		"firewall_id":     firewallID.String(),
		"firewall_name":   firewall.Asset.Name,
		"management_ip":   firewall.Details.ManagementIP,
		"vendor_code":     firewall.Asset.VendorCode,
		"zone_count":      len(firewall.Zones),
		"interface_count": len(firewall.Interfaces),
		"vlan_count":      len(firewall.VLANs),
		"policy_count":    len(firewall.Policies),
	})

	logger.DebugContext(ctx, "Internal firewall service: Validating firewall data for update")
	if err := firewall.ValidateForUpdate(); err != nil {
		logger.WarnContextWithFields(ctx, "Internal firewall service: Firewall validation failed", map[string]interface{}{
			"error":         err.Error(),
			"firewall_id":   firewallID.String(),
			"firewall_name": firewall.Asset.Name,
			"management_ip": firewall.Details.ManagementIP,
		})
		return ErrInvalidFirewallData
	}

	if firewallID == uuid.Nil {
		logger.WarnContext(ctx, "Internal firewall service: Invalid firewall UUID provided")
		return ErrInvalidFirewallData
	}

	logger.DebugContext(ctx, "Internal firewall service: Checking if firewall exists")
	existingFirewall, err := s.repo.GetByID(ctx, firewallID)
	if err != nil {
		if errors.Is(err, ErrFirewallNotFound) {
			logger.WarnContext(ctx, "Internal firewall service: Firewall not found for update: %s", firewallID.String())
			return err
		}
		logger.ErrorContext(ctx, "Internal firewall service: Failed to check firewall existence: %v", err)
		return err
	}

	logger.DebugContext(ctx, "Internal firewall service: Checking if vendor exists: %s", firewall.Asset.VendorCode)
	vendorExists, err := s.repo.CheckVendorExists(ctx, firewall.Asset.VendorCode)
	if err != nil {
		logger.ErrorContext(ctx, "Internal firewall service: Failed to check vendor existence: %v", err)
		return err
	}
	if !vendorExists {
		logger.WarnContext(ctx, "Internal firewall service: Vendor not found: %s", firewall.Asset.VendorCode)
		return ErrVendorNotFound
	}

	if existingFirewall.Details.ManagementIP != firewall.Details.ManagementIP {
		logger.DebugContext(ctx, "Internal firewall service: Management IP changed, checking uniqueness: %s", firewall.Details.ManagementIP)
		ipExists, err := s.repo.CheckManagementIPExistsExcludingFirewall(ctx, firewall.Details.ManagementIP, firewallID)
		if err != nil {
			logger.ErrorContext(ctx, "Internal firewall service: Failed to check management IP existence: %v", err)
			return err
		}
		if ipExists {
			logger.WarnContext(ctx, "Internal firewall service: Management IP already exists for another firewall: %s", firewall.Details.ManagementIP)
			return ErrFirewallManagementIPExists
		}
	}

	firewall.Asset.ID = firewallID.String()
	firewall.Details.AssetID = firewallID.String()

	logger.DebugContext(ctx, "Internal firewall service: Calling repository to update firewall")
	if err := s.repo.Update(ctx, firewallID, firewall); err != nil {
		if errors.Is(err, domain.ErrFirewallNotFound) {
			logger.WarnContext(ctx, "Internal firewall service: Firewall not found during update: %s", firewallID.String())
			return err
		}
		if errors.Is(err, domain.ErrFirewallManagementIPExists) {
			logger.WarnContext(ctx, "Internal firewall service: Management IP already exists during update: %s", firewall.Details.ManagementIP)
			return err
		}
		logger.ErrorContext(ctx, "Internal firewall service: Firewall update failed: %v", err)
		return ErrFirewallUpdateFailed
	}

	logger.InfoContext(ctx, "Internal firewall service: Successfully updated firewall with ID: %s", firewallID.String())
	return nil
}

// DeleteFirewall deletes a firewall by ID
func (s *service) DeleteFirewall(ctx context.Context, firewallID domain.FirewallUUID) error {
	logger.InfoContext(ctx, "Internal firewall service: Deleting firewall by ID: %s", firewallID.String())

	if firewallID == uuid.Nil {
		logger.WarnContext(ctx, "Internal firewall service: Invalid firewall UUID provided for delete")
		return ErrInvalidFirewallData
	}

	logger.DebugContext(ctx, "Internal firewall service: Checking if firewall exists before delete")
	_, err := s.repo.GetByID(ctx, firewallID)
	if err != nil {
		if errors.Is(err, domain.ErrFirewallNotFound) {
			logger.WarnContext(ctx, "Internal firewall service: Firewall not found for delete: %s", firewallID.String())
			return err
		}
		logger.ErrorContext(ctx, "Internal firewall service: Failed to check firewall existence for delete: %v", err)
		return err
	}

	logger.DebugContext(ctx, "Internal firewall service: Calling repository to delete firewall")
	if err := s.repo.Delete(ctx, firewallID); err != nil {
		if errors.Is(err, domain.ErrFirewallNotFound) {
			logger.WarnContext(ctx, "Internal firewall service: Firewall not found during delete: %s", firewallID.String())
			return err
		}
		logger.ErrorContext(ctx, "Internal firewall service: Firewall delete failed: %v", err)
		return ErrFirewallDeleteFailed
	}

	logger.InfoContext(ctx, "Internal firewall service: Successfully deleted firewall with ID: %s", firewallID.String())
	return nil
}

// DeleteFirewallBatch deletes multiple firewalls by their IDs
func (s *service) DeleteFirewallBatch(ctx context.Context, firewallIDs []domain.FirewallUUID) error {
	logger.InfoContextWithFields(ctx, "Internal firewall service: Deleting firewalls in batch", map[string]interface{}{
		"firewall_count": len(firewallIDs),
	})

	if len(firewallIDs) == 0 {
		logger.WarnContext(ctx, "Internal firewall service: Empty firewall IDs list provided for batch delete")
		return ErrInvalidFirewallData
	}

	// Validate all UUIDs
	for i, firewallID := range firewallIDs {
		if firewallID == uuid.Nil {
			logger.WarnContext(ctx, "Internal firewall service: Invalid firewall UUID at index %d provided for batch delete", i)
			return ErrInvalidFirewallData
		}
	}

	// Call repository to delete firewalls in batch
	logger.DebugContext(ctx, "Internal firewall service: Calling repository to delete firewalls in batch")
	if err := s.repo.DeleteBatch(ctx, firewallIDs); err != nil {
		logger.ErrorContext(ctx, "Internal firewall service: Firewall batch delete failed: %v", err)
		return ErrFirewallDeleteFailed
	}

	logger.InfoContext(ctx, "Internal firewall service: Successfully deleted %d firewalls in batch", len(firewallIDs))
	return nil
}

// DeleteAllFirewalls deletes all firewalls
func (s *service) DeleteAllFirewalls(ctx context.Context) error {
	logger.InfoContext(ctx, "Internal firewall service: Deleting all firewalls")

	logger.DebugContext(ctx, "Internal firewall service: Calling repository to delete all firewalls")
	if err := s.repo.DeleteAll(ctx); err != nil {
		logger.ErrorContext(ctx, "Internal firewall service: Delete all firewalls failed: %v", err)
		return ErrFirewallDeleteFailed
	}

	logger.InfoContext(ctx, "Internal firewall service: Successfully deleted all firewalls")
	return nil
}

// ListFirewalls retrieves a paginated list of firewalls
func (s *service) ListFirewalls(ctx context.Context, limit int, offset int) (*domain.ListFirewalls, error) {
	logger.InfoContextWithFields(ctx, "Internal firewall service: Listing firewalls", map[string]interface{}{
		"offset": offset,
	})

	if offset < 0 {
		offset = 0 // Minimum offset
	}

	// Call repository to list firewalls
	logger.DebugContext(ctx, "Internal firewall service: Calling repository to list firewalls")
	result, err := s.repo.List(ctx, limit, offset)
	if err != nil {
		logger.ErrorContext(ctx, "Internal firewall service: Failed to list firewalls: %v", err)
		return nil, err
	}

	logger.InfoContextWithFields(ctx, "Internal firewall service: Successfully listed firewalls", map[string]interface{}{
		"returned_count": len(result.Firewalls),
		"total_count":    result.TotalCount,
	})

	return result, nil
}
