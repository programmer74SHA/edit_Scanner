package service

import (
	"context"
	"errors"

	"github.com/google/uuid"

	"gitlab.apk-group.net/siem/backend/asset-discovery/api/pb"
	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/firewall"
	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/firewall/domain"
	firewallPort "gitlab.apk-group.net/siem/backend/asset-discovery/internal/firewall/port"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/logger"
)

var (
	ErrFirewallNotFound           = firewall.ErrFirewallNotFound
	ErrFirewallCreateFailed       = firewall.ErrFirewallCreateFailed
	ErrFirewallUpdateFailed       = firewall.ErrFirewallUpdateFailed
	ErrFirewallDeleteFailed       = firewall.ErrFirewallDeleteFailed
	ErrInvalidFirewallData        = firewall.ErrInvalidFirewallData
	ErrFirewallManagementIPExists = firewall.ErrFirewallManagementIPExists
	ErrVendorNotFound             = firewall.ErrVendorNotFound
	ErrInvalidFirewallUUID        = errors.New("invalid firewall UUID")
)

// FirewallService provides API operations for firewalls
type FirewallService struct {
	service firewallPort.Service
}

// NewFirewallService creates a new FirewallService
func NewFirewallService(srv firewallPort.Service) *FirewallService {
	return &FirewallService{
		service: srv,
	}
}

// CreateFirewall handles creation of a new firewall via API
func (s *FirewallService) CreateFirewall(ctx context.Context, req *pb.CreateFirewallRequest) (*pb.CreateFirewallResponse, error) {
	logger.InfoContextWithFields(ctx, "API firewall service: Creating new firewall", map[string]interface{}{
		"firewall_name":   req.GetAsset().GetName(),
		"management_ip":   req.GetDetails().GetManagementIp(),
		"vendor_code":     req.GetAsset().GetVendorCode(),
		"zone_count":      len(req.GetZones()),
		"interface_count": len(req.GetInterfaces()),
		"vlan_count":      len(req.GetVlans()),
		"policy_count":    len(req.GetPolicies()),
	})

	// Convert protobuf request to domain model
	logger.DebugContext(ctx, "API firewall service: Converting protobuf request to domain model")
	firewallDomain, err := s.convertPbToDomain(req)
	if err != nil {
		logger.ErrorContextWithFields(ctx, "API firewall service: Failed to convert protobuf to domain", map[string]interface{}{
			"error":          err.Error(),
			"firewall_name":  req.GetAsset().GetName(),
			"management_ip":  req.GetDetails().GetManagementIp(),
			"has_asset_id":   req.GetDetails().GetAssetId() != "",
			"asset_id_value": req.GetDetails().GetAssetId(),
		})
		return &pb.CreateFirewallResponse{
			Success: false,
			Message: "Invalid firewall data: " + err.Error(),
		}, err
	}

	// Call internal service to create firewall
	logger.DebugContext(ctx, "API firewall service: Calling internal service to create firewall")
	firewallID, err := s.service.CreateFirewall(ctx, *firewallDomain)
	if err != nil {
		if errors.Is(err, ErrFirewallManagementIPExists) {
			logger.WarnContext(ctx, "API firewall service: Firewall creation failed - Management IP already exists: %s", req.GetDetails().GetManagementIp())
			return &pb.CreateFirewallResponse{
				Success: false,
				Message: "Management IP already exists",
			}, err
		}
		if errors.Is(err, ErrVendorNotFound) {
			logger.WarnContext(ctx, "API firewall service: Firewall creation failed - Vendor not found: %s", req.GetAsset().GetVendorCode())
			return &pb.CreateFirewallResponse{
				Success: false,
				Message: "Vendor not found",
			}, err
		}
		if errors.Is(err, ErrInvalidFirewallData) {
			logger.WarnContext(ctx, "API firewall service: Firewall creation failed - Invalid data: %v", err)
			return &pb.CreateFirewallResponse{
				Success: false,
				Message: "Invalid firewall data",
			}, err
		}
		logger.ErrorContext(ctx, "API firewall service: Firewall creation failed: %v", err)
		return &pb.CreateFirewallResponse{
			Success: false,
			Message: "Failed to create firewall",
		}, err
	}

	logger.InfoContext(ctx, "API firewall service: Successfully created firewall with ID: %s", firewallID.String())
	return &pb.CreateFirewallResponse{
		Id:      firewallID.String(),
		Success: true,
		Message: "Firewall created successfully",
	}, nil
}

// GetFirewallByID retrieves a firewall by its ID via API
func (s *FirewallService) GetFirewallByID(ctx context.Context, req *pb.GetFirewallByIDRequest) (*pb.GetFirewallByIDResponse, error) {
	logger.InfoContext(ctx, "API firewall service: Getting firewall by ID: %s", req.GetId())

	// Validate input
	if req.GetId() == "" {
		logger.WarnContext(ctx, "API firewall service: Empty firewall ID provided")
		return &pb.GetFirewallByIDResponse{
			Success: false,
			Message: "Firewall ID is required",
		}, ErrInvalidFirewallUUID
	}

	// Parse UUID
	firewallUUID, err := uuid.Parse(req.GetId())
	if err != nil {
		logger.WarnContext(ctx, "API firewall service: Invalid firewall UUID format: %s", req.GetId())
		return &pb.GetFirewallByIDResponse{
			Success: false,
			Message: "Invalid firewall ID format",
		}, ErrInvalidFirewallUUID
	}

	// Call internal service to get firewall
	logger.DebugContext(ctx, "API firewall service: Calling internal service to get firewall")
	firewallDomain, err := s.service.GetFirewallByID(ctx, firewallUUID)
	if err != nil {
		if errors.Is(err, ErrFirewallNotFound) {
			logger.WarnContext(ctx, "API firewall service: Firewall not found with ID: %s", req.GetId())
			return &pb.GetFirewallByIDResponse{
				Success: false,
				Message: "Firewall not found",
			}, err
		}
		logger.ErrorContext(ctx, "API firewall service: Failed to get firewall: %v", err)
		return &pb.GetFirewallByIDResponse{
			Success: false,
			Message: "Failed to retrieve firewall",
		}, err
	}

	// Convert domain model to protobuf
	logger.DebugContext(ctx, "API firewall service: Converting domain model to protobuf")
	firewallPb, err := s.convertDomainToPb(firewallDomain)
	if err != nil {
		logger.ErrorContext(ctx, "API firewall service: Failed to convert domain to protobuf: %v", err)
		return &pb.GetFirewallByIDResponse{
			Success: false,
			Message: "Failed to convert firewall data",
		}, err
	}

	logger.InfoContext(ctx, "API firewall service: Successfully retrieved firewall with ID: %s", req.GetId())
	return &pb.GetFirewallByIDResponse{
		Success:  true,
		Message:  "Firewall retrieved successfully",
		Firewall: firewallPb,
	}, nil
}

// UpdateFirewall handles updating an existing firewall via API
func (s *FirewallService) UpdateFirewall(ctx context.Context, req *pb.UpdateFirewallRequest) (*pb.UpdateFirewallResponse, error) {
	logger.InfoContextWithFields(ctx, "API firewall service: Updating firewall", map[string]interface{}{
		"firewall_id":     req.GetId(),
		"firewall_name":   req.GetAsset().GetName(),
		"management_ip":   req.GetDetails().GetManagementIp(),
		"vendor_code":     req.GetAsset().GetVendorCode(),
		"zone_count":      len(req.GetZones()),
		"interface_count": len(req.GetInterfaces()),
		"vlan_count":      len(req.GetVlans()),
		"policy_count":    len(req.GetPolicies()),
	})

	if req.GetId() == "" {
		logger.WarnContext(ctx, "API firewall service: Empty firewall ID provided for update")
		return &pb.UpdateFirewallResponse{
			Success: false,
			Message: "Firewall ID is required",
		}, ErrInvalidFirewallUUID
	}

	firewallUUID, err := uuid.Parse(req.GetId())
	if err != nil {
		logger.WarnContext(ctx, "API firewall service: Invalid firewall UUID format for update: %s", req.GetId())
		return &pb.UpdateFirewallResponse{
			Success: false,
			Message: "Invalid firewall ID format",
		}, ErrInvalidFirewallUUID
	}

	updateReq := &pb.CreateFirewallRequest{
		Asset:      req.GetAsset(),
		Details:    req.GetDetails(),
		Zones:      req.GetZones(),
		Interfaces: req.GetInterfaces(),
		Vlans:      req.GetVlans(),
		Policies:   req.GetPolicies(),
	}

	// Convert protobuf request to domain model
	logger.DebugContext(ctx, "API firewall service: Converting protobuf request to domain model for update")
	firewallDomain, err := s.convertPbToDomain(updateReq)
	if err != nil {
		logger.ErrorContextWithFields(ctx, "API firewall service: Failed to convert protobuf to domain for update", map[string]interface{}{
			"error":         err.Error(),
			"firewall_id":   req.GetId(),
			"firewall_name": req.GetAsset().GetName(),
			"management_ip": req.GetDetails().GetManagementIp(),
		})
		return &pb.UpdateFirewallResponse{
			Success: false,
			Message: "Invalid firewall data: " + err.Error(),
		}, err
	}

	logger.DebugContext(ctx, "API firewall service: Calling internal service to update firewall")
	err = s.service.UpdateFirewall(ctx, firewallUUID, *firewallDomain)
	if err != nil {
		if errors.Is(err, ErrFirewallNotFound) {
			logger.WarnContext(ctx, "API firewall service: Firewall not found for update: %s", req.GetId())
			return &pb.UpdateFirewallResponse{
				Success: false,
				Message: "Firewall not found",
			}, err
		}
		if errors.Is(err, ErrFirewallManagementIPExists) {
			logger.WarnContext(ctx, "API firewall service: Firewall update failed - Management IP already exists: %s", req.GetDetails().GetManagementIp())
			return &pb.UpdateFirewallResponse{
				Success: false,
				Message: "Management IP already exists",
			}, err
		}
		if errors.Is(err, ErrVendorNotFound) {
			logger.WarnContext(ctx, "API firewall service: Firewall update failed - Vendor not found: %s", req.GetAsset().GetVendorCode())
			return &pb.UpdateFirewallResponse{
				Success: false,
				Message: "Vendor not found",
			}, err
		}
		if errors.Is(err, ErrInvalidFirewallData) {
			logger.WarnContext(ctx, "API firewall service: Firewall update failed - Invalid data: %v", err)
			return &pb.UpdateFirewallResponse{
				Success: false,
				Message: "Invalid firewall data",
			}, err
		}
		logger.ErrorContext(ctx, "API firewall service: Firewall update failed: %v", err)
		return &pb.UpdateFirewallResponse{
			Success: false,
			Message: "Failed to update firewall",
		}, err
	}

	logger.InfoContext(ctx, "API firewall service: Successfully updated firewall with ID: %s", req.GetId())
	return &pb.UpdateFirewallResponse{
		Success: true,
		Message: "Firewall updated successfully",
	}, nil
}

// DeleteFirewall handles deletion of a firewall by ID
func (s *FirewallService) DeleteFirewall(ctx context.Context, req *pb.DeleteFirewallRequest) (*pb.DeleteFirewallResponse, error) {
	logger.InfoContext(ctx, "API firewall service: Deleting firewall by ID: %s", req.GetId())

	if req.GetId() == "" {
		logger.WarnContext(ctx, "API firewall service: Empty firewall ID provided")
		return &pb.DeleteFirewallResponse{
			Success: false,
			Message: "Firewall ID is required",
		}, ErrInvalidFirewallUUID
	}

	firewallUUID, err := uuid.Parse(req.GetId())
	if err != nil {
		logger.WarnContext(ctx, "API firewall service: Invalid firewall UUID format: %s", req.GetId())
		return &pb.DeleteFirewallResponse{
			Success: false,
			Message: "Invalid firewall ID format",
		}, ErrInvalidFirewallUUID
	}

	logger.DebugContext(ctx, "API firewall service: Calling internal service to delete firewall")
	err = s.service.DeleteFirewall(ctx, firewallUUID)
	if err != nil {
		if errors.Is(err, ErrFirewallNotFound) {
			logger.WarnContext(ctx, "API firewall service: Firewall not found for delete: %s", req.GetId())
			return &pb.DeleteFirewallResponse{
				Success: false,
				Message: "Firewall not found",
			}, err
		}
		if errors.Is(err, ErrInvalidFirewallData) {
			logger.WarnContext(ctx, "API firewall service: Firewall delete failed - Invalid data: %v", err)
			return &pb.DeleteFirewallResponse{
				Success: false,
				Message: "Invalid firewall data",
			}, err
		}
		logger.ErrorContext(ctx, "API firewall service: Firewall delete failed: %v", err)
		return &pb.DeleteFirewallResponse{
			Success: false,
			Message: "Failed to delete firewall",
		}, err
	}

	logger.InfoContext(ctx, "API firewall service: Successfully deleted firewall with ID: %s", req.GetId())
	return &pb.DeleteFirewallResponse{
		Success: true,
		Message: "Firewall deleted successfully",
	}, nil
}

// DeleteFirewallBatch handles deletion of multiple firewalls by IDs
func (s *FirewallService) DeleteFirewallBatch(ctx context.Context, req *pb.DeleteFirewallBatchRequest) (*pb.DeleteFirewallBatchResponse, error) {
	logger.InfoContextWithFields(ctx, "API firewall service: Deleting firewalls in batch", map[string]interface{}{
		"firewall_count": len(req.GetIds()),
	})

	if len(req.GetIds()) == 0 {
		logger.WarnContext(ctx, "API firewall service: Empty firewall IDs list provided")
		return &pb.DeleteFirewallBatchResponse{
			Success: false,
			Message: "At least one firewall ID is required",
		}, ErrInvalidFirewallData
	}

	firewallUUIDs := make([]domain.FirewallUUID, 0, len(req.GetIds()))
	for i, idStr := range req.GetIds() {
		if idStr == "" {
			logger.WarnContext(ctx, "API firewall service: Empty firewall ID at index %d", i)
			return &pb.DeleteFirewallBatchResponse{
				Success: false,
				Message: "All firewall IDs must be provided",
			}, ErrInvalidFirewallUUID
		}

		firewallUUID, err := uuid.Parse(idStr)
		if err != nil {
			logger.WarnContext(ctx, "API firewall service: Invalid firewall UUID format at index %d: %s", i, idStr)
			return &pb.DeleteFirewallBatchResponse{
				Success: false,
				Message: "Invalid firewall ID format",
			}, ErrInvalidFirewallUUID
		}
		firewallUUIDs = append(firewallUUIDs, firewallUUID)
	}

	logger.DebugContext(ctx, "API firewall service: Calling internal service to delete firewalls in batch")
	err := s.service.DeleteFirewallBatch(ctx, firewallUUIDs)
	if err != nil {
		if errors.Is(err, ErrInvalidFirewallData) {
			logger.WarnContext(ctx, "API firewall service: Firewall batch delete failed - Invalid data: %v", err)
			return &pb.DeleteFirewallBatchResponse{
				Success: false,
				Message: "Invalid firewall data",
			}, err
		}
		logger.ErrorContext(ctx, "API firewall service: Firewall batch delete failed: %v", err)
		return &pb.DeleteFirewallBatchResponse{
			Success: false,
			Message: "Failed to delete firewalls",
		}, err
	}

	logger.InfoContext(ctx, "API firewall service: Successfully deleted %d firewalls in batch", len(firewallUUIDs))
	return &pb.DeleteFirewallBatchResponse{
		Success: true,
		Message: "Firewalls deleted successfully",
	}, nil
}

// DeleteAllFirewalls handles deletion of all firewalls
func (s *FirewallService) DeleteAllFirewalls(ctx context.Context, req *pb.DeleteAllFirewallsRequest) (*pb.DeleteAllFirewallsResponse, error) {
	logger.InfoContext(ctx, "API firewall service: Deleting all firewalls")

	logger.DebugContext(ctx, "API firewall service: Calling internal service to delete all firewalls")
	err := s.service.DeleteAllFirewalls(ctx)
	if err != nil {
		logger.ErrorContext(ctx, "API firewall service: Delete all firewalls failed: %v", err)
		return &pb.DeleteAllFirewallsResponse{
			Success: false,
			Message: "Failed to delete all firewalls",
		}, err
	}

	logger.InfoContext(ctx, "API firewall service: Successfully deleted all firewalls")
	return &pb.DeleteAllFirewallsResponse{
		Success: true,
		Message: "All firewalls deleted successfully",
	}, nil
}

// ListFirewalls retrieves a paginated list of firewalls via API
func (s *FirewallService) ListFirewalls(ctx context.Context, req *pb.ListFirewallsRequest) (*pb.ListFirewallsResponse, error) {
	logger.InfoContextWithFields(ctx, "API firewall service: Listing firewalls", map[string]interface{}{
		"limit": req.GetLimit(),
		"page":  req.GetPage(),
	})

	// Set defaults and validate pagination parameters
	limit := req.GetLimit()
	page := req.GetPage()

	// Convert page to offset
	offset := int(page) * int(limit)

	logger.DebugContextWithFields(ctx, "API firewall service: Final pagination parameters", map[string]interface{}{
		"limit":  limit,
		"page":   page,
		"offset": offset,
	})

	// Call internal service to list firewalls
	logger.DebugContext(ctx, "API firewall service: Calling internal service to list firewalls")
	result, err := s.service.ListFirewalls(ctx, int(limit), offset)
	if err != nil {
		logger.ErrorContext(ctx, "API firewall service: Failed to list firewalls: %v", err)
		return &pb.ListFirewallsResponse{
			Contents: nil,
			Count:    0,
		}, err
	}

	// Convert domain models to flattened protobuf format
	logger.DebugContextWithFields(ctx, "API firewall service: Converting domain models to flattened protobuf", map[string]interface{}{
		"firewall_count": len(result.Firewalls),
		"total_count":    result.TotalCount,
	})

	contents := make([]*pb.FirewallListItemFlat, len(result.Firewalls))
	for i, firewallDomain := range result.Firewalls {
		// Convert to flattened format by combining asset and details fields
		var lastSyncStr string
		if firewallDomain.Details.LastSync != nil {
			lastSyncStr = firewallDomain.Details.LastSync.Format("2006-01-02T15:04:05Z")
		}

		var discoveredBy string
		if firewallDomain.Asset.DiscoveredBy != nil {
			discoveredBy = *firewallDomain.Asset.DiscoveredBy
		}

		contents[i] = &pb.FirewallListItemFlat{
			// Asset fields
			AssetId:          firewallDomain.Asset.ID,
			VendorCode:       firewallDomain.Asset.VendorCode,
			Name:             firewallDomain.Asset.Name,
			Domain:           firewallDomain.Asset.Domain,
			Hostname:         firewallDomain.Asset.Hostname,
			OsName:           firewallDomain.Asset.OSName,
			OsVersion:        firewallDomain.Asset.OSVersion,
			Description:      firewallDomain.Asset.Description,
			AssetType:        firewallDomain.Asset.AssetType,
			DiscoveredBy:     discoveredBy,
			Risk:             int32(firewallDomain.Asset.Risk),
			LoggingCompleted: firewallDomain.Asset.LoggingCompleted,
			AssetValue:       firewallDomain.Asset.AssetValue,

			// Details fields
			DetailsId:       firewallDomain.Details.ID,
			Model:           firewallDomain.Details.Model,
			FirmwareVersion: firewallDomain.Details.FirmwareVersion,
			SerialNumber:    firewallDomain.Details.SerialNumber,
			IsHaEnabled:     firewallDomain.Details.IsHAEnabled,
			HaRole:          firewallDomain.Details.HARole,
			ManagementIp:    firewallDomain.Details.ManagementIP,
			SiteName:        firewallDomain.Details.SiteName,
			Location:        firewallDomain.Details.Location,
			Status:          firewallDomain.Details.Status,
			LastSync:        lastSyncStr,
			SyncStatus:      firewallDomain.Details.SyncStatus,
		}
	}

	logger.InfoContextWithFields(ctx, "API firewall service: Successfully listed firewalls", map[string]interface{}{
		"returned_count": len(contents),
		"total_count":    result.TotalCount,
		"limit":          limit,
		"page":           page,
	})

	return &pb.ListFirewallsResponse{
		Contents: contents,
		Count:    int32(result.TotalCount),
	}, nil
}

// convertPbToDomain converts protobuf request to domain model
func (s *FirewallService) convertPbToDomain(req *pb.CreateFirewallRequest) (*domain.FirewallDomain, error) {
	logger.DebugContext(context.Background(), "API firewall service: Starting protobuf to domain conversion")

	if req.GetAsset() == nil {
		return nil, errors.New("asset data is required")
	}
	if req.GetDetails() == nil {
		return nil, errors.New("details data is required")
	}

	// Convert asset
	asset := domain.FirewallAsset{
		ID:               req.GetAsset().GetId(),
		VendorCode:       req.GetAsset().GetVendorCode(),
		Name:             req.GetAsset().GetName(),
		Domain:           req.GetAsset().GetDomain(),
		Hostname:         req.GetAsset().GetHostname(),
		OSName:           req.GetAsset().GetOsName(),
		OSVersion:        req.GetAsset().GetOsVersion(),
		Description:      req.GetAsset().GetDescription(),
		AssetType:        "firewall", // Hard-coded value
		Risk:             int(req.GetAsset().GetRisk()),
		LoggingCompleted: req.GetAsset().GetLoggingCompleted(),
		AssetValue:       req.GetAsset().GetAssetValue(),
	}

	if req.GetAsset().DiscoveredBy != "" {
		asset.DiscoveredBy = &req.GetAsset().DiscoveredBy
	}

	// Convert details
	details := domain.FirewallDetails{
		ID:              req.GetDetails().GetId(),
		Model:           req.GetDetails().GetModel(),
		FirmwareVersion: req.GetDetails().GetFirmwareVersion(),
		SerialNumber:    req.GetDetails().GetSerialNumber(),
		IsHAEnabled:     req.GetDetails().GetIsHaEnabled(),
		HARole:          req.GetDetails().GetHaRole(),
		ManagementIP:    req.GetDetails().GetManagementIp(),
		SiteName:        req.GetDetails().GetSiteName(),
		Location:        req.GetDetails().GetLocation(),
		Status:          req.GetDetails().GetStatus(),
		SyncStatus:      req.GetDetails().GetSyncStatus(),
	}

	if req.GetDetails().GetAssetId() != "" {
		details.AssetID = req.GetDetails().GetAssetId()
		logger.DebugContext(context.Background(), "API firewall service: AssetID provided in request: %s", details.AssetID)
	} else {
		logger.DebugContext(context.Background(), "API firewall service: No AssetID provided, will be generated by storage layer")
	}

	// Convert zones
	zones := make([]domain.FirewallZone, 0, len(req.GetZones()))
	for _, zone := range req.GetZones() {
		logger.DebugContext(context.Background(), "API firewall service: Converting zone: %s", zone.GetZoneName())

		var interfaceNames []string
		var vlanNames []string

		if zone.GetInterfaces() != nil {
			interfaceNames = zone.GetInterfaces().GetInterfaceName()
			vlanNames = zone.GetInterfaces().GetVlanName()
		}

		zones = append(zones, domain.FirewallZone{
			ID:                    zone.GetId(),
			ZoneName:              zone.GetZoneName(),
			ZoneType:              zone.GetZoneType(),
			VendorZoneType:        zone.GetVendorZoneType(),
			Description:           zone.GetDescription(),
			ZoneMode:              zone.GetZoneMode(),
			IntrazoneAction:       zone.GetIntrazoneAction(),
			ZoneProtectionProfile: zone.GetZoneProtectionProfile(),
			LogSetting:            zone.GetLogSetting(),
			Interfaces: domain.ZoneInterfaces{
				InterfaceName: interfaceNames,
				VLANName:      vlanNames,
			},
		})
	}

	// Convert interfaces
	interfaces := make([]domain.FirewallInterface, 0, len(req.GetInterfaces()))
	for _, iface := range req.GetInterfaces() {
		logger.DebugContext(context.Background(), "API firewall service: Converting interface: %s", iface.GetInterfaceName())

		secondaryIPs := make([]domain.SecondaryIP, 0, len(iface.GetSecondaryIps()))
		for _, secIP := range iface.GetSecondaryIps() {
			cidr := int(secIP.GetCidrPrefix())
			secondaryIP := domain.SecondaryIP{
				ID:          int(secIP.GetId()),
				IP:          secIP.GetIp(),
				Allowaccess: secIP.GetAllowaccess(),
			}
			if cidr != 0 {
				secondaryIP.CIDRPrefix = &cidr
			}
			secondaryIPs = append(secondaryIPs, secondaryIP)
		}

		if iface.GetVendorSpecificConfig() == "" {
			iface.VendorSpecificConfig = "{}"
		}

		firewallInterface := domain.FirewallInterface{
			ID:                   iface.GetId(),
			InterfaceName:        iface.GetInterfaceName(),
			InterfaceType:        iface.GetInterfaceType(),
			VirtualRouter:        iface.GetVirtualRouter(),
			VirtualSystem:        iface.GetVirtualSystem(),
			Description:          iface.GetDescription(),
			OperationalStatus:    iface.GetOperationalStatus(),
			AdminStatus:          iface.GetAdminStatus(),
			MacAddress:           iface.GetMacAddress(),
			VendorSpecificConfig: iface.VendorSpecificConfig,
			SecondaryIPs:         secondaryIPs,
			PrimaryIP:            iface.GetPrimaryIp(),
		}

		if iface.ParentInterfaceName != "" {
			parentName := iface.ParentInterfaceName
			firewallInterface.ParentInterfaceName = &parentName
		}

		if iface.VlanId != 0 {
			vlanID := int(iface.VlanId)
			firewallInterface.VLANId = &vlanID
		}

		if iface.CidrPrefix != 0 {
			cidr := int(iface.CidrPrefix)
			firewallInterface.CIDRPrefix = &cidr
		}

		interfaces = append(interfaces, firewallInterface)
	}

	// Convert VLANs
	vlans := make([]domain.FirewallVLAN, 0, len(req.GetVlans()))
	for _, vlan := range req.GetVlans() {
		logger.DebugContext(context.Background(), "API firewall service: Converting VLAN: %s", vlan.GetVlanName())

		if vlan.GetVendorSpecificConfig() == "" {
			vlan.VendorSpecificConfig = "{}"
		}

		vlans = append(vlans, domain.FirewallVLAN{
			ID:                   vlan.GetId(),
			VLANNumber:           int(vlan.GetVlanNumber()),
			VLANName:             vlan.GetVlanName(),
			Description:          vlan.GetDescription(),
			IsNative:             vlan.GetIsNative(),
			VendorSpecificConfig: vlan.VendorSpecificConfig,
			Interfaces:           vlan.GetInterfaces(),
		})
	}

	// Convert policies
	policies := make([]domain.FirewallPolicy, 0, len(req.GetPolicies()))
	for _, policy := range req.GetPolicies() {
		logger.DebugContext(context.Background(), "API firewall service: Converting policy: %s", policy.GetPolicyName())

		if policy.GetVendorSpecificConfig() == "" {
			policy.VendorSpecificConfig = "{}"
		}

		firewallPolicy := domain.FirewallPolicy{
			ID:                   policy.GetId(),
			PolicyName:           policy.GetPolicyName(),
			SrcAddresses:         policy.GetSrcAddresses(),
			DstAddresses:         policy.GetDstAddresses(),
			Services:             policy.GetServices(),
			Action:               policy.GetAction(),
			PolicyType:           policy.GetPolicyType(),
			Status:               policy.GetStatus(),
			VendorSpecificConfig: policy.VendorSpecificConfig,
			Schedule:             policy.GetSchedule(),
		}

		if policy.PolicyId != 0 {
			policyID := int(policy.PolicyId)
			firewallPolicy.PolicyID = &policyID
		}

		if policy.RuleOrder != 0 {
			ruleOrder := int(policy.RuleOrder)
			firewallPolicy.RuleOrder = &ruleOrder
		}

		policies = append(policies, firewallPolicy)
	}

	logger.DebugContext(context.Background(), "API firewall service: Successfully converted protobuf to domain model")

	logger.DebugContextWithFields(context.Background(), "API firewall service: Domain object created", map[string]interface{}{
		"asset_id_in_asset":   asset.ID,
		"asset_id_in_details": details.AssetID,
		"asset_name":          asset.Name,
		"management_ip":       details.ManagementIP,
		"details_id":          details.ID,
		"zone_count":          len(zones),
		"interface_count":     len(interfaces),
		"vlan_count":          len(vlans),
		"policy_count":        len(policies),
	})

	return &domain.FirewallDomain{
		Asset:      asset,
		Details:    details,
		Zones:      zones,
		Interfaces: interfaces,
		VLANs:      vlans,
		Policies:   policies,
	}, nil
}

// convertDomainToPb converts domain model to protobuf response
func (s *FirewallService) convertDomainToPb(domainModel *domain.FirewallDomain) (*pb.Firewall, error) {
	logger.DebugContext(context.Background(), "API firewall service: Starting domain to protobuf conversion")

	// Convert asset
	asset := &pb.FirewallAsset{
		Id:               domainModel.Asset.ID,
		VendorCode:       domainModel.Asset.VendorCode,
		Name:             domainModel.Asset.Name,
		Domain:           domainModel.Asset.Domain,
		Hostname:         domainModel.Asset.Hostname,
		OsName:           domainModel.Asset.OSName,
		OsVersion:        domainModel.Asset.OSVersion,
		Description:      domainModel.Asset.Description,
		AssetType:        domainModel.Asset.AssetType,
		Risk:             int32(domainModel.Asset.Risk),
		LoggingCompleted: domainModel.Asset.LoggingCompleted,
		AssetValue:       domainModel.Asset.AssetValue,
	}

	if domainModel.Asset.DiscoveredBy != nil {
		asset.DiscoveredBy = *domainModel.Asset.DiscoveredBy
	}

	// Convert details
	var lastSyncStr string
	if domainModel.Details.LastSync != nil {
		lastSyncStr = domainModel.Details.LastSync.Format("2006-01-02T15:04:05Z")
	}

	details := &pb.FirewallDetails{
		Id:              domainModel.Details.ID,
		AssetId:         domainModel.Details.AssetID,
		Model:           domainModel.Details.Model,
		FirmwareVersion: domainModel.Details.FirmwareVersion,
		SerialNumber:    domainModel.Details.SerialNumber,
		IsHaEnabled:     domainModel.Details.IsHAEnabled,
		HaRole:          domainModel.Details.HARole,
		ManagementIp:    domainModel.Details.ManagementIP,
		SiteName:        domainModel.Details.SiteName,
		Location:        domainModel.Details.Location,
		Status:          domainModel.Details.Status,
		LastSync:        lastSyncStr,
		SyncStatus:      domainModel.Details.SyncStatus,
	}

	// Convert zones
	zones := make([]*pb.FirewallZone, 0, len(domainModel.Zones))
	for _, zone := range domainModel.Zones {
		logger.DebugContext(context.Background(), "API firewall service: Converting zone: %s", zone.ZoneName)

		zoneInterfaces := &pb.ZoneInterfaces{
			InterfaceName: zone.Interfaces.InterfaceName,
			VlanName:      zone.Interfaces.VLANName,
		}

		zones = append(zones, &pb.FirewallZone{
			Id:                    zone.ID,
			ZoneName:              zone.ZoneName,
			ZoneType:              zone.ZoneType,
			VendorZoneType:        zone.VendorZoneType,
			Description:           zone.Description,
			ZoneMode:              zone.ZoneMode,
			IntrazoneAction:       zone.IntrazoneAction,
			ZoneProtectionProfile: zone.ZoneProtectionProfile,
			LogSetting:            zone.LogSetting,
			Interfaces:            zoneInterfaces,
		})
	}

	// Convert interfaces
	interfaces := make([]*pb.FirewallInterface, 0, len(domainModel.Interfaces))
	for _, iface := range domainModel.Interfaces {
		logger.DebugContext(context.Background(), "API firewall service: Converting interface: %s", iface.InterfaceName)

		secondaryIPs := make([]*pb.SecondaryIP, 0, len(iface.SecondaryIPs))
		for _, secIP := range iface.SecondaryIPs {
			secondaryIP := &pb.SecondaryIP{
				Id:          int32(secIP.ID),
				Ip:          secIP.IP,
				Allowaccess: secIP.Allowaccess,
			}
			if secIP.CIDRPrefix != nil {
				cidr := int32(*secIP.CIDRPrefix)
				secondaryIP.CidrPrefix = cidr
			}
			secondaryIPs = append(secondaryIPs, secondaryIP)
		}

		firewallInterface := &pb.FirewallInterface{
			Id:                   iface.ID,
			InterfaceName:        iface.InterfaceName,
			InterfaceType:        iface.InterfaceType,
			VirtualRouter:        iface.VirtualRouter,
			VirtualSystem:        iface.VirtualSystem,
			Description:          iface.Description,
			OperationalStatus:    iface.OperationalStatus,
			AdminStatus:          iface.AdminStatus,
			MacAddress:           iface.MacAddress,
			VendorSpecificConfig: iface.VendorSpecificConfig,
			SecondaryIps:         secondaryIPs,
			PrimaryIp:            iface.PrimaryIP,
		}

		if iface.ParentInterfaceName != nil {
			firewallInterface.ParentInterfaceName = *iface.ParentInterfaceName
		}

		if iface.VLANId != nil {
			vlanID := int32(*iface.VLANId)
			firewallInterface.VlanId = vlanID
		}

		if iface.CIDRPrefix != nil {
			cidr := int32(*iface.CIDRPrefix)
			firewallInterface.CidrPrefix = cidr
		}

		interfaces = append(interfaces, firewallInterface)
	}

	// Convert VLANs
	vlans := make([]*pb.FirewallVLAN, 0, len(domainModel.VLANs))
	for _, vlan := range domainModel.VLANs {
		logger.DebugContext(context.Background(), "API firewall service: Converting VLAN: %s", vlan.VLANName)

		vlans = append(vlans, &pb.FirewallVLAN{
			Id:                   vlan.ID,
			VlanNumber:           int32(vlan.VLANNumber),
			VlanName:             vlan.VLANName,
			Description:          vlan.Description,
			IsNative:             vlan.IsNative,
			VendorSpecificConfig: vlan.VendorSpecificConfig,
			Interfaces:           vlan.Interfaces,
		})
	}

	// Convert policies
	policies := make([]*pb.FirewallPolicy, 0, len(domainModel.Policies))
	for _, policy := range domainModel.Policies {
		logger.DebugContext(context.Background(), "API firewall service: Converting policy: %s", policy.PolicyName)

		firewallPolicy := &pb.FirewallPolicy{
			Id:                   policy.ID,
			PolicyName:           policy.PolicyName,
			SrcAddresses:         policy.SrcAddresses,
			DstAddresses:         policy.DstAddresses,
			Services:             policy.Services,
			Action:               policy.Action,
			PolicyType:           policy.PolicyType,
			Status:               policy.Status,
			VendorSpecificConfig: policy.VendorSpecificConfig,
			Schedule:             policy.Schedule,
		}

		if policy.PolicyID != nil {
			policyID := int32(*policy.PolicyID)
			firewallPolicy.PolicyId = policyID
		}

		if policy.RuleOrder != nil {
			ruleOrder := int32(*policy.RuleOrder)
			firewallPolicy.RuleOrder = ruleOrder
		}

		policies = append(policies, firewallPolicy)
	}

	logger.DebugContext(context.Background(), "API firewall service: Successfully converted domain model to protobuf")

	return &pb.Firewall{
		Asset:      asset,
		Details:    details,
		Zones:      zones,
		Interfaces: interfaces,
		Vlans:      vlans,
		Policies:   policies,
	}, nil
}
