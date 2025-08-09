package storage

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/firewall/domain"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/adapter/storage/types"
	typesMapper "gitlab.apk-group.net/siem/backend/asset-discovery/pkg/adapter/storage/types/mapper"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/logger"
	"gorm.io/gorm"
)

type FirewallAssetRepo struct {
	db *gorm.DB
}

// NewFirewallAssetRepo creates a new firewall asset repository
func NewFirewallAssetRepo(db *gorm.DB) *FirewallAssetRepo {
	return &FirewallAssetRepo{db: db}
}

// Create creates a new firewall with all its related data
func (r *FirewallAssetRepo) Create(ctx context.Context, firewall domain.FirewallDomain) (domain.FirewallUUID, error) {
	logger.InfoContextWithFields(ctx, "Firewall repository: Creating firewall", map[string]interface{}{
		"firewall_name":   firewall.Asset.Name,
		"management_ip":   firewall.Details.ManagementIP,
		"vendor_code":     firewall.Asset.VendorCode,
		"zone_count":      len(firewall.Zones),
		"interface_count": len(firewall.Interfaces),
		"vlan_count":      len(firewall.VLANs),
		"policy_count":    len(firewall.Policies),
	})

	// Start transaction
	logger.DebugContext(ctx, "Firewall repository: Starting database transaction")
	tx := r.db.WithContext(ctx).Begin()
	if tx.Error != nil {
		logger.ErrorContext(ctx, "Firewall repository: Failed to start transaction: %v", tx.Error)
		return uuid.Nil, tx.Error
	}

	defer func() {
		if r := recover(); r != nil {
			logger.ErrorContext(ctx, "Firewall repository: Panic occurred, rolling back transaction: %v", r)
			tx.Rollback()
		}
	}()

	// Get vendor ID
	logger.DebugContext(ctx, "Firewall repository: Getting vendor ID for code: %s", firewall.Asset.VendorCode)
	var vendor types.Vendors
	if err := tx.Where("vendor_code = ?", firewall.Asset.VendorCode).First(&vendor).Error; err != nil {
		logger.ErrorContext(ctx, "Firewall repository: Failed to find vendor: %v", err)
		tx.Rollback()
		return uuid.Nil, domain.ErrVendorNotFound
	}

	// Check if management IP already exists
	logger.DebugContext(ctx, "Firewall repository: Checking management IP uniqueness: %s", firewall.Details.ManagementIP)
	var existingDetails types.FirewallDetails
	if err := tx.Where("management_ip = ? AND deleted_at IS NULL", firewall.Details.ManagementIP).First(&existingDetails).Error; err == nil {
		logger.WarnContext(ctx, "Firewall repository: Management IP already exists: %s", firewall.Details.ManagementIP)
		tx.Rollback()
		return uuid.Nil, domain.ErrFirewallManagementIPExists
	} else if err != gorm.ErrRecordNotFound {
		logger.ErrorContext(ctx, "Firewall repository: Database error checking management IP: %v", err)
		tx.Rollback()
		return uuid.Nil, err
	}

	// Generate asset ID if not provided
	assetID := firewall.Asset.ID
	if assetID == "" {
		assetID = uuid.New().String()
		logger.DebugContext(ctx, "Firewall repository: Generated new asset ID: %s", assetID)
	}

	// Create asset
	logger.DebugContext(ctx, "Firewall repository: Creating asset record")
	assetRecord := types.Assets{
		ID:               assetID,
		VendorID:         vendor.ID,
		Name:             firewall.Asset.Name,
		Domain:           firewall.Asset.Domain,
		Hostname:         firewall.Asset.Hostname,
		OSName:           firewall.Asset.OSName,
		OSVersion:        firewall.Asset.OSVersion,
		Description:      firewall.Asset.Description,
		AssetType:        firewall.Asset.AssetType,
		DiscoveredBy:     firewall.Asset.DiscoveredBy,
		Risk:             firewall.Asset.Risk,
		LoggingCompleted: firewall.Asset.LoggingCompleted,
		AssetValue:       firewall.Asset.AssetValue,
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
	}

	if err := tx.Create(&assetRecord).Error; err != nil {
		logger.ErrorContext(ctx, "Firewall repository: Failed to create asset: %v", err)
		tx.Rollback()
		return uuid.Nil, err
	}

	// Generate details ID if not provided and set asset ID
	detailsID := firewall.Details.ID
	if detailsID == "" {
		detailsID = uuid.New().String()
		logger.DebugContext(ctx, "Firewall repository: Generated new details ID: %s", detailsID)
	}

	// Create firewall details
	logger.DebugContext(ctx, "Firewall repository: Creating firewall details record")
	detailsRecord := types.FirewallDetails{
		ID:              detailsID,
		AssetID:         assetID,
		Model:           firewall.Details.Model,
		FirmwareVersion: firewall.Details.FirmwareVersion,
		SerialNumber:    firewall.Details.SerialNumber,
		IsHAEnabled:     firewall.Details.IsHAEnabled,
		HARole:          firewall.Details.HARole,
		ManagementIP:    firewall.Details.ManagementIP,
		SiteName:        firewall.Details.SiteName,
		Location:        firewall.Details.Location,
		Status:          firewall.Details.Status,
		LastSync:        firewall.Details.LastSync,
		SyncStatus:      firewall.Details.SyncStatus,
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}

	if err := tx.Create(&detailsRecord).Error; err != nil {
		logger.ErrorContext(ctx, "Firewall repository: Failed to create firewall details: %v", err)
		tx.Rollback()
		return uuid.Nil, err
	}

	// Create interfaces
	logger.DebugContext(ctx, "Firewall repository: Creating %d interface records", len(firewall.Interfaces))
	interfaceMap, err := r.createInterfaces(ctx, tx, firewall.Interfaces, assetID)
	if err != nil {
		tx.Rollback()
		return uuid.Nil, err
	}

	logger.DebugContext(ctx, "Firewall repository: Creating %d VLAN records", len(firewall.VLANs))
	vlanMap, err := r.createVLANs(ctx, tx, firewall.VLANs, assetID, interfaceMap)
	if err != nil {
		tx.Rollback()
		return uuid.Nil, err
	}

	logger.DebugContext(ctx, "Firewall repository: Creating %d zone records", len(firewall.Zones))
	if err := r.createZones(ctx, tx, firewall.Zones, detailsRecord.ID, interfaceMap, vlanMap); err != nil {
		tx.Rollback()
		return uuid.Nil, err
	}

	logger.DebugContext(ctx, "Firewall repository: Creating %d policy records", len(firewall.Policies))
	if err := r.createPolicies(ctx, tx, firewall.Policies, detailsRecord.ID); err != nil {
		tx.Rollback()
		return uuid.Nil, err
	}

	logger.DebugContext(ctx, "Firewall repository: Committing database transaction")
	if err := tx.Commit().Error; err != nil {
		logger.ErrorContext(ctx, "Firewall repository: Failed to commit transaction: %v", err)
		return uuid.Nil, err
	}

	firewallUUID, err := uuid.Parse(assetID)
	if err != nil {
		logger.ErrorContext(ctx, "Firewall repository: Failed to parse created asset ID as UUID: %v", err)
		return uuid.Nil, err
	}

	logger.InfoContext(ctx, "Firewall repository: Successfully created firewall with ID: %s", firewallUUID.String())
	return firewallUUID, nil
}

// createInterfaces creates interface records
func (r *FirewallAssetRepo) createInterfaces(ctx context.Context, tx *gorm.DB, interfaces []domain.FirewallInterface, assetID string) (map[string]string, error) {
	interfaceMap := make(map[string]string) // interface_name/interface_id -> actual_interface_id

	for _, iface := range interfaces {
		interfaceID := iface.ID
		if interfaceID == "" {
			interfaceID = uuid.New().String()
			logger.DebugContext(ctx, "Firewall repository: Generated new interface ID: %s for interface: %s", interfaceID, iface.InterfaceName)
		}

		// Check if an interface with this name exists but is soft-deleted
		var existingInterface types.Interfaces
		var shouldRestore bool
		if err := tx.Unscoped().Where("interface_name = ?", iface.InterfaceName).First(&existingInterface).Error; err == nil {
			// Interface exists
			if existingInterface.DeletedAt != nil {
				// Interface is soft-deleted
				shouldRestore = true
				interfaceID = existingInterface.ID
				logger.DebugContext(ctx, "Firewall repository: Found soft-deleted interface: %s, will restore it", iface.InterfaceName)
			} else if existingInterface.AssetID != nil && *existingInterface.AssetID != assetID {
				// Interface exists and is not deleted, but belongs to different asset
				logger.ErrorContext(ctx, "Firewall repository: Interface name %s already exists for different asset", iface.InterfaceName)
				return nil, errors.New("interface name already exists for different asset: " + iface.InterfaceName)
			} else {
				// Interface exists for same asset - just update it
				interfaceID = existingInterface.ID
				logger.DebugContext(ctx, "Firewall repository: Interface %s already exists for same asset, updating", iface.InterfaceName)
			}
		} else if err != gorm.ErrRecordNotFound {
			logger.ErrorContext(ctx, "Firewall repository: Database error checking interface: %v", err)
			return nil, err
		}

		// Get or create interface type
		var interfaceType types.InterfaceTypes
		if err := tx.Where("type_name = ?", iface.InterfaceType).First(&interfaceType).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				// Create default interface type if not exists
				interfaceType = types.InterfaceTypes{
					TypeName:    iface.InterfaceType,
					Description: "Auto-created interface type",
				}
				if err := tx.Create(&interfaceType).Error; err != nil {
					logger.ErrorContext(ctx, "Firewall repository: Failed to create interface type: %v", err)
					return nil, err
				}
				logger.DebugContext(ctx, "Firewall repository: Created new interface type: %s", iface.InterfaceType)
			} else {
				logger.ErrorContext(ctx, "Firewall repository: Failed to find interface type: %v", err)
				return nil, err
			}
		}

		var parentInterfaceID *string
		if iface.ParentInterfaceName != nil && *iface.ParentInterfaceName != "" {
			if parentID, exists := interfaceMap[*iface.ParentInterfaceName]; exists {
				parentInterfaceID = &parentID
			} else {
				var parentInterface types.Interfaces
				if err := tx.Where("interface_name = ? AND deleted_at IS NULL", *iface.ParentInterfaceName).First(&parentInterface).Error; err != nil {
					if err == gorm.ErrRecordNotFound {
						logger.ErrorContext(ctx, "Firewall repository: Parent interface not found: %s for interface: %s", *iface.ParentInterfaceName, iface.InterfaceName)
						return nil, errors.New("parent interface not found: " + *iface.ParentInterfaceName)
					}
					logger.ErrorContext(ctx, "Firewall repository: Failed to find parent interface: %v", err)
					return nil, err
				}
				parentInterfaceID = &parentInterface.ID
			}
		}

		interfaceRecord := types.Interfaces{
			ID:                   interfaceID,
			InterfaceName:        iface.InterfaceName,
			InterfaceTypeID:      interfaceType.ID,
			AssetID:              &assetID,
			VirtualRouter:        iface.VirtualRouter,
			VirtualSystem:        iface.VirtualSystem,
			Description:          iface.Description,
			OperationalStatus:    iface.OperationalStatus,
			AdminStatus:          iface.AdminStatus,
			ParentInterfaceID:    parentInterfaceID,
			VLANId:               iface.VLANId,
			MacAddress:           iface.MacAddress,
			VendorSpecificConfig: iface.VendorSpecificConfig,
			CreatedAt:            time.Now(),
			UpdatedAt:            time.Now(),
		}

		if shouldRestore {
			// Restore soft-deleted interface by updating it and clearing deleted_at
			if err := tx.Unscoped().Model(&types.Interfaces{}).Where("id = ?", interfaceID).Updates(map[string]interface{}{
				"interface_name":         iface.InterfaceName,
				"interface_type_id":      interfaceType.ID,
				"asset_id":               &assetID,
				"virtual_router":         iface.VirtualRouter,
				"virtual_system":         iface.VirtualSystem,
				"description":            iface.Description,
				"operational_status":     iface.OperationalStatus,
				"admin_status":           iface.AdminStatus,
				"parent_interface_id":    parentInterfaceID,
				"vlan_id":                iface.VLANId,
				"mac_address":            iface.MacAddress,
				"vendor_specific_config": iface.VendorSpecificConfig,
				"updated_at":             time.Now(),
				"deleted_at":             nil,
			}).Error; err != nil {
				logger.ErrorContext(ctx, "Firewall repository: Failed to restore interface %s: %v", iface.InterfaceName, err)
				return nil, err
			}
			logger.DebugContext(ctx, "Firewall repository: Restored interface %s with ID: %s", iface.InterfaceName, interfaceID)
		} else {
			// Create new interface or update existing one
			if err := tx.Save(&interfaceRecord).Error; err != nil {
				logger.ErrorContext(ctx, "Firewall repository: Failed to create interface %s: %v", iface.InterfaceName, err)
				return nil, err
			}
		}

		interfaceMap[iface.InterfaceName] = interfaceID
		interfaceMap[interfaceID] = interfaceID

		// Create primary IP for interface if provided
		if iface.PrimaryIP != "" {
			logger.DebugContext(ctx, "Firewall repository: Creating primary IP for interface %s: %s", iface.InterfaceName, iface.PrimaryIP)
			ipRecord := types.IPs{
				ID:          uuid.New().String(),
				AssetID:     assetID,
				InterfaceID: &interfaceID,
				IPAddress:   iface.PrimaryIP,
				CIDRPrefix:  iface.CIDRPrefix,
				CreatedAt:   time.Now(),
			}

			if err := tx.Create(&ipRecord).Error; err != nil {
				logger.ErrorContext(ctx, "Firewall repository: Failed to create primary IP for interface %s: %v", iface.InterfaceName, err)
				return nil, err
			}
		}

		// Create secondary IPs for interface
		for _, secIP := range iface.SecondaryIPs {
			logger.DebugContext(ctx, "Firewall repository: Creating secondary IP for interface %s: %s", iface.InterfaceName, secIP.IP)
			secIPRecord := types.IPs{
				ID:          uuid.New().String(),
				AssetID:     assetID,
				InterfaceID: &interfaceID,
				IPAddress:   secIP.IP,
				CIDRPrefix:  secIP.CIDRPrefix,
				CreatedAt:   time.Now(),
			}

			if err := tx.Create(&secIPRecord).Error; err != nil {
				logger.ErrorContext(ctx, "Firewall repository: Failed to create secondary IP for interface %s: %v", iface.InterfaceName, err)
				return nil, err
			}
		}
	}

	logger.DebugContext(ctx, "Firewall repository: Successfully created %d interfaces", len(interfaces))
	return interfaceMap, nil
}

// createVLANs creates VLAN records
func (r *FirewallAssetRepo) createVLANs(ctx context.Context, tx *gorm.DB, vlans []domain.FirewallVLAN, assetID string, interfaceMap map[string]string) (map[string]string, error) {
	vlanMap := make(map[string]string) // vlan_name/vlan_id -> actual_vlan_id

	for _, vlan := range vlans {
		vlanID := vlan.ID
		if vlanID == "" {
			vlanID = uuid.New().String()
			logger.DebugContext(ctx, "Firewall repository: Generated new VLAN ID: %s for VLAN: %s", vlanID, vlan.VLANName)
		}

		// Check if a VLAN with this name exists but is soft-deleted
		var existingVLAN types.VLANs
		var shouldRestore bool
		if err := tx.Unscoped().Where("vlan_name = ? AND device_type = ?", vlan.VLANName, "firewall").First(&existingVLAN).Error; err == nil {
			// VLAN exists
			if existingVLAN.DeletedAt != nil {
				// VLAN is soft-deleted, we can restore and reuse it
				shouldRestore = true
				vlanID = existingVLAN.ID
				logger.DebugContext(ctx, "Firewall repository: Found soft-deleted VLAN: %s, will restore it", vlan.VLANName)
			} else if existingVLAN.AssetID != assetID {
				// VLAN exists and is not deleted, but belongs to different asset
				logger.ErrorContext(ctx, "Firewall repository: VLAN name %s already exists for different asset", vlan.VLANName)
				return nil, errors.New("VLAN name already exists for different asset: " + vlan.VLANName)
			} else {
				// VLAN exists for same asset - just update it
				vlanID = existingVLAN.ID
				logger.DebugContext(ctx, "Firewall repository: VLAN %s already exists for same asset, updating", vlan.VLANName)
			}
		} else if err != gorm.ErrRecordNotFound {
			logger.ErrorContext(ctx, "Firewall repository: Database error checking VLAN: %v", err)
			return nil, err
		}

		vlanRecord := types.VLANs{
			ID:                   vlanID,
			VLANNumber:           vlan.VLANNumber,
			VLANName:             vlan.VLANName,
			Description:          vlan.Description,
			IsNative:             vlan.IsNative,
			VendorSpecificConfig: vlan.VendorSpecificConfig,
			DeviceType:           "firewall",
			AssetID:              assetID,
			CreatedAt:            time.Now(),
			UpdatedAt:            time.Now(),
		}

		if shouldRestore {
			// Restore soft-deleted VLAN by updating it and clearing deleted_at
			if err := tx.Unscoped().Model(&types.VLANs{}).Where("id = ?", vlanID).Updates(map[string]interface{}{
				"vlan_id":                vlan.VLANNumber,
				"vlan_name":              vlan.VLANName,
				"description":            vlan.Description,
				"is_native":              vlan.IsNative,
				"vendor_specific_config": vlan.VendorSpecificConfig,
				"device_type":            "firewall",
				"asset_id":               assetID,
				"updated_at":             time.Now(),
				"deleted_at":             nil,
			}).Error; err != nil {
				logger.ErrorContext(ctx, "Firewall repository: Failed to restore VLAN %s: %v", vlan.VLANName, err)
				return nil, err
			}
			logger.DebugContext(ctx, "Firewall repository: Restored VLAN %s with ID: %s", vlan.VLANName, vlanID)
		} else {
			// Create new VLAN or update existing one
			if err := tx.Save(&vlanRecord).Error; err != nil {
				logger.ErrorContext(ctx, "Firewall repository: Failed to create VLAN %s: %v", vlan.VLANName, err)
				return nil, err
			}
		}

		// Map both VLAN name and ID to the actual ID for lookups
		vlanMap[vlan.VLANName] = vlanID
		vlanMap[vlanID] = vlanID

		// Create VLAN-Interface relationships if interfaces are specified
		for _, interfaceName := range vlan.Interfaces {
			if interfaceName != "" {
				// Check if interface exists (by name or ID)
				var resolvedInterfaceID string
				if interfaceID, exists := interfaceMap[interfaceName]; exists {
					resolvedInterfaceID = interfaceID
				} else {
					// If not found in map, check if it exists in database
					var existingInterface types.Interfaces
					if err := tx.Where("(interface_name = ? OR id = ?) AND deleted_at IS NULL", interfaceName, interfaceName).First(&existingInterface).Error; err != nil {
						if err == gorm.ErrRecordNotFound {
							logger.ErrorContext(ctx, "Firewall repository: Interface not found for VLAN %s: %s", vlan.VLANName, interfaceName)
							return nil, errors.New("interface not found for VLAN: " + interfaceName)
						}
						logger.ErrorContext(ctx, "Firewall repository: Database error checking interface: %v", err)
						return nil, err
					}
					resolvedInterfaceID = existingInterface.ID
				}

				logger.DebugContext(ctx, "Firewall repository: Creating VLAN-Interface relationship for VLAN %s and interface %s", vlan.VLANName, interfaceName)
				vlanInterfaceRecord := types.VLANInterface{
					VLANTableID: vlanID,
					InterfaceID: resolvedInterfaceID,
					IsNative:    &vlan.IsNative,
					CreatedAt:   &time.Time{},
				}
				*vlanInterfaceRecord.CreatedAt = time.Now()

				if err := tx.Create(&vlanInterfaceRecord).Error; err != nil {
					logger.ErrorContext(ctx, "Firewall repository: Failed to create VLAN-Interface relationship: %v", err)
					return nil, err
				}
			}
		}
	}

	logger.DebugContext(ctx, "Firewall repository: Successfully created %d VLANs", len(vlans))
	return vlanMap, nil
}

// createZones creates zone records
func (r *FirewallAssetRepo) createZones(ctx context.Context, tx *gorm.DB, zones []domain.FirewallZone, firewallDetailsID string, interfaceMap map[string]string, vlanMap map[string]string) error {
	for _, zone := range zones {
		zoneID := zone.ID
		if zoneID == "" {
			zoneID = uuid.New().String()
			logger.DebugContext(ctx, "Firewall repository: Generated new zone ID: %s for zone: %s", zoneID, zone.ZoneName)
		}

		zoneRecord := types.Zones{
			ID:                    zoneID,
			ZoneName:              zone.ZoneName,
			ZoneType:              zone.ZoneType,
			VendorZoneType:        zone.VendorZoneType,
			Description:           zone.Description,
			ZoneMode:              zone.ZoneMode,
			IntrazoneAction:       zone.IntrazoneAction,
			ZoneProtectionProfile: zone.ZoneProtectionProfile,
			LogSetting:            zone.LogSetting,
			FirewallID:            firewallDetailsID,
			CreatedAt:             time.Now(),
			UpdatedAt:             time.Now(),
		}

		if err := tx.Create(&zoneRecord).Error; err != nil {
			logger.ErrorContext(ctx, "Firewall repository: Failed to create zone %s: %v", zone.ZoneName, err)
			return err
		}

		// Create zone details (zone-interface-vlan relationships)
		// Create cross-product of interfaces and VLANs

		// If both interface names and VLAN names are provided, create records for all combinations
		if len(zone.Interfaces.InterfaceName) > 0 && len(zone.Interfaces.VLANName) > 0 {
			for _, interfaceName := range zone.Interfaces.InterfaceName {
				if interfaceName == "" {
					continue
				}

				// Resolve interface name to ID
				var resolvedInterfaceID string
				if id, exists := interfaceMap[interfaceName]; exists {
					resolvedInterfaceID = id
					logger.DebugContext(ctx, "Firewall repository: Found interface in map: %s -> %s", interfaceName, resolvedInterfaceID)
				} else {
					var existingInterface types.Interfaces
					if err := tx.Where("interface_name = ? AND deleted_at IS NULL", interfaceName).First(&existingInterface).Error; err != nil {
						if err == gorm.ErrRecordNotFound {
							logger.ErrorContext(ctx, "Firewall repository: Interface not found for zone %s: %s. Available interfaces: %v", zone.ZoneName, interfaceName, interfaceMap)
							return errors.New("interface not found for zone: " + interfaceName)
						}
						logger.ErrorContext(ctx, "Firewall repository: Database error checking interface: %v", err)
						return err
					}
					resolvedInterfaceID = existingInterface.ID
					logger.DebugContext(ctx, "Firewall repository: Found interface in database: %s -> %s", interfaceName, resolvedInterfaceID)
				}

				for _, vlanName := range zone.Interfaces.VLANName {
					if vlanName == "" {
						continue
					}

					// Resolve VLAN name to ID
					var resolvedVLANID string
					if vlanID, exists := vlanMap[vlanName]; exists {
						resolvedVLANID = vlanID
						logger.DebugContext(ctx, "Firewall repository: Found VLAN in map: %s -> %s", vlanName, resolvedVLANID)
					} else {
						var existingVLAN types.VLANs
						if err := tx.Where("vlan_name = ? AND deleted_at IS NULL", vlanName).First(&existingVLAN).Error; err != nil {
							if err == gorm.ErrRecordNotFound {
								logger.ErrorContext(ctx, "Firewall repository: VLAN not found for zone %s: %s. Available VLANs: %v", zone.ZoneName, vlanName, vlanMap)
								return errors.New("VLAN not found for zone: " + vlanName)
							}
							logger.ErrorContext(ctx, "Firewall repository: Database error checking VLAN: %v", err)
							return err
						}
						resolvedVLANID = existingVLAN.ID
						logger.DebugContext(ctx, "Firewall repository: Found VLAN in database: %s -> %s", vlanName, resolvedVLANID)
					}

					logger.DebugContext(ctx, "Firewall repository: Creating zone detail for zone %s with interface_name=%s and vlan_name=%s", zone.ZoneName, interfaceName, vlanName)

					// Create zone detail with both interface and VLAN
					zoneDetailRecord := types.ZoneDetails{
						ID:                  uuid.New().String(),
						ZoneID:              zoneID,
						FirewallInterfaceID: resolvedInterfaceID,
						VLANTableID:         resolvedVLANID,
						CreatedAt:           time.Now(),
						UpdatedAt:           time.Now(),
					}

					if err := tx.Create(&zoneDetailRecord).Error; err != nil {
						logger.ErrorContext(ctx, "Firewall repository: Failed to create zone detail for interface %s and VLAN %s: %v", interfaceName, vlanName, err)
						return err
					}
				}
			}
		} else {
			// Handle cases where only one type is provided
			logger.DebugContext(ctx, "Firewall repository: Zone %s has incomplete interface/VLAN specification - skipping zone detail creation", zone.ZoneName)
		}
	}

	logger.DebugContext(ctx, "Firewall repository: Successfully created %d zones", len(zones))
	return nil
}

// createPolicies creates policy records
func (r *FirewallAssetRepo) createPolicies(ctx context.Context, tx *gorm.DB, policies []domain.FirewallPolicy, firewallDetailsID string) error {
	for _, policy := range policies {
		policyID := policy.ID
		if policyID == "" {
			policyID = uuid.New().String()
			logger.DebugContext(ctx, "Firewall repository: Generated new policy ID: %s for policy: %s", policyID, policy.PolicyName)
		}

		policyRecord := types.FirewallPolicy{
			ID:                   policyID,
			FirewallDetailsID:    firewallDetailsID,
			PolicyName:           policy.PolicyName,
			PolicyID:             policy.PolicyID,
			Action:               policy.Action,
			PolicyType:           policy.PolicyType,
			Status:               policy.Status,
			RuleOrder:            policy.RuleOrder,
			VendorSpecificConfig: policy.VendorSpecificConfig,
			CreatedAt:            time.Now(),
			UpdatedAt:            time.Now(),
		}

		if err := tx.Create(&policyRecord).Error; err != nil {
			logger.ErrorContext(ctx, "Firewall repository: Failed to create policy %s: %v", policy.PolicyName, err)
			return err
		}
	}

	logger.DebugContext(ctx, "Firewall repository: Successfully created %d policies", len(policies))
	return nil
}

// GetByID retrieves a firewall by its ID with all related data
func (r *FirewallAssetRepo) GetByID(ctx context.Context, firewallID domain.FirewallUUID) (*domain.FirewallDomain, error) {
	logger.InfoContext(ctx, "Firewall repository: Getting firewall by ID: %s", firewallID.String())

	// Get asset and firewall details
	var asset types.Assets
	var details types.FirewallDetails

	logger.DebugContext(ctx, "Firewall repository: Fetching asset and firewall details")
	if err := r.db.WithContext(ctx).
		Preload("Vendor").
		Where("id = ? AND deleted_at IS NULL", firewallID.String()).
		First(&asset).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			logger.WarnContext(ctx, "Firewall repository: Firewall not found with ID: %s", firewallID.String())
			return nil, domain.ErrFirewallNotFound
		}
		logger.ErrorContext(ctx, "Firewall repository: Database error fetching asset: %v", err)
		return nil, err
	}

	// Get firewall details
	if err := r.db.WithContext(ctx).
		Where("asset_id = ? AND deleted_at IS NULL", firewallID.String()).
		First(&details).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			logger.WarnContext(ctx, "Firewall repository: Firewall details not found for asset ID: %s", firewallID.String())
			return nil, domain.ErrFirewallNotFound
		}
		logger.ErrorContext(ctx, "Firewall repository: Database error fetching firewall details: %v", err)
		return nil, err
	}

	// Get zones with zone details
	var zones []types.Zones
	logger.DebugContext(ctx, "Firewall repository: Fetching zones with zone details")
	if err := r.db.WithContext(ctx).
		Preload("ZoneDetails", "deleted_at IS NULL").
		Where("firewall_id = ? AND deleted_at IS NULL", details.ID).
		Find(&zones).Error; err != nil {
		logger.ErrorContext(ctx, "Firewall repository: Database error fetching zones: %v", err)
		return nil, err
	}

	// Get interfaces with interface types
	var interfaces []types.Interfaces
	logger.DebugContext(ctx, "Firewall repository: Fetching interfaces with types")
	if err := r.db.WithContext(ctx).
		Preload("InterfaceType").
		Where("asset_id = ? AND deleted_at IS NULL", firewallID.String()).
		Order("updated_at ASC").
		Find(&interfaces).Error; err != nil {
		logger.ErrorContext(ctx, "Firewall repository: Database error fetching interfaces: %v", err)
		return nil, err
	}

	// Get VLANs
	var vlans []types.VLANs
	logger.DebugContext(ctx, "Firewall repository: Fetching VLANs")
	if err := r.db.WithContext(ctx).
		Where("asset_id = ? AND device_type = ? AND deleted_at IS NULL", firewallID.String(), "firewall").
		Find(&vlans).Error; err != nil {
		logger.ErrorContext(ctx, "Firewall repository: Database error fetching VLANs: %v", err)
		return nil, err
	}

	// Get VLAN-Interface relationships
	var vlanInterfaces []types.VLANInterface
	if len(vlans) > 0 {
		vlanIDs := make([]string, len(vlans))
		for i, vlan := range vlans {
			vlanIDs[i] = vlan.ID
		}

		logger.DebugContext(ctx, "Firewall repository: Fetching VLAN-Interface relationships for %d VLANs", len(vlanIDs))
		if err := r.db.WithContext(ctx).
			Where("vlan_table_id IN ? AND deleted_at IS NULL", vlanIDs).
			Find(&vlanInterfaces).Error; err != nil {
			logger.ErrorContext(ctx, "Firewall repository: Database error fetching VLAN-Interface relationships: %v", err)
			return nil, err
		}
	}

	// Get policies
	var policies []types.FirewallPolicy
	logger.DebugContext(ctx, "Firewall repository: Fetching firewall policies")
	if err := r.db.WithContext(ctx).
		Where("firewall_details_id = ? AND deleted_at IS NULL", details.ID).
		Find(&policies).Error; err != nil {
		logger.ErrorContext(ctx, "Firewall repository: Database error fetching policies: %v", err)
		return nil, err
	}

	// Get IPs associated with this asset
	var ips []types.IPs
	logger.DebugContext(ctx, "Firewall repository: Fetching asset IPs")
	if err := r.db.WithContext(ctx).
		Where("asset_id = ? AND deleted_at IS NULL", firewallID.String()).
		Find(&ips).Error; err != nil {
		logger.ErrorContext(ctx, "Firewall repository: Database error fetching IPs: %v", err)
		return nil, err
	}

	// Convert storage types to domain model
	logger.DebugContext(ctx, "Firewall repository: Converting storage types to domain model")
	firewallDomain, err := typesMapper.FirewallStorage2Domain(asset, details, zones, interfaces, vlans, policies, ips, vlanInterfaces)
	if err != nil {
		logger.ErrorContext(ctx, "Firewall repository: Failed to convert storage to domain: %v", err)
		return nil, err
	}

	logger.InfoContextWithFields(ctx, "Firewall repository: Successfully retrieved firewall", map[string]interface{}{
		"firewall_id":     firewallID.String(),
		"firewall_name":   firewallDomain.Asset.Name,
		"zone_count":      len(firewallDomain.Zones),
		"interface_count": len(firewallDomain.Interfaces),
		"vlan_count":      len(firewallDomain.VLANs),
		"policy_count":    len(firewallDomain.Policies),
	})

	return firewallDomain, nil
}

// Update updates an existing firewall
func (r *FirewallAssetRepo) Update(ctx context.Context, firewallID domain.FirewallUUID, firewall domain.FirewallDomain) error {
	logger.InfoContextWithFields(ctx, "Firewall repository: Updating firewall", map[string]interface{}{
		"firewall_id":     firewallID.String(),
		"firewall_name":   firewall.Asset.Name,
		"management_ip":   firewall.Details.ManagementIP,
		"vendor_code":     firewall.Asset.VendorCode,
		"zone_count":      len(firewall.Zones),
		"interface_count": len(firewall.Interfaces),
		"vlan_count":      len(firewall.VLANs),
		"policy_count":    len(firewall.Policies),
	})

	logger.DebugContext(ctx, "Firewall repository: Starting database transaction for update")
	tx := r.db.WithContext(ctx).Begin()
	if tx.Error != nil {
		logger.ErrorContext(ctx, "Firewall repository: Failed to start transaction: %v", tx.Error)
		return tx.Error
	}

	defer func() {
		if r := recover(); r != nil {
			logger.ErrorContext(ctx, "Firewall repository: Panic occurred during update, rolling back transaction: %v", r)
			tx.Rollback()
		}
	}()

	// Verify firewall exists
	var existingAsset types.Assets
	if err := tx.Where("id = ?", firewallID.String()).First(&existingAsset).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			logger.WarnContext(ctx, "Firewall repository: Firewall not found for update: %s", firewallID.String())
			tx.Rollback()
			return domain.ErrFirewallNotFound
		}
		logger.ErrorContext(ctx, "Firewall repository: Database error checking firewall existence: %v", err)
		tx.Rollback()
		return err
	}

	// Get vendor ID
	logger.DebugContext(ctx, "Firewall repository: Getting vendor ID for code: %s", firewall.Asset.VendorCode)
	var vendor types.Vendors
	if err := tx.Where("vendor_code = ?", firewall.Asset.VendorCode).First(&vendor).Error; err != nil {
		logger.ErrorContext(ctx, "Firewall repository: Failed to find vendor: %v", err)
		tx.Rollback()
		return domain.ErrVendorNotFound
	}

	// Check if management IP already exists for other firewalls
	logger.DebugContext(ctx, "Firewall repository: Checking management IP uniqueness for update: %s", firewall.Details.ManagementIP)
	var existingDetails types.FirewallDetails
	if err := tx.Where("management_ip = ? AND asset_id != ? AND deleted_at IS NULL", firewall.Details.ManagementIP, firewallID.String()).First(&existingDetails).Error; err == nil {
		logger.WarnContext(ctx, "Firewall repository: Management IP already exists for another firewall: %s", firewall.Details.ManagementIP)
		tx.Rollback()
		return domain.ErrFirewallManagementIPExists
	} else if err != gorm.ErrRecordNotFound {
		logger.ErrorContext(ctx, "Firewall repository: Database error checking management IP: %v", err)
		tx.Rollback()
		return err
	}

	// Update asset
	logger.DebugContext(ctx, "Firewall repository: Updating asset record")
	assetRecord := types.Assets{
		ID:               firewallID.String(),
		VendorID:         vendor.ID,
		Name:             firewall.Asset.Name,
		Domain:           firewall.Asset.Domain,
		Hostname:         firewall.Asset.Hostname,
		OSName:           firewall.Asset.OSName,
		OSVersion:        firewall.Asset.OSVersion,
		Description:      firewall.Asset.Description,
		AssetType:        firewall.Asset.AssetType,
		DiscoveredBy:     firewall.Asset.DiscoveredBy,
		Risk:             firewall.Asset.Risk,
		LoggingCompleted: firewall.Asset.LoggingCompleted,
		AssetValue:       firewall.Asset.AssetValue,
		UpdatedAt:        time.Now(),
	}

	if err := tx.Model(&types.Assets{}).Where("id = ?", firewallID.String()).Updates(&assetRecord).Error; err != nil {
		logger.ErrorContext(ctx, "Firewall repository: Failed to update asset: %v", err)
		tx.Rollback()
		return err
	}

	// Update firewall details
	logger.DebugContext(ctx, "Firewall repository: Updating firewall details record")
	detailsRecord := types.FirewallDetails{
		Model:           firewall.Details.Model,
		FirmwareVersion: firewall.Details.FirmwareVersion,
		SerialNumber:    firewall.Details.SerialNumber,
		IsHAEnabled:     firewall.Details.IsHAEnabled,
		HARole:          firewall.Details.HARole,
		ManagementIP:    firewall.Details.ManagementIP,
		SiteName:        firewall.Details.SiteName,
		Location:        firewall.Details.Location,
		Status:          firewall.Details.Status,
		LastSync:        firewall.Details.LastSync,
		SyncStatus:      firewall.Details.SyncStatus,
		UpdatedAt:       time.Now(),
	}

	if err := tx.Model(&types.FirewallDetails{}).Where("asset_id = ?", firewallID.String()).Updates(&detailsRecord).Error; err != nil {
		logger.ErrorContext(ctx, "Firewall repository: Failed to update firewall details: %v", err)
		tx.Rollback()
		return err
	}

	// Get the firewall details ID for related record operations
	var details types.FirewallDetails
	if err := tx.Where("asset_id = ?", firewallID.String()).First(&details).Error; err != nil {
		logger.ErrorContext(ctx, "Firewall repository: Failed to get firewall details ID: %v", err)
		tx.Rollback()
		return err
	}

	// Update related entities
	logger.DebugContext(ctx, "Firewall repository: Updating interfaces")
	interfaceMap, err := r.updateInterfaces(ctx, tx, firewall.Interfaces, firewallID.String())
	if err != nil {
		tx.Rollback()
		return err
	}

	logger.DebugContext(ctx, "Firewall repository: Updating VLANs")
	vlanMap, err := r.updateVLANs(ctx, tx, firewall.VLANs, firewallID.String(), interfaceMap)
	if err != nil {
		tx.Rollback()
		return err
	}

	logger.DebugContext(ctx, "Firewall repository: Updating zones")
	if err := r.updateZones(ctx, tx, firewall.Zones, details.ID, interfaceMap, vlanMap); err != nil {
		tx.Rollback()
		return err
	}

	logger.DebugContext(ctx, "Firewall repository: Updating policies")
	if err := r.updatePolicies(ctx, tx, firewall.Policies, details.ID); err != nil {
		tx.Rollback()
		return err
	}

	logger.DebugContext(ctx, "Firewall repository: Committing update transaction")
	if err := tx.Commit().Error; err != nil {
		logger.ErrorContext(ctx, "Firewall repository: Failed to commit update transaction: %v", err)
		return err
	}

	logger.InfoContext(ctx, "Firewall repository: Successfully updated firewall with ID: %s", firewallID.String())
	return nil
}

// updateInterfaces updates interface records
func (r *FirewallAssetRepo) updateInterfaces(ctx context.Context, tx *gorm.DB, interfaces []domain.FirewallInterface, assetID string) (map[string]string, error) {
	interfaceMap := make(map[string]string) // interface_name/interface_id -> actual_interface_id

	// Get existing interfaces for this firewall
	var existingInterfaces []types.Interfaces
	if err := tx.Where("asset_id = ? AND deleted_at IS NULL", assetID).Find(&existingInterfaces).Error; err != nil {
		logger.ErrorContext(ctx, "Firewall repository: Failed to fetch existing interfaces: %v", err)
		return nil, err
	}

	// Create a map of existing interfaces by ID and name
	existingByID := make(map[string]types.Interfaces)
	existingByName := make(map[string]types.Interfaces)
	for _, existing := range existingInterfaces {
		existingByID[existing.ID] = existing
		existingByName[existing.InterfaceName] = existing
	}

	// Track which existing interfaces are still referenced
	referencedInterfaces := make(map[string]bool)

	// Process each interface in the update request
	for _, iface := range interfaces {
		var interfaceID string
		var isUpdate bool

		// Rule 1: If ID is provided, check if it exists and is already connected
		if iface.ID != "" {
			if existing, exists := existingByID[iface.ID]; exists {
				// ID exists and is connected - update it
				interfaceID = existing.ID
				isUpdate = true
				logger.DebugContext(ctx, "Firewall repository: Updating existing interface by ID: %s", iface.ID)
			} else {
				// Rule 3: ID provided but doesn't exist - return error
				logger.ErrorContext(ctx, "Firewall repository: Interface ID provided but does not exist: %s", iface.ID)
				return nil, errors.New("interface ID provided but does not exist: " + iface.ID)
			}
		} else {
			// Rule 2: If name is provided instead of ID, check if interface exists by name
			if existing, exists := existingByName[iface.InterfaceName]; exists {
				// Interface exists by name - update it
				interfaceID = existing.ID
				isUpdate = true
				logger.DebugContext(ctx, "Firewall repository: Updating existing interface by name: %s", iface.InterfaceName)
			} else {
				// Interface doesn't exist - create new one
				interfaceID = uuid.New().String()
				isUpdate = false
				logger.DebugContext(ctx, "Firewall repository: Creating new interface: %s", iface.InterfaceName)
			}
		}

		// Mark this interface as referenced
		referencedInterfaces[interfaceID] = true

		// Get or create interface type
		var interfaceType types.InterfaceTypes
		if err := tx.Where("type_name = ?", iface.InterfaceType).First(&interfaceType).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				// Create default interface type if not exists
				interfaceType = types.InterfaceTypes{
					TypeName:    iface.InterfaceType,
					Description: "Auto-created interface type",
				}
				if err := tx.Create(&interfaceType).Error; err != nil {
					logger.ErrorContext(ctx, "Firewall repository: Failed to create interface type: %v", err)
					return nil, err
				}
				logger.DebugContext(ctx, "Firewall repository: Created new interface type: %s", iface.InterfaceType)
			} else {
				logger.ErrorContext(ctx, "Firewall repository: Failed to find interface type: %v", err)
				return nil, err
			}
		}

		// Handle parent interface reference
		var parentInterfaceID *string
		if iface.ParentInterfaceName != nil && *iface.ParentInterfaceName != "" {
			if parentID, exists := interfaceMap[*iface.ParentInterfaceName]; exists {
				parentInterfaceID = &parentID
			} else {
				var parentInterface types.Interfaces
				if err := tx.Where("interface_name = ? AND deleted_at IS NULL", *iface.ParentInterfaceName).First(&parentInterface).Error; err != nil {
					if err == gorm.ErrRecordNotFound {
						logger.ErrorContext(ctx, "Firewall repository: Parent interface not found: %s for interface: %s", *iface.ParentInterfaceName, iface.InterfaceName)
						return nil, errors.New("parent interface not found: " + *iface.ParentInterfaceName)
					}
					logger.ErrorContext(ctx, "Firewall repository: Failed to find parent interface: %v", err)
					return nil, err
				}
				parentInterfaceID = &parentInterface.ID
			}
		}

		// Create/update interface record
		interfaceRecord := types.Interfaces{
			ID:                   interfaceID,
			InterfaceName:        iface.InterfaceName,
			InterfaceTypeID:      interfaceType.ID,
			AssetID:              &assetID,
			VirtualRouter:        iface.VirtualRouter,
			VirtualSystem:        iface.VirtualSystem,
			Description:          iface.Description,
			OperationalStatus:    iface.OperationalStatus,
			AdminStatus:          iface.AdminStatus,
			ParentInterfaceID:    parentInterfaceID,
			VLANId:               iface.VLANId,
			MacAddress:           iface.MacAddress,
			VendorSpecificConfig: iface.VendorSpecificConfig,
			UpdatedAt:            time.Now(),
		}

		if isUpdate {
			// Update existing interface
			if err := tx.Model(&types.Interfaces{}).Where("id = ?", interfaceID).Updates(&interfaceRecord).Error; err != nil {
				logger.ErrorContext(ctx, "Firewall repository: Failed to update interface %s: %v", iface.InterfaceName, err)
				return nil, err
			}
		} else {
			// Create new interface
			interfaceRecord.CreatedAt = time.Now()
			if err := tx.Create(&interfaceRecord).Error; err != nil {
				logger.ErrorContext(ctx, "Firewall repository: Failed to create interface %s: %v", iface.InterfaceName, err)
				return nil, err
			}
		}

		interfaceMap[iface.InterfaceName] = interfaceID
		interfaceMap[interfaceID] = interfaceID

		// Handle IPs - soft delete existing IPs for this interface and recreate
		if err := tx.Model(&types.IPs{}).Where("interface_id = ?", interfaceID).Update("deleted_at", time.Now()).Error; err != nil {
			logger.ErrorContext(ctx, "Firewall repository: Failed to soft delete existing IPs for interface %s: %v", iface.InterfaceName, err)
			return nil, err
		}

		// Create primary IP for interface if provided
		if iface.PrimaryIP != "" {
			logger.DebugContext(ctx, "Firewall repository: Creating primary IP for interface %s: %s", iface.InterfaceName, iface.PrimaryIP)
			ipRecord := types.IPs{
				ID:          uuid.New().String(),
				AssetID:     assetID,
				InterfaceID: &interfaceID,
				IPAddress:   iface.PrimaryIP,
				CIDRPrefix:  iface.CIDRPrefix,
				CreatedAt:   time.Now(),
			}

			if err := tx.Create(&ipRecord).Error; err != nil {
				logger.ErrorContext(ctx, "Firewall repository: Failed to create primary IP for interface %s: %v", iface.InterfaceName, err)
				return nil, err
			}
		}

		// Create secondary IPs for interface
		for _, secIP := range iface.SecondaryIPs {
			logger.DebugContext(ctx, "Firewall repository: Creating secondary IP for interface %s: %s", iface.InterfaceName, secIP.IP)
			secIPRecord := types.IPs{
				ID:          uuid.New().String(),
				AssetID:     assetID,
				InterfaceID: &interfaceID,
				IPAddress:   secIP.IP,
				CIDRPrefix:  secIP.CIDRPrefix,
				CreatedAt:   time.Now(),
			}

			if err := tx.Create(&secIPRecord).Error; err != nil {
				logger.ErrorContext(ctx, "Firewall repository: Failed to create secondary IP for interface %s: %v", iface.InterfaceName, err)
				return nil, err
			}
		}
	}
	// Rule 4: Delete orphaned interfaces (not referenced in the update request)
	for _, existing := range existingInterfaces {
		if !referencedInterfaces[existing.ID] {
			logger.DebugContext(ctx, "Firewall repository: Soft deleting orphaned interface: %s", existing.InterfaceName)

			// Soft delete associated IPs first
			if err := tx.Model(&types.IPs{}).Where("interface_id = ?", existing.ID).Update("deleted_at", time.Now()).Error; err != nil {
				logger.ErrorContext(ctx, "Firewall repository: Failed to soft delete IPs for orphaned interface %s: %v", existing.InterfaceName, err)
				return nil, err
			}

			// Soft delete the interface
			if err := tx.Model(&existing).Update("deleted_at", time.Now()).Error; err != nil {
				logger.ErrorContext(ctx, "Firewall repository: Failed to soft delete orphaned interface %s: %v", existing.InterfaceName, err)
				return nil, err
			}
		}
	}

	logger.DebugContext(ctx, "Firewall repository: Successfully updated %d interfaces", len(interfaces))
	return interfaceMap, nil
}

// updateVLANs updates VLAN records
func (r *FirewallAssetRepo) updateVLANs(ctx context.Context, tx *gorm.DB, vlans []domain.FirewallVLAN, assetID string, interfaceMap map[string]string) (map[string]string, error) {
	vlanMap := make(map[string]string) // vlan_name/vlan_id -> actual_vlan_id

	// Get existing VLANs for this firewall (exclude soft-deleted)
	var existingVLANs []types.VLANs
	if err := tx.Where("asset_id = ? AND device_type = ? AND deleted_at IS NULL", assetID, "firewall").Find(&existingVLANs).Error; err != nil {
		logger.ErrorContext(ctx, "Firewall repository: Failed to fetch existing VLANs: %v", err)
		return nil, err
	}

	// Create a map of existing VLANs by ID and name
	existingByID := make(map[string]types.VLANs)
	existingByName := make(map[string]types.VLANs)
	for _, existing := range existingVLANs {
		existingByID[existing.ID] = existing
		existingByName[existing.VLANName] = existing
	}

	// Track which existing VLANs are still referenced
	referencedVLANs := make(map[string]bool)

	// Process each VLAN in the update request
	for _, vlan := range vlans {
		var vlanID string
		var isUpdate bool

		// Rule 1: If ID is provided, check if it exists and is already connected
		if vlan.ID != "" {
			if existing, exists := existingByID[vlan.ID]; exists {
				// ID exists and is connected - update it
				vlanID = existing.ID
				isUpdate = true
				logger.DebugContext(ctx, "Firewall repository: Updating existing VLAN by ID: %s", vlan.ID)
			} else {
				// Rule 3: ID provided but doesn't exist - return error
				logger.ErrorContext(ctx, "Firewall repository: VLAN ID provided but does not exist: %s", vlan.ID)
				return nil, errors.New("VLAN ID provided but does not exist: " + vlan.ID)
			}
		} else {
			// Rule 2: If name is provided instead of ID, check if VLAN exists by name
			if existing, exists := existingByName[vlan.VLANName]; exists {
				// VLAN exists by name - update it
				vlanID = existing.ID
				isUpdate = true
				logger.DebugContext(ctx, "Firewall repository: Updating existing VLAN by name: %s", vlan.VLANName)
			} else {
				// VLAN doesn't exist - create new one
				vlanID = uuid.New().String()
				isUpdate = false
				logger.DebugContext(ctx, "Firewall repository: Creating new VLAN: %s", vlan.VLANName)
			}
		}

		// Mark this VLAN as referenced
		referencedVLANs[vlanID] = true

		// Create/update VLAN record
		vlanRecord := types.VLANs{
			ID:                   vlanID,
			VLANNumber:           vlan.VLANNumber,
			VLANName:             vlan.VLANName,
			Description:          vlan.Description,
			IsNative:             vlan.IsNative,
			VendorSpecificConfig: vlan.VendorSpecificConfig,
			DeviceType:           "firewall",
			AssetID:              assetID,
			UpdatedAt:            time.Now(),
		}

		if isUpdate {
			// Update existing VLAN
			if err := tx.Model(&types.VLANs{}).Where("id = ?", vlanID).Updates(&vlanRecord).Error; err != nil {
				logger.ErrorContext(ctx, "Firewall repository: Failed to update VLAN %s: %v", vlan.VLANName, err)
				return nil, err
			}
		} else {
			// Create new VLAN
			vlanRecord.CreatedAt = time.Now()
			if err := tx.Create(&vlanRecord).Error; err != nil {
				logger.ErrorContext(ctx, "Firewall repository: Failed to create VLAN %s: %v", vlan.VLANName, err)
				return nil, err
			}
		}

		// Map both VLAN name and ID to the actual ID for lookups
		vlanMap[vlan.VLANName] = vlanID
		vlanMap[vlanID] = vlanID

		// Handle VLAN-Interface relationships
		// Soft delete existing relationships for this VLAN
		if err := tx.Model(&types.VLANInterface{}).Where("vlan_table_id = ?", vlanID).Update("deleted_at", time.Now()).Error; err != nil {
			logger.ErrorContext(ctx, "Firewall repository: Failed to soft delete existing VLAN-Interface relationships for VLAN %s: %v", vlan.VLANName, err)
			return nil, err
		}

		// Create VLAN-Interface relationships if interfaces are specified
		for _, interfaceName := range vlan.Interfaces {
			if interfaceName != "" {
				// Check if interface exists (by name or ID)
				var resolvedInterfaceID string
				if interfaceID, exists := interfaceMap[interfaceName]; exists {
					resolvedInterfaceID = interfaceID
				} else {
					// If not found in map, check if it exists in database
					var existingInterface types.Interfaces
					if err := tx.Where("(interface_name = ? OR id = ?) AND deleted_at IS NULL", interfaceName, interfaceName).First(&existingInterface).Error; err != nil {
						if err == gorm.ErrRecordNotFound {
							logger.ErrorContext(ctx, "Firewall repository: Interface not found for VLAN %s: %s", vlan.VLANName, interfaceName)
							return nil, errors.New("interface not found for VLAN: " + interfaceName)
						}
						logger.ErrorContext(ctx, "Firewall repository: Database error checking interface: %v", err)
						return nil, err
					}
					resolvedInterfaceID = existingInterface.ID
				}

				logger.DebugContext(ctx, "Firewall repository: Creating VLAN-Interface relationship for VLAN %s and interface %s", vlan.VLANName, interfaceName)
				vlanInterfaceRecord := types.VLANInterface{
					VLANTableID: vlanID,
					InterfaceID: resolvedInterfaceID,
					IsNative:    &vlan.IsNative,
					CreatedAt:   &time.Time{},
				}
				*vlanInterfaceRecord.CreatedAt = time.Now()

				if err := tx.Create(&vlanInterfaceRecord).Error; err != nil {
					logger.ErrorContext(ctx, "Firewall repository: Failed to create VLAN-Interface relationship: %v", err)
					return nil, err
				}
			}
		}
	}
	// Rule 4: Delete orphaned VLANs (not referenced in the update request)
	for _, existing := range existingVLANs {
		if !referencedVLANs[existing.ID] {
			logger.DebugContext(ctx, "Firewall repository: Soft deleting orphaned VLAN: %s", existing.VLANName)

			// Soft delete VLAN-Interface relationships first
			if err := tx.Model(&types.VLANInterface{}).Where("vlan_table_id = ?", existing.ID).Update("deleted_at", time.Now()).Error; err != nil {
				logger.ErrorContext(ctx, "Firewall repository: Failed to soft delete VLAN-Interface relationships for orphaned VLAN %s: %v", existing.VLANName, err)
				return nil, err
			}

			// Soft delete the VLAN
			if err := tx.Model(&existing).Update("deleted_at", time.Now()).Error; err != nil {
				logger.ErrorContext(ctx, "Firewall repository: Failed to soft delete orphaned VLAN %s: %v", existing.VLANName, err)
				return nil, err
			}
		}
	}

	logger.DebugContext(ctx, "Firewall repository: Successfully updated %d VLANs", len(vlans))
	return vlanMap, nil
}

// updateZones updates zone records
func (r *FirewallAssetRepo) updateZones(ctx context.Context, tx *gorm.DB, zones []domain.FirewallZone, firewallDetailsID string, interfaceMap map[string]string, vlanMap map[string]string) error {
	// Get existing zones for this firewall (exclude soft-deleted)
	var existingZones []types.Zones
	if err := tx.Where("firewall_id = ? AND deleted_at IS NULL", firewallDetailsID).Find(&existingZones).Error; err != nil {
		logger.ErrorContext(ctx, "Firewall repository: Failed to fetch existing zones: %v", err)
		return err
	}

	// Create a map of existing zones by ID and name
	existingByID := make(map[string]types.Zones)
	existingByName := make(map[string]types.Zones)
	for _, existing := range existingZones {
		existingByID[existing.ID] = existing
		existingByName[existing.ZoneName] = existing
	}

	// Track which existing zones are still referenced
	referencedZones := make(map[string]bool)

	// Process each zone in the update request
	for _, zone := range zones {
		var zoneID string
		var isUpdate bool

		// Rule 1: If ID is provided, check if it exists and is already connected
		if zone.ID != "" {
			if existing, exists := existingByID[zone.ID]; exists {
				// ID exists and is connected - update it
				zoneID = existing.ID
				isUpdate = true
				logger.DebugContext(ctx, "Firewall repository: Updating existing zone by ID: %s", zone.ID)
			} else {
				// Rule 3: ID provided but doesn't exist - return error
				logger.ErrorContext(ctx, "Firewall repository: Zone ID provided but does not exist: %s", zone.ID)
				return errors.New("zone ID provided but does not exist: " + zone.ID)
			}
		} else {
			// Rule 2: If name is provided instead of ID, check if zone exists by name
			if existing, exists := existingByName[zone.ZoneName]; exists {
				// Zone exists by name - update it
				zoneID = existing.ID
				isUpdate = true
				logger.DebugContext(ctx, "Firewall repository: Updating existing zone by name: %s", zone.ZoneName)
			} else {
				// Zone doesn't exist - create new one
				zoneID = uuid.New().String()
				isUpdate = false
				logger.DebugContext(ctx, "Firewall repository: Creating new zone: %s", zone.ZoneName)
			}
		}

		// Mark this zone as referenced
		referencedZones[zoneID] = true

		// Create/update zone record
		zoneRecord := types.Zones{
			ID:                    zoneID,
			ZoneName:              zone.ZoneName,
			ZoneType:              zone.ZoneType,
			VendorZoneType:        zone.VendorZoneType,
			Description:           zone.Description,
			ZoneMode:              zone.ZoneMode,
			IntrazoneAction:       zone.IntrazoneAction,
			ZoneProtectionProfile: zone.ZoneProtectionProfile,
			LogSetting:            zone.LogSetting,
			FirewallID:            firewallDetailsID,
			UpdatedAt:             time.Now(),
		}

		if isUpdate {
			// Update existing zone
			if err := tx.Model(&types.Zones{}).Where("id = ?", zoneID).Updates(&zoneRecord).Error; err != nil {
				logger.ErrorContext(ctx, "Firewall repository: Failed to update zone %s: %v", zone.ZoneName, err)
				return err
			}
		} else {
			// Create new zone
			zoneRecord.CreatedAt = time.Now()
			if err := tx.Create(&zoneRecord).Error; err != nil {
				logger.ErrorContext(ctx, "Firewall repository: Failed to create zone %s: %v", zone.ZoneName, err)
				return err
			}
		}

		// Handle zone details (zone-interface-vlan relationships)
		// Soft delete existing zone details for this zone
		if err := tx.Model(&types.ZoneDetails{}).Where("zone_id = ?", zoneID).Update("deleted_at", time.Now()).Error; err != nil {
			logger.ErrorContext(ctx, "Firewall repository: Failed to soft delete existing zone details for zone %s: %v", zone.ZoneName, err)
			return err
		}

		// Create new zone details
		// Handle interface names
		for _, interfaceName := range zone.Interfaces.InterfaceName {
			if interfaceName != "" {
				logger.DebugContext(ctx, "Firewall repository: Creating zone detail for zone %s with interface_name=%s", zone.ZoneName, interfaceName)

				var resolvedInterfaceID string
				// First check in our interface map
				if id, exists := interfaceMap[interfaceName]; exists {
					resolvedInterfaceID = id
					logger.DebugContext(ctx, "Firewall repository: Found interface in map: %s -> %s", interfaceName, resolvedInterfaceID)
				} else {
					// Check if interface exists in database (by name)
					var existingInterface types.Interfaces
					if err := tx.Where("interface_name = ? AND deleted_at IS NULL", interfaceName).First(&existingInterface).Error; err != nil {
						if err == gorm.ErrRecordNotFound {
							logger.ErrorContext(ctx, "Firewall repository: Interface not found for zone %s: %s. Available interfaces: %v", zone.ZoneName, interfaceName, interfaceMap)
							return errors.New("interface not found for zone: " + interfaceName)
						}
						logger.ErrorContext(ctx, "Firewall repository: Database error checking interface: %v", err)
						return err
					}
					resolvedInterfaceID = existingInterface.ID
					logger.DebugContext(ctx, "Firewall repository: Found interface in database: %s -> %s", interfaceName, resolvedInterfaceID)
				}

				// Create zone detail with interface only
				zoneDetailRecord := types.ZoneDetails{
					ID:                  uuid.New().String(),
					ZoneID:              zoneID,
					FirewallInterfaceID: resolvedInterfaceID,
					VLANTableID:         "", // Empty for interface-only relationships
					CreatedAt:           time.Now(),
					UpdatedAt:           time.Now(),
				}

				if err := tx.Create(&zoneDetailRecord).Error; err != nil {
					logger.ErrorContext(ctx, "Firewall repository: Failed to create zone detail for interface: %v", err)
					return err
				}
			}
		}

		// Handle VLAN names
		for _, vlanName := range zone.Interfaces.VLANName {
			if vlanName != "" {
				logger.DebugContext(ctx, "Firewall repository: Creating zone detail for zone %s with vlan_name=%s", zone.ZoneName, vlanName)

				// Resolve VLAN name to ID
				var resolvedVLANID string
				// First check in our VLAN map
				if vlanID, exists := vlanMap[vlanName]; exists {
					resolvedVLANID = vlanID
					logger.DebugContext(ctx, "Firewall repository: Found VLAN in map: %s -> %s", vlanName, resolvedVLANID)
				} else {
					// Check if VLAN exists in database (by name)
					var existingVLAN types.VLANs
					if err := tx.Where("vlan_name = ? AND deleted_at IS NULL", vlanName).First(&existingVLAN).Error; err != nil {
						if err == gorm.ErrRecordNotFound {
							logger.ErrorContext(ctx, "Firewall repository: VLAN not found for zone %s: %s. Available VLANs: %v", zone.ZoneName, vlanName, vlanMap)
							return errors.New("VLAN not found for zone: " + vlanName)
						}
						logger.ErrorContext(ctx, "Firewall repository: Database error checking VLAN: %v", err)
						return err
					}
					resolvedVLANID = existingVLAN.ID
					logger.DebugContext(ctx, "Firewall repository: Found VLAN in database: %s -> %s", vlanName, resolvedVLANID)
				}

				// Create zone detail with VLAN only
				zoneDetailRecord := types.ZoneDetails{
					ID:                  uuid.New().String(),
					ZoneID:              zoneID,
					FirewallInterfaceID: "", // Empty for VLAN-only relationships
					VLANTableID:         resolvedVLANID,
					CreatedAt:           time.Now(),
					UpdatedAt:           time.Now(),
				}

				if err := tx.Create(&zoneDetailRecord).Error; err != nil {
					logger.ErrorContext(ctx, "Firewall repository: Failed to create zone detail for VLAN: %v", err)
					return err
				}
			}
		}
	}
	// Rule 4: Delete orphaned zones (not referenced in the update request)
	for _, existing := range existingZones {
		if !referencedZones[existing.ID] {
			logger.DebugContext(ctx, "Firewall repository: Soft deleting orphaned zone: %s", existing.ZoneName)

			// Soft delete zone details first (foreign key dependency)
			if err := tx.Model(&types.ZoneDetails{}).Where("zone_id = ?", existing.ID).Update("deleted_at", time.Now()).Error; err != nil {
				logger.ErrorContext(ctx, "Firewall repository: Failed to soft delete zone details for orphaned zone %s: %v", existing.ZoneName, err)
				return err
			}

			// Soft delete the zone
			if err := tx.Model(&existing).Update("deleted_at", time.Now()).Error; err != nil {
				logger.ErrorContext(ctx, "Firewall repository: Failed to soft delete orphaned zone %s: %v", existing.ZoneName, err)
				return err
			}
		}
	}

	logger.DebugContext(ctx, "Firewall repository: Successfully updated %d zones", len(zones))
	return nil
}

// updatePolicies updates policy records
func (r *FirewallAssetRepo) updatePolicies(ctx context.Context, tx *gorm.DB, policies []domain.FirewallPolicy, firewallDetailsID string) error {
	// Get existing policies for this firewall
	var existingPolicies []types.FirewallPolicy
	if err := tx.Where("firewall_details_id = ?", firewallDetailsID).Find(&existingPolicies).Error; err != nil {
		logger.ErrorContext(ctx, "Firewall repository: Failed to fetch existing policies: %v", err)
		return err
	}

	// Create a map of existing policies by ID and name
	existingByID := make(map[string]types.FirewallPolicy)
	existingByName := make(map[string]types.FirewallPolicy)
	for _, existing := range existingPolicies {
		existingByID[existing.ID] = existing
		existingByName[existing.PolicyName] = existing
	}

	// Track which existing policies are still referenced
	referencedPolicies := make(map[string]bool)

	// Process each policy in the update request
	for _, policy := range policies {
		var policyID string
		var isUpdate bool

		// Rule 1: If ID is provided, check if it exists and is already connected
		if policy.ID != "" {
			if existing, exists := existingByID[policy.ID]; exists {
				// ID exists and is connected - update it
				policyID = existing.ID
				isUpdate = true
				logger.DebugContext(ctx, "Firewall repository: Updating existing policy by ID: %s", policy.ID)
			} else {
				// Rule 3: ID provided but doesn't exist - return error
				logger.ErrorContext(ctx, "Firewall repository: Policy ID provided but does not exist: %s", policy.ID)
				return errors.New("policy ID provided but does not exist: " + policy.ID)
			}
		} else {
			// Rule 2: If name is provided instead of ID, check if policy exists by name
			if existing, exists := existingByName[policy.PolicyName]; exists {
				// Policy exists by name - update it
				policyID = existing.ID
				isUpdate = true
				logger.DebugContext(ctx, "Firewall repository: Updating existing policy by name: %s", policy.PolicyName)
			} else {
				// Policy doesn't exist - create new one
				policyID = uuid.New().String()
				isUpdate = false
				logger.DebugContext(ctx, "Firewall repository: Creating new policy: %s", policy.PolicyName)
			}
		}

		// Mark this policy as referenced
		referencedPolicies[policyID] = true

		// Create/update policy record
		policyRecord := types.FirewallPolicy{
			ID:                   policyID,
			FirewallDetailsID:    firewallDetailsID,
			PolicyName:           policy.PolicyName,
			PolicyID:             policy.PolicyID,
			Action:               policy.Action,
			PolicyType:           policy.PolicyType,
			Status:               policy.Status,
			RuleOrder:            policy.RuleOrder,
			VendorSpecificConfig: policy.VendorSpecificConfig,
			UpdatedAt:            time.Now(),
		}

		if isUpdate {
			// Update existing policy
			if err := tx.Model(&types.FirewallPolicy{}).Where("id = ?", policyID).Updates(&policyRecord).Error; err != nil {
				logger.ErrorContext(ctx, "Firewall repository: Failed to update policy %s: %v", policy.PolicyName, err)
				return err
			}
		} else {
			// Create new policy
			policyRecord.CreatedAt = time.Now()
			if err := tx.Create(&policyRecord).Error; err != nil {
				logger.ErrorContext(ctx, "Firewall repository: Failed to create policy %s: %v", policy.PolicyName, err)
				return err
			}
		}
	}
	// Rule 4: Delete orphaned policies (not referenced in the update request)
	for _, existing := range existingPolicies {
		if !referencedPolicies[existing.ID] {
			logger.DebugContext(ctx, "Firewall repository: Soft deleting orphaned policy: %s", existing.PolicyName)

			// Soft delete the policy
			if err := tx.Model(&existing).Update("deleted_at", time.Now()).Error; err != nil {
				logger.ErrorContext(ctx, "Firewall repository: Failed to soft delete orphaned policy %s: %v", existing.PolicyName, err)
				return err
			}
		}
	}

	logger.DebugContext(ctx, "Firewall repository: Successfully updated %d policies", len(policies))
	return nil
}

// Delete deletes a firewall and all its related entities
func (r *FirewallAssetRepo) Delete(ctx context.Context, firewallID domain.FirewallUUID) error {
	logger.InfoContext(ctx, "Firewall repository: Deleting firewall with ID: %s", firewallID.String())

	logger.DebugContext(ctx, "Firewall repository: Starting database transaction for delete")
	tx := r.db.WithContext(ctx).Begin()
	if tx.Error != nil {
		logger.ErrorContext(ctx, "Firewall repository: Failed to start transaction: %v", tx.Error)
		return tx.Error
	}

	defer func() {
		if r := recover(); r != nil {
			logger.ErrorContext(ctx, "Firewall repository: Panic occurred during delete, rolling back transaction: %v", r)
			tx.Rollback()
		}
	}()

	var existingAsset types.Assets
	if err := tx.Where("id = ?", firewallID.String()).First(&existingAsset).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			logger.WarnContext(ctx, "Firewall repository: Firewall not found for delete: %s", firewallID.String())
			tx.Rollback()
			return domain.ErrFirewallNotFound
		}
		logger.ErrorContext(ctx, "Firewall repository: Database error checking firewall existence: %v", err)
		tx.Rollback()
		return err
	}

	// Get firewall details for deletion cascade
	var firewallDetails types.FirewallDetails
	if err := tx.Where("asset_id = ?", firewallID.String()).First(&firewallDetails).Error; err != nil {
		if err != gorm.ErrRecordNotFound {
			logger.ErrorContext(ctx, "Firewall repository: Failed to get firewall details for delete: %v", err)
			tx.Rollback()
			return err
		}
	}

	// Delete all related entities in proper order

	// 1. Delete zone details (depends on zones)
	logger.DebugContext(ctx, "Firewall repository: Soft deleting zone details")
	if err := tx.Model(&types.ZoneDetails{}).
		Where("zone_id IN (SELECT id FROM zones WHERE firewall_id = ?)", firewallDetails.ID).
		Update("deleted_at", time.Now()).Error; err != nil {
		logger.ErrorContext(ctx, "Firewall repository: Failed to soft delete zone details: %v", err)
		tx.Rollback()
		return err
	}

	// 2. Delete zones
	logger.DebugContext(ctx, "Firewall repository: Soft deleting zones")
	if err := tx.Model(&types.Zones{}).
		Where("firewall_id = ?", firewallDetails.ID).
		Update("deleted_at", time.Now()).Error; err != nil {
		logger.ErrorContext(ctx, "Firewall repository: Failed to soft delete zones: %v", err)
		tx.Rollback()
		return err
	}

	// 3. Delete policies
	logger.DebugContext(ctx, "Firewall repository: Soft deleting policies")
	if err := tx.Model(&types.FirewallPolicy{}).
		Where("firewall_details_id = ?", firewallDetails.ID).
		Update("deleted_at", time.Now()).Error; err != nil {
		logger.ErrorContext(ctx, "Firewall repository: Failed to soft delete policies: %v", err)
		tx.Rollback()
		return err
	}

	// 4. Delete VLAN-Interface relationships
	logger.DebugContext(ctx, "Firewall repository: Soft deleting VLAN-Interface relationships")
	if err := tx.Model(&types.VLANInterface{}).
		Where("vlan_table_id IN (SELECT id FROM vlans WHERE asset_id = ? AND device_type = ?)", firewallID.String(), "firewall").
		Update("deleted_at", time.Now()).Error; err != nil {
		logger.ErrorContext(ctx, "Firewall repository: Failed to soft delete VLAN-Interface relationships: %v", err)
		tx.Rollback()
		return err
	}

	// 5. Delete VLANs
	logger.DebugContext(ctx, "Firewall repository: Soft deleting VLANs")
	if err := tx.Model(&types.VLANs{}).
		Where("asset_id = ? AND device_type = ?", firewallID.String(), "firewall").
		Update("deleted_at", time.Now()).Error; err != nil {
		logger.ErrorContext(ctx, "Firewall repository: Failed to soft delete VLANs: %v", err)
		tx.Rollback()
		return err
	}

	// 6. Delete IPs (associated with interfaces)
	logger.DebugContext(ctx, "Firewall repository: Soft deleting IPs")
	if err := tx.Model(&types.IPs{}).
		Where("asset_id = ?", firewallID.String()).
		Update("deleted_at", time.Now()).Error; err != nil {
		logger.ErrorContext(ctx, "Firewall repository: Failed to soft delete IPs: %v", err)
		tx.Rollback()
		return err
	}

	// 7. Delete interfaces
	logger.DebugContext(ctx, "Firewall repository: Soft deleting interfaces")
	if err := tx.Model(&types.Interfaces{}).
		Where("asset_id = ?", firewallID.String()).
		Update("deleted_at", time.Now()).Error; err != nil {
		logger.ErrorContext(ctx, "Firewall repository: Failed to soft delete interfaces: %v", err)
		tx.Rollback()
		return err
	}

	// 8. Delete firewall details
	logger.DebugContext(ctx, "Firewall repository: Soft deleting firewall details")
	if err := tx.Model(&types.FirewallDetails{}).
		Where("asset_id = ?", firewallID.String()).
		Update("deleted_at", time.Now()).Error; err != nil {
		logger.ErrorContext(ctx, "Firewall repository: Failed to soft delete firewall details: %v", err)
		tx.Rollback()
		return err
	}

	// 9. delete the asset
	logger.DebugContext(ctx, "Firewall repository: Soft deleting asset")
	if err := tx.Model(&types.Assets{}).
		Where("id = ?", firewallID.String()).
		Update("deleted_at", time.Now()).Error; err != nil {
		logger.ErrorContext(ctx, "Firewall repository: Failed to soft delete asset: %v", err)
		tx.Rollback()
		return err
	}

	// Commit transaction
	logger.DebugContext(ctx, "Firewall repository: Committing delete transaction")
	if err := tx.Commit().Error; err != nil {
		logger.ErrorContext(ctx, "Firewall repository: Failed to commit delete transaction: %v", err)
		return err
	}

	logger.InfoContext(ctx, "Firewall repository: Successfully deleted firewall with ID: %s", firewallID.String())
	return nil
}

// DeleteBatch deletes multiple firewalls and all their related entities
func (r *FirewallAssetRepo) DeleteBatch(ctx context.Context, firewallIDs []domain.FirewallUUID) error {
	logger.InfoContextWithFields(ctx, "Firewall repository: Deleting firewalls in batch", map[string]interface{}{
		"firewall_count": len(firewallIDs),
	})

	if len(firewallIDs) == 0 {
		logger.WarnContext(ctx, "Firewall repository: Empty firewall IDs list provided for batch delete")
		return nil
	}

	firewallIDStrings := make([]string, len(firewallIDs))
	for i, id := range firewallIDs {
		firewallIDStrings[i] = id.String()
	}

	logger.DebugContext(ctx, "Firewall repository: Starting database transaction for batch delete")
	tx := r.db.WithContext(ctx).Begin()
	if tx.Error != nil {
		logger.ErrorContext(ctx, "Firewall repository: Failed to start transaction: %v", tx.Error)
		return tx.Error
	}

	defer func() {
		if r := recover(); r != nil {
			logger.ErrorContext(ctx, "Firewall repository: Panic occurred during batch delete, rolling back transaction: %v", r)
			tx.Rollback()
		}
	}()

	// Get all firewall details for deletion cascade
	var firewallDetailsList []types.FirewallDetails
	if err := tx.Where("asset_id IN ?", firewallIDStrings).Find(&firewallDetailsList).Error; err != nil {
		logger.ErrorContext(ctx, "Firewall repository: Failed to get firewall details for batch delete: %v", err)
		tx.Rollback()
		return err
	}

	firewallDetailsIDs := make([]string, len(firewallDetailsList))
	for i, details := range firewallDetailsList {
		firewallDetailsIDs[i] = details.ID
	}

	// Delete all related entities in proper order

	// 1. Delete zone details
	logger.DebugContext(ctx, "Firewall repository: Soft deleting zone details for batch")
	if len(firewallDetailsIDs) > 0 {
		if err := tx.Model(&types.ZoneDetails{}).
			Where("zone_id IN (SELECT id FROM zones WHERE firewall_id IN ?)", firewallDetailsIDs).
			Update("deleted_at", time.Now()).Error; err != nil {
			logger.ErrorContext(ctx, "Firewall repository: Failed to soft delete zone details for batch: %v", err)
			tx.Rollback()
			return err
		}
	}

	// 2. Delete zones
	logger.DebugContext(ctx, "Firewall repository: Soft deleting zones for batch")
	if len(firewallDetailsIDs) > 0 {
		if err := tx.Model(&types.Zones{}).
			Where("firewall_id IN ?", firewallDetailsIDs).
			Update("deleted_at", time.Now()).Error; err != nil {
			logger.ErrorContext(ctx, "Firewall repository: Failed to soft delete zones for batch: %v", err)
			tx.Rollback()
			return err
		}
	}

	// 3. Delete policies
	logger.DebugContext(ctx, "Firewall repository: Soft deleting policies for batch")
	if len(firewallDetailsIDs) > 0 {
		if err := tx.Model(&types.FirewallPolicy{}).
			Where("firewall_details_id IN ?", firewallDetailsIDs).
			Update("deleted_at", time.Now()).Error; err != nil {
			logger.ErrorContext(ctx, "Firewall repository: Failed to soft delete policies for batch: %v", err)
			tx.Rollback()
			return err
		}
	}

	// 4. Delete VLAN-Interface relationships
	logger.DebugContext(ctx, "Firewall repository: Soft deleting VLAN-Interface relationships for batch")
	if err := tx.Model(&types.VLANInterface{}).
		Where("vlan_table_id IN (SELECT id FROM vlans WHERE asset_id IN ? AND device_type = ?)", firewallIDStrings, "firewall").
		Update("deleted_at", time.Now()).Error; err != nil {
		logger.ErrorContext(ctx, "Firewall repository: Failed to soft delete VLAN-Interface relationships for batch: %v", err)
		tx.Rollback()
		return err
	}

	// 5. Delete VLANs
	logger.DebugContext(ctx, "Firewall repository: Soft deleting VLANs for batch")
	if err := tx.Model(&types.VLANs{}).
		Where("asset_id IN ? AND device_type = ?", firewallIDStrings, "firewall").
		Update("deleted_at", time.Now()).Error; err != nil {
		logger.ErrorContext(ctx, "Firewall repository: Failed to soft delete VLANs for batch: %v", err)
		tx.Rollback()
		return err
	}

	// 6. Delete IPs
	logger.DebugContext(ctx, "Firewall repository: Soft deleting IPs for batch")
	if err := tx.Model(&types.IPs{}).
		Where("asset_id IN ?", firewallIDStrings).
		Update("deleted_at", time.Now()).Error; err != nil {
		logger.ErrorContext(ctx, "Firewall repository: Failed to soft delete IPs for batch: %v", err)
		tx.Rollback()
		return err
	}

	// 7. Delete interfaces
	logger.DebugContext(ctx, "Firewall repository: Soft deleting interfaces for batch")
	if err := tx.Model(&types.Interfaces{}).
		Where("asset_id IN ?", firewallIDStrings).
		Update("deleted_at", time.Now()).Error; err != nil {
		logger.ErrorContext(ctx, "Firewall repository: Failed to soft delete interfaces for batch: %v", err)
		tx.Rollback()
		return err
	}

	// 8. Delete firewall details
	logger.DebugContext(ctx, "Firewall repository: Soft deleting firewall details for batch")
	if err := tx.Model(&types.FirewallDetails{}).
		Where("asset_id IN ?", firewallIDStrings).
		Update("deleted_at", time.Now()).Error; err != nil {
		logger.ErrorContext(ctx, "Firewall repository: Failed to soft delete firewall details for batch: %v", err)
		tx.Rollback()
		return err
	}

	// 9. Finally, delete the assets
	logger.DebugContext(ctx, "Firewall repository: Soft deleting assets for batch")
	if err := tx.Model(&types.Assets{}).
		Where("id IN ?", firewallIDStrings).
		Update("deleted_at", time.Now()).Error; err != nil {
		logger.ErrorContext(ctx, "Firewall repository: Failed to soft delete assets for batch: %v", err)
		tx.Rollback()
		return err
	}

	logger.DebugContext(ctx, "Firewall repository: Committing batch delete transaction")
	if err := tx.Commit().Error; err != nil {
		logger.ErrorContext(ctx, "Firewall repository: Failed to commit batch delete transaction: %v", err)
		return err
	}

	logger.InfoContext(ctx, "Firewall repository: Successfully deleted %d firewalls in batch", len(firewallIDs))
	return nil
}

// DeleteAll deletes all firewalls and their related entities
func (r *FirewallAssetRepo) DeleteAll(ctx context.Context) error {
	logger.InfoContext(ctx, "Firewall repository: Deleting all firewalls")

	logger.DebugContext(ctx, "Firewall repository: Starting database transaction for delete all")
	tx := r.db.WithContext(ctx).Begin()
	if tx.Error != nil {
		logger.ErrorContext(ctx, "Firewall repository: Failed to start transaction: %v", tx.Error)
		return tx.Error
	}

	defer func() {
		if r := recover(); r != nil {
			logger.ErrorContext(ctx, "Firewall repository: Panic occurred during delete all, rolling back transaction: %v", r)
			tx.Rollback()
		}
	}()

	// Get all firewall assets to delete
	var firewallAssets []types.Assets
	if err := tx.Where("asset_type = ?", "firewall").Find(&firewallAssets).Error; err != nil {
		logger.ErrorContext(ctx, "Firewall repository: Failed to get firewall assets for delete all: %v", err)
		tx.Rollback()
		return err
	}

	if len(firewallAssets) == 0 {
		logger.InfoContext(ctx, "Firewall repository: No firewalls found to delete")
		tx.Rollback()
		return nil
	}

	// Extract asset IDs
	assetIDs := make([]string, len(firewallAssets))
	for i, asset := range firewallAssets {
		assetIDs[i] = asset.ID
	}

	// Get all firewall details
	var firewallDetailsList []types.FirewallDetails
	if err := tx.Where("asset_id IN ?", assetIDs).Find(&firewallDetailsList).Error; err != nil {
		logger.ErrorContext(ctx, "Firewall repository: Failed to get firewall details for delete all: %v", err)
		tx.Rollback()
		return err
	}

	firewallDetailsIDs := make([]string, len(firewallDetailsList))
	for i, details := range firewallDetailsList {
		firewallDetailsIDs[i] = details.ID
	}

	// Delete all related entities in proper order

	// 1. Delete zone details
	logger.DebugContext(ctx, "Firewall repository: Soft deleting all zone details")
	if len(firewallDetailsIDs) > 0 {
		if err := tx.Model(&types.ZoneDetails{}).
			Where("zone_id IN (SELECT id FROM zones WHERE firewall_id IN ?)", firewallDetailsIDs).
			Update("deleted_at", time.Now()).Error; err != nil {
			logger.ErrorContext(ctx, "Firewall repository: Failed to soft delete all zone details: %v", err)
			tx.Rollback()
			return err
		}
	}

	// 2. Delete zones
	logger.DebugContext(ctx, "Firewall repository: Soft deleting all zones")
	if len(firewallDetailsIDs) > 0 {
		if err := tx.Model(&types.Zones{}).
			Where("firewall_id IN ?", firewallDetailsIDs).
			Update("deleted_at", time.Now()).Error; err != nil {
			logger.ErrorContext(ctx, "Firewall repository: Failed to soft delete all zones: %v", err)
			tx.Rollback()
			return err
		}
	}

	// 3. Delete policies
	logger.DebugContext(ctx, "Firewall repository: Soft deleting all policies")
	if len(firewallDetailsIDs) > 0 {
		if err := tx.Model(&types.FirewallPolicy{}).
			Where("firewall_details_id IN ?", firewallDetailsIDs).
			Update("deleted_at", time.Now()).Error; err != nil {
			logger.ErrorContext(ctx, "Firewall repository: Failed to soft delete all policies: %v", err)
			tx.Rollback()
			return err
		}
	}

	// 4. Delete VLAN-Interface relationships
	logger.DebugContext(ctx, "Firewall repository: Soft deleting all VLAN-Interface relationships")
	if err := tx.Model(&types.VLANInterface{}).
		Where("vlan_table_id IN (SELECT id FROM vlans WHERE asset_id IN ? AND device_type = ?)", assetIDs, "firewall").
		Update("deleted_at", time.Now()).Error; err != nil {
		logger.ErrorContext(ctx, "Firewall repository: Failed to soft delete all VLAN-Interface relationships: %v", err)
		tx.Rollback()
		return err
	}

	// 5. Delete VLANs
	logger.DebugContext(ctx, "Firewall repository: Soft deleting all VLANs")
	if err := tx.Model(&types.VLANs{}).
		Where("asset_id IN ? AND device_type = ?", assetIDs, "firewall").
		Update("deleted_at", time.Now()).Error; err != nil {
		logger.ErrorContext(ctx, "Firewall repository: Failed to soft delete all VLANs: %v", err)
		tx.Rollback()
		return err
	}

	// 6. Delete IPs
	logger.DebugContext(ctx, "Firewall repository: Soft deleting all IPs")
	if err := tx.Model(&types.IPs{}).
		Where("asset_id IN ?", assetIDs).
		Update("deleted_at", time.Now()).Error; err != nil {
		logger.ErrorContext(ctx, "Firewall repository: Failed to soft delete all IPs: %v", err)
		tx.Rollback()
		return err
	}

	// 7. Delete interfaces
	logger.DebugContext(ctx, "Firewall repository: Soft deleting all interfaces")
	if err := tx.Model(&types.Interfaces{}).
		Where("asset_id IN ?", assetIDs).
		Update("deleted_at", time.Now()).Error; err != nil {
		logger.ErrorContext(ctx, "Firewall repository: Failed to soft delete all interfaces: %v", err)
		tx.Rollback()
		return err
	}

	// 8. Delete firewall details
	logger.DebugContext(ctx, "Firewall repository: Soft deleting all firewall details")
	if err := tx.Model(&types.FirewallDetails{}).
		Where("asset_id IN ?", assetIDs).
		Update("deleted_at", time.Now()).Error; err != nil {
		logger.ErrorContext(ctx, "Firewall repository: Failed to soft delete all firewall details: %v", err)
		tx.Rollback()
		return err
	}

	// 9. Finally, delete all firewall assets
	logger.DebugContext(ctx, "Firewall repository: Soft deleting all firewall assets")
	if err := tx.Model(&types.Assets{}).
		Where("id IN ?", assetIDs).
		Update("deleted_at", time.Now()).Error; err != nil {
		logger.ErrorContext(ctx, "Firewall repository: Failed to soft delete all firewall assets: %v", err)
		tx.Rollback()
		return err
	}

	logger.DebugContext(ctx, "Firewall repository: Committing delete all transaction")
	if err := tx.Commit().Error; err != nil {
		logger.ErrorContext(ctx, "Firewall repository: Failed to commit delete all transaction: %v", err)
		return err
	}

	logger.InfoContext(ctx, "Firewall repository: Successfully deleted all %d firewalls", len(firewallAssets))
	return nil
}

// CheckVendorExists checks if a vendor exists by vendor code
func (r *FirewallAssetRepo) CheckVendorExists(ctx context.Context, vendorCode string) (bool, error) {
	logger.DebugContext(ctx, "Firewall repository: Checking if vendor exists: %s", vendorCode)

	var count int64
	if err := r.db.WithContext(ctx).Model(&types.Vendors{}).Where("vendor_code = ?", vendorCode).Count(&count).Error; err != nil {
		logger.ErrorContext(ctx, "Firewall repository: Failed to check vendor existence: %v", err)
		return false, err
	}

	exists := count > 0
	logger.DebugContext(ctx, "Firewall repository: Vendor %s exists: %t", vendorCode, exists)
	return exists, nil
}

// CheckManagementIPExists checks if a management IP already exists
func (r *FirewallAssetRepo) CheckManagementIPExists(ctx context.Context, managementIP string) (bool, error) {
	logger.DebugContext(ctx, "Firewall repository: Checking if management IP exists: %s", managementIP)

	var count int64
	if err := r.db.WithContext(ctx).Model(&types.FirewallDetails{}).Where("management_ip = ? AND deleted_at IS NULL", managementIP).Count(&count).Error; err != nil {
		logger.ErrorContext(ctx, "Firewall repository: Failed to check management IP existence: %v", err)
		return false, err
	}

	exists := count > 0
	logger.DebugContext(ctx, "Firewall repository: Management IP %s exists: %t", managementIP, exists)
	return exists, nil
}

// CheckManagementIPExistsExcludingFirewall checks if a management IP exists for other firewalls
func (r *FirewallAssetRepo) CheckManagementIPExistsExcludingFirewall(ctx context.Context, managementIP string, firewallID domain.FirewallUUID) (bool, error) {
	logger.DebugContext(ctx, "Firewall repository: Checking if management IP exists for other firewalls: %s (excluding %s)", managementIP, firewallID.String())

	var count int64
	if err := r.db.WithContext(ctx).Model(&types.FirewallDetails{}).
		Where("management_ip = ? AND asset_id != ? AND deleted_at IS NULL", managementIP, firewallID.String()).
		Count(&count).Error; err != nil {
		logger.ErrorContext(ctx, "Firewall repository: Failed to check management IP existence: %v", err)
		return false, err
	}

	exists := count > 0
	logger.DebugContext(ctx, "Firewall repository: Management IP %s exists for other firewalls: %t", managementIP, exists)
	return exists, nil
}

// List retrieves firewalls with pagination and efficient bulk loading
func (r *FirewallAssetRepo) List(ctx context.Context, limit int, offset int) (*domain.ListFirewalls, error) {
	logger.InfoContextWithFields(ctx, "Firewall repository: Listing firewalls with pagination", map[string]interface{}{
		"limit":  limit,
		"offset": offset,
	})

	// Get total count of firewall assets
	var totalCount int64
	logger.DebugContext(ctx, "Firewall repository: Getting total count of firewalls")
	if err := r.db.WithContext(ctx).
		Model(&types.Assets{}).
		Where("asset_type IN ? AND deleted_at IS NULL", []string{"Firewall Device", "firewall"}).
		Count(&totalCount).Error; err != nil {
		logger.ErrorContext(ctx, "Firewall repository: Failed to get total count of firewalls: %v", err)
		return nil, err
	}

	var assets []types.Assets
	logger.DebugContextWithFields(ctx, "Firewall repository: Fetching paginated firewall assets", map[string]interface{}{
		"total_count": totalCount,
	})
	if err := r.db.WithContext(ctx).
		Preload("Vendor").
		Where("asset_type IN ? AND deleted_at IS NULL", []string{"Firewall Device", "firewall"}).
		Limit(limit).
		Offset(offset).
		Find(&assets).Error; err != nil {
		logger.ErrorContext(ctx, "Firewall repository: Failed to fetch firewall assets: %v", err)
		return nil, err
	}

	if len(assets) == 0 {
		logger.InfoContext(ctx, "Firewall repository: No firewalls found")
		return &domain.ListFirewalls{
			Firewalls:  []domain.FirewallDomain{},
			TotalCount: int(totalCount),
		}, nil
	}

	assetIDs := make([]string, len(assets))
	for i, asset := range assets {
		assetIDs[i] = asset.ID
	}

	var details []types.FirewallDetails
	logger.DebugContext(ctx, "Firewall repository: Bulk fetching firewall details for %d assets", len(assetIDs))
	if err := r.db.WithContext(ctx).
		Where("asset_id IN ? AND deleted_at IS NULL", assetIDs).
		Find(&details).Error; err != nil {
		logger.ErrorContext(ctx, "Firewall repository: Failed to bulk fetch firewall details: %v", err)
		return nil, err
	}

	detailsMap := make(map[string]types.FirewallDetails)
	for _, detail := range details {
		detailsMap[detail.AssetID] = detail
	}

	detailIDs := make([]string, 0, len(details))
	for _, detail := range details {
		detailIDs = append(detailIDs, detail.ID)
	}

	var zones []types.Zones
	if len(detailIDs) > 0 {
		logger.DebugContext(ctx, "Firewall repository: Bulk fetching zones for %d firewall details", len(detailIDs))
		if err := r.db.WithContext(ctx).
			Preload("ZoneDetails", "deleted_at IS NULL").
			Where("firewall_id IN ? AND deleted_at IS NULL", detailIDs).
			Find(&zones).Error; err != nil {
			logger.ErrorContext(ctx, "Firewall repository: Failed to bulk fetch zones: %v", err)
			return nil, err
		}
	}

	zonesMap := make(map[string][]types.Zones)
	for _, zone := range zones {
		zonesMap[zone.FirewallID] = append(zonesMap[zone.FirewallID], zone)
	}

	var interfaces []types.Interfaces
	logger.DebugContext(ctx, "Firewall repository: Bulk fetching interfaces for %d assets", len(assetIDs))
	if err := r.db.WithContext(ctx).
		Preload("InterfaceType").
		Where("asset_id IN ? AND deleted_at IS NULL", assetIDs).
		Order("updated_at ASC").
		Find(&interfaces).Error; err != nil {
		logger.ErrorContext(ctx, "Firewall repository: Failed to bulk fetch interfaces: %v", err)
		return nil, err
	}

	interfacesMap := make(map[string][]types.Interfaces)
	for _, iface := range interfaces {
		if iface.AssetID != nil {
			interfacesMap[*iface.AssetID] = append(interfacesMap[*iface.AssetID], iface)
		}
	}

	var vlans []types.VLANs
	logger.DebugContext(ctx, "Firewall repository: Bulk fetching VLANs for %d assets", len(assetIDs))
	if err := r.db.WithContext(ctx).
		Where("asset_id IN ? AND device_type = ? AND deleted_at IS NULL", assetIDs, "firewall").
		Find(&vlans).Error; err != nil {
		logger.ErrorContext(ctx, "Firewall repository: Failed to bulk fetch VLANs: %v", err)
		return nil, err
	}

	vlansMap := make(map[string][]types.VLANs)
	for _, vlan := range vlans {
		vlansMap[vlan.AssetID] = append(vlansMap[vlan.AssetID], vlan)
	}

	var vlanInterfaces []types.VLANInterface
	if len(vlans) > 0 {
		vlanIDs := make([]string, len(vlans))
		for i, vlan := range vlans {
			vlanIDs[i] = vlan.ID
		}

		logger.DebugContext(ctx, "Firewall repository: Bulk fetching VLAN-Interface relationships for %d VLANs", len(vlanIDs))
		if err := r.db.WithContext(ctx).
			Where("vlan_table_id IN ? AND deleted_at IS NULL", vlanIDs).
			Find(&vlanInterfaces).Error; err != nil {
			logger.ErrorContext(ctx, "Firewall repository: Failed to bulk fetch VLAN-Interface relationships: %v", err)
			return nil, err
		}
	}

	var policies []types.FirewallPolicy
	if len(detailIDs) > 0 {
		logger.DebugContext(ctx, "Firewall repository: Bulk fetching policies for %d firewall details", len(detailIDs))
		if err := r.db.WithContext(ctx).
			Where("firewall_details_id IN ? AND deleted_at IS NULL", detailIDs).
			Find(&policies).Error; err != nil {
			logger.ErrorContext(ctx, "Firewall repository: Failed to bulk fetch policies: %v", err)
			return nil, err
		}
	}

	policiesMap := make(map[string][]types.FirewallPolicy)
	for _, policy := range policies {
		policiesMap[policy.FirewallDetailsID] = append(policiesMap[policy.FirewallDetailsID], policy)
	}

	var ips []types.IPs
	logger.DebugContext(ctx, "Firewall repository: Bulk fetching IPs for %d assets", len(assetIDs))
	if err := r.db.WithContext(ctx).
		Where("asset_id IN ? AND deleted_at IS NULL", assetIDs).
		Find(&ips).Error; err != nil {
		logger.ErrorContext(ctx, "Firewall repository: Failed to bulk fetch IPs: %v", err)
		return nil, err
	}

	ipsMap := make(map[string][]types.IPs)
	for _, ip := range ips {
		ipsMap[ip.AssetID] = append(ipsMap[ip.AssetID], ip)
	}

	logger.DebugContext(ctx, "Firewall repository: Converting storage types to domain models")
	firewallDomains := make([]domain.FirewallDomain, 0, len(assets))

	for _, asset := range assets {
		detail, hasDetail := detailsMap[asset.ID]
		if !hasDetail {
			logger.WarnContext(ctx, "Firewall repository: No firewall details found for asset %s, skipping", asset.ID)
			continue
		}

		assetZones := zonesMap[detail.ID]
		assetInterfaces := interfacesMap[asset.ID]
		assetVLANs := vlansMap[asset.ID]
		assetPolicies := policiesMap[detail.ID]
		assetIPs := ipsMap[asset.ID]

		firewallDomain, err := typesMapper.FirewallStorage2Domain(asset, detail, assetZones, assetInterfaces, assetVLANs, assetPolicies, assetIPs, vlanInterfaces)
		if err != nil {
			logger.ErrorContextWithFields(ctx, "Firewall repository: Failed to convert firewall to domain model", map[string]interface{}{
				"asset_id":   asset.ID,
				"asset_name": asset.Name,
				"error":      err.Error(),
			})
			continue
		}

		firewallDomains = append(firewallDomains, *firewallDomain)
	}

	result := &domain.ListFirewalls{
		Firewalls:  firewallDomains,
		TotalCount: int(totalCount),
	}

	logger.InfoContextWithFields(ctx, "Firewall repository: Successfully retrieved firewalls", map[string]interface{}{
		"returned_count": len(firewallDomains),
		"total_count":    totalCount,
	})

	return result, nil
}
