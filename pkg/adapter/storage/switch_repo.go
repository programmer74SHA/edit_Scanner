package storage

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	assetPort "gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/port"
	scannerDomain "gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanner/domain"
	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/switch/domain"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/adapter/storage/types"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/adapter/storage/types/mapper"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/logger"
	"gorm.io/gorm"
)

type SwitchRepository struct {
	db        *gorm.DB
	assetRepo assetPort.Repo
}

// NewSwitchRepository creates a new unified switch repository
func NewSwitchRepository(db *gorm.DB, assetRepo assetPort.Repo) *SwitchRepository {
	return &SwitchRepository{
		db:        db,
		assetRepo: assetRepo,
	}
}

// StoreSwitchScanResult stores complete switch scan results in a single transaction
func (r *SwitchRepository) StoreSwitchScanResult(ctx context.Context, result *scannerDomain.SwitchScanResult) error {
	logger.InfoContext(ctx, "[SwitchRepo] Starting to store switch scan result for device: %s", result.DeviceIP)
	logger.InfoContext(ctx, "[SwitchRepo] Data to store: %d interfaces, %d VLANs, %d neighbors",
		len(result.Interfaces), len(result.VLANs), len(result.Neighbors))

	if result == nil {
		return fmt.Errorf("switch scan result is nil")
	}

	if result.AssetID == "" {
		return fmt.Errorf("asset ID is required for switch scan result")
	}

	assetID, err := uuid.Parse(result.AssetID)
	if err != nil {
		return fmt.Errorf("invalid asset ID format '%s': %w", result.AssetID, err)
	}

	logger.InfoContext(ctx, "[SwitchRepo] Parsed asset ID: %s", assetID.String())

	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var totalStored int

		// Store interfaces
		if len(result.Interfaces) > 0 {
			logger.InfoContext(ctx, "[SwitchRepo] Storing %d interfaces", len(result.Interfaces))
			if err := r.storeInterfacesWithTx(ctx, tx, result.Interfaces, assetID); err != nil {
				logger.InfoContext(ctx, "[SwitchRepo] FAILED to store interfaces: %v", err)
				return fmt.Errorf("failed to store interfaces: %w", err)
			}
			logger.InfoContext(ctx, "[SwitchRepo] SUCCESS: Stored interfaces")
			totalStored += len(result.Interfaces)
		}

		// Store VLANs
		if len(result.VLANs) > 0 {
			logger.InfoContext(ctx, "[SwitchRepo] Storing %d VLANs", len(result.VLANs))
			if err := r.storeVLANsWithTx(ctx, tx, result.VLANs, assetID); err != nil {
				logger.InfoContext(ctx, "[SwitchRepo] FAILED to store VLANs: %v", err)
				return fmt.Errorf("failed to store VLANs: %w", err)
			}
			logger.InfoContext(ctx, "[SwitchRepo] SUCCESS: Stored VLANs")
			totalStored += len(result.VLANs)
		}

		// Store neighbors
		if len(result.Neighbors) > 0 {
			logger.InfoContext(ctx, "[SwitchRepo] Storing %d neighbors", len(result.Neighbors))
			if err := r.storeNeighborsWithTx(ctx, tx, result.Neighbors, assetID); err != nil {
				logger.InfoContext(ctx, "[SwitchRepo] FAILED to store neighbors: %v", err)
				return fmt.Errorf("failed to store neighbors: %w", err)
			}
			logger.InfoContext(ctx, "[SwitchRepo] SUCCESS: Stored neighbors")
			totalStored += len(result.Neighbors)
		}

		// Store VLAN ports if any (optional)
		if len(result.VLANPorts) > 0 {
			logger.InfoContext(ctx, "[SwitchRepo] Storing %d VLAN ports", len(result.VLANPorts))
			if err := r.storeVLANPortsWithTx(ctx, tx, result.VLANPorts, assetID); err != nil {
				logger.InfoContext(ctx, "[SwitchRepo] Warning: Failed to store VLAN ports: %v", err)
				// Don't fail the entire operation for VLAN ports
			}
		}

		// Store routing table if any (optional)
		if len(result.RoutingTable) > 0 {
			logger.InfoContext(ctx, "[SwitchRepo] Storing %d routing entries", len(result.RoutingTable))
			if err := r.storeRoutingTableWithTx(ctx, tx, result.RoutingTable, assetID); err != nil {
				logger.InfoContext(ctx, "[SwitchRepo] Warning: Failed to store routing table: %v", err)
				// Don't fail the entire operation for routing table
			}
		}

		logger.InfoContext(ctx, "[SwitchRepo] TRANSACTION SUCCESS: Stored all switch data for asset %s (total items: %d)",
			assetID.String(), totalStored)
		return nil
	})
}

// GetSwitchMetadataByAssetID retrieves switch metadata by asset ID
func (r *SwitchRepository) GetSwitchMetadataByAssetID(ctx context.Context, assetID uuid.UUID) (*scannerDomain.SwitchMetadata, error) {
	var metadata types.SwitchMetadata
	err := r.db.WithContext(ctx).Table("switch_metadata").
		Where("asset_id = ?", assetID.String()).
		First(&metadata).Error

	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil // Return nil when not found instead of error
		}
		return nil, fmt.Errorf("failed to get switch metadata: %w", err)
	}

	return mapper.SwitchMetadataStorage2Domain(&metadata), nil
}

// StoreSwitchMetadata stores switch metadata
func (r *SwitchRepository) StoreSwitchMetadata(ctx context.Context, metadata *scannerDomain.SwitchMetadata) error {
	if metadata == nil {
		return fmt.Errorf("metadata is nil")
	}

	storageMetadata := mapper.SwitchMetadataDomain2Storage(metadata)
	if storageMetadata.ID == "" {
		storageMetadata.ID = uuid.New().String()
	}
	storageMetadata.CreatedAt = time.Now()
	storageMetadata.UpdatedAt = time.Now()

	err := r.db.WithContext(ctx).Table("switch_metadata").Create(storageMetadata).Error
	if err != nil {
		return fmt.Errorf("failed to store switch metadata: %w", err)
	}

	metadata.ID = storageMetadata.ID
	return nil
}

// UpdateSwitchMetadata updates switch metadata
func (r *SwitchRepository) UpdateSwitchMetadata(ctx context.Context, metadata *scannerDomain.SwitchMetadata) error {
	if metadata == nil {
		return fmt.Errorf("metadata is nil")
	}

	if metadata.ID == "" {
		return fmt.Errorf("metadata ID is required for update")
	}

	updates := map[string]interface{}{
		"scanner_id": metadata.ScannerID,
		"username":   metadata.Username,
		"password":   metadata.Password,
		"port":       metadata.Port,
		"brand":      metadata.Brand,
		"updated_at": time.Now(),
	}

	result := r.db.WithContext(ctx).Table("switch_metadata").
		Where("id = ?", metadata.ID).
		Updates(updates)

	if result.Error != nil {
		return fmt.Errorf("failed to update switch metadata: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		return fmt.Errorf("switch metadata with ID %s not found", metadata.ID)
	}

	return nil
}

// DeleteSwitchDataByAssetID deletes all switch data by asset ID
func (r *SwitchRepository) DeleteSwitchDataByAssetID(ctx context.Context, assetID uuid.UUID) error {
	logger.InfoContext(ctx, "[SwitchRepo] Deleting all switch data for asset: %s", assetID.String())

	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		assetIDStr := assetID.String()

		// Soft delete interfaces
		if err := tx.Table("interfaces").
			Where("asset_id = ? AND deleted_at IS NULL", assetIDStr).
			Update("deleted_at", time.Now()).Error; err != nil {
			return fmt.Errorf("failed to delete interfaces: %w", err)
		}

		// Soft delete VLANs
		if err := tx.Table("vlans").
			Where("asset_id = ? AND deleted_at IS NULL", assetIDStr).
			Update("deleted_at", time.Now()).Error; err != nil {
			return fmt.Errorf("failed to delete VLANs: %w", err)
		}

		// Delete switch metadata (hard delete)
		if err := tx.Table("switch_metadata").
			Where("asset_id = ?", assetIDStr).
			Delete(&types.SwitchMetadata{}).Error; err != nil {
			return fmt.Errorf("failed to delete switch metadata: %w", err)
		}

		// Delete switch neighbors (hard delete)
		if err := tx.Table("switch_neighbors").
			Where("switch_id = ?", assetIDStr).
			Delete(&types.SwitchNeighbor{}).Error; err != nil {
			return fmt.Errorf("failed to delete switch neighbors: %w", err)
		}

		// Delete IPs associated with this asset
		if err := tx.Table("ips").
			Where("asset_id = ?", assetIDStr).
			Delete(&types.IPs{}).Error; err != nil {
			return fmt.Errorf("failed to delete IPs: %w", err)
		}

		logger.InfoContext(ctx, "[SwitchRepo] Successfully deleted all switch data for asset %s", assetIDStr)
		return nil
	})
}

// StoreInterfaces stores switch interfaces
func (r *SwitchRepository) StoreInterfaces(ctx context.Context, interfaces []scannerDomain.SwitchInterface, assetID uuid.UUID) error {
	if len(interfaces) == 0 {
		return nil
	}

	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		return r.storeInterfacesWithTx(ctx, tx, interfaces, assetID)
	})
}

// StoreVLANs stores switch VLANs
func (r *SwitchRepository) StoreVLANs(ctx context.Context, vlans []scannerDomain.SwitchVLAN, assetID uuid.UUID) error {
	if len(vlans) == 0 {
		return nil
	}

	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		return r.storeVLANsWithTx(ctx, tx, vlans, assetID)
	})
}

// StoreNeighbors stores switch neighbors
func (r *SwitchRepository) StoreNeighbors(ctx context.Context, neighbors []scannerDomain.SwitchNeighbor, assetID uuid.UUID) error {
	if len(neighbors) == 0 {
		return nil
	}

	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		return r.storeNeighborsWithTx(ctx, tx, neighbors, assetID)
	})
}

// GetAssetIDForScanner retrieves the asset ID associated with the scanner
func (r *SwitchRepository) GetAssetIDForScanner(ctx context.Context, scannerID int64) (uuid.UUID, error) {
	var switchMetadata types.SwitchMetadata
	if err := r.db.WithContext(ctx).Table("switch_metadata").
		Where("scanner_id = ?", scannerID).
		First(&switchMetadata).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return uuid.Nil, fmt.Errorf("no asset found for scanner ID: %d", scannerID)
		}
		return uuid.Nil, fmt.Errorf("failed to get scanner metadata: %w", err)
	}

	assetID, err := uuid.Parse(switchMetadata.AssetID)
	if err != nil {
		return uuid.Nil, fmt.Errorf("invalid asset ID format: %w", err)
	}

	return assetID, nil
}

// UpdateAssetWithScanResults updates the existing asset with information from the scan
func (r *SwitchRepository) UpdateAssetWithScanResults(ctx context.Context, assetID uuid.UUID, result *scannerDomain.SwitchScanResult) error {
	if result == nil {
		return fmt.Errorf("scan result is nil")
	}

	updates := map[string]interface{}{
		"updated_at": time.Now(),
	}

	// Update hostname if we got it from the scan
	if result.SystemInfo.Hostname != "" {
		// Truncate hostname to reasonable length
		hostname := r.truncateString(result.SystemInfo.Hostname, 100)
		updates["hostname"] = hostname
		// Update name only if it's currently a generic name
		updates["name"] = hostname
	}

	// Update OS information - TRUNCATE TO FIT DATABASE COLUMN
	if result.SystemInfo.SoftwareVersion != "" {
		// Extract just the version part, not the entire line
		osName := r.extractOSVersion(result.SystemInfo.SoftwareVersion)
		updates["os_name"] = r.truncateString(osName, 100) // Truncate to 100 chars max
	} else if result.SystemInfo.Model != "" {
		osName := fmt.Sprintf("Switch %s", result.SystemInfo.Model)
		updates["os_name"] = r.truncateString(osName, 100)
	}

	// Update description with more details
	description := fmt.Sprintf("Switch %s", r.truncateString(result.SystemInfo.Model, 50))
	if result.SystemInfo.SystemUptime != "" {
		description += fmt.Sprintf(" - Uptime: %s", r.truncateString(result.SystemInfo.SystemUptime, 50))
	}
	description += fmt.Sprintf(" (Last scanned: %s)", time.Now().Format("2006-01-02 15:04:05"))
	updates["description"] = r.truncateString(description, 500) // Truncate description too

	// Update the asset - make this more resilient
	result_update := r.db.WithContext(ctx).Table("assets").
		Where("id = ?", assetID.String()).
		Updates(updates)

	if result_update.Error != nil {
		// Log the error but don't fail the entire operation
		logger.InfoContext(ctx, "[SwitchRepo] Warning: Failed to update asset %s: %v", assetID.String(), result_update.Error)
		// Don't return error - allow switch data to be stored even if asset update fails
	} else if result_update.RowsAffected == 0 {
		logger.InfoContext(ctx, "[SwitchRepo] Warning: Asset %s not found for update", assetID.String())
	} else {
		logger.InfoContext(ctx, "[SwitchRepo] Successfully updated asset %s", assetID.String())
	}

	// Update asset IPs with MAC addresses from interfaces
	if err := r.updateAssetIPs(ctx, assetID, result); err != nil {
		logger.InfoContext(ctx, "[SwitchRepo] Warning: Failed to update asset IPs: %v", err)
		// Don't fail the entire operation for IP update failures
	}

	return nil // Always return nil to allow switch data storage to continue
}

// extractOSVersion extracts a clean OS version from a potentially long version string
func (r *SwitchRepository) extractOSVersion(fullVersion string) string {
	fullVersion = strings.TrimSpace(fullVersion)

	// Try to extract just the version number part
	// Example: "Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), Version 15.2(7)E3, RELEASE SOFTWARE (fc2)"
	// Should extract: "Cisco IOS 15.2(7)E3"

	if strings.Contains(fullVersion, "Version") {
		// Find "Version" and extract what comes after it
		parts := strings.Split(fullVersion, "Version")
		if len(parts) > 1 {
			versionPart := strings.TrimSpace(parts[1])
			// Take everything up to the first comma or space after version number
			fields := strings.FieldsFunc(versionPart, func(c rune) bool {
				return c == ',' || c == '\n' || c == '\r'
			})
			if len(fields) > 0 {
				return fmt.Sprintf("Cisco IOS %s", strings.TrimSpace(fields[0]))
			}
		}
	}

	// If we can't parse it cleanly, just take the first part
	if len(fullVersion) > 80 {
		return fullVersion[:77] + "..."
	}

	return fullVersion
}

// LinkAssetToScanJob links an asset to a scan job record
func (r *SwitchRepository) LinkAssetToScanJob(ctx context.Context, assetID uuid.UUID, scanJobID int64) error {
	if r.assetRepo != nil {
		return r.assetRepo.LinkAssetToScanJob(ctx, assetID, scanJobID)
	}

	// Fallback implementation
	linkRecord := map[string]interface{}{
		"scan_job_id": scanJobID,
		"asset_id":    assetID.String(),
		"created_at":  time.Now(),
	}

	if err := r.db.WithContext(ctx).Table("scan_job_assets").Create(linkRecord).Error; err != nil {
		logger.InfoContext(ctx, "[SwitchRepo] Warning: Could not create scan job asset link: %v", err)
		// Don't return error as this is not critical
	}

	return nil
}

// CreateSwitchAsset creates a new switch asset with associated metadata
func (r *SwitchRepository) CreateSwitchAsset(ctx context.Context, scannerID int64, switchConfig scannerDomain.SwitchConfig) (uuid.UUID, error) {
	// Validate required fields
	if err := r.validateSwitchConfig(switchConfig); err != nil {
		return uuid.Nil, fmt.Errorf("invalid switch config: %w", err)
	}

	var assetID uuid.UUID

	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var err error
		assetID, err = r.createSwitchAssetWithTx(tx, scannerID, switchConfig)
		return err
	})

	return assetID, err
}

// GetSwitchDataByAssetID retrieves comprehensive switch data by asset ID
func (r *SwitchRepository) GetSwitchDataByAssetID(ctx context.Context, assetID uuid.UUID) (*scannerDomain.SwitchData, error) {
	var data scannerDomain.SwitchData

	// Get switch metadata
	metadata, err := r.GetSwitchMetadataByAssetID(ctx, assetID)
	if err != nil {
		return nil, fmt.Errorf("failed to get switch metadata: %w", err)
	}
	data.Metadata = metadata

	// Get interfaces
	interfaceStorage, err := r.getSwitchInterfacesByAssetID(ctx, assetID)
	if err != nil {
		return nil, fmt.Errorf("failed to get interfaces: %w", err)
	}
	data.Interfaces = r.convertInterfacesToDomain(interfaceStorage)

	// Get VLANs
	vlanStorage, err := r.getSwitchVLANsByAssetID(ctx, assetID)
	if err != nil {
		return nil, fmt.Errorf("failed to get VLANs: %w", err)
	}
	data.VLANs = r.convertVLANsToDomain(vlanStorage)

	// Get neighbors
	neighborStorage, err := r.getSwitchNeighborsByAssetID(ctx, assetID)
	if err != nil {
		return nil, fmt.Errorf("failed to get neighbors: %w", err)
	}
	data.Neighbors = r.convertNeighborsToDomain(neighborStorage)

	return &data, nil
}

// storeInterfacesWithTx stores interfaces within a transaction
func (r *SwitchRepository) storeInterfacesWithTx(ctx context.Context, tx *gorm.DB, interfaces []scannerDomain.SwitchInterface, assetID uuid.UUID) error {
	if err := r.ensureInterfaceTypesExist(ctx, tx); err != nil {
		logger.InfoContext(ctx, "[SwitchRepo] Warning: Could not ensure interface types exist: %v", err)
	}

	successCount, errorCount := 0, 0

	for _, iface := range interfaces {
		interfaceName := strings.TrimSpace(iface.Name)
		if interfaceName == "" {
			errorCount++
			continue
		}

		// Create interface record
		interfaceRecord := types.Interfaces{
			ID:                   uuid.New().String(),
			InterfaceName:        r.truncateString(interfaceName, 100),
			InterfaceTypeID:      r.getInterfaceTypeIDWithFallback(ctx, tx, interfaceName),
			AssetID:              r.stringPtr(assetID.String()),
			Description:          r.truncateString(iface.Description, 500),
			OperationalStatus:    r.normalizeStatus(iface.Status),
			AdminStatus:          r.normalizeStatus(iface.Protocol),
			MacAddress:           r.cleanMacAddress(iface.MacAddress),
			VendorSpecificConfig: r.createVendorConfig(iface),
			CreatedAt:            time.Now(),
			UpdatedAt:            time.Now(),
		}

		// Set VLAN information if available
		if len(iface.VLANs) > 0 {
			if vlanID := r.parseVLANID(iface.VLANs[0]); vlanID > 0 && vlanID <= 4094 {
				interfaceRecord.VLANId = &vlanID
			}
		}

		if err := tx.Table("interfaces").Create(&interfaceRecord).Error; err != nil {
			logger.InfoContext(ctx, "[SwitchRepo] Error creating interface %s: %v", interfaceName, err)
			errorCount++
			continue
		}

		successCount++

		// Add interface IP if valid
		if r.isValidIP(iface.IPAddress) {
			if err := r.createInterfaceIP(ctx, tx, interfaceRecord.ID, assetID.String(), iface.IPAddress, iface.MacAddress); err != nil {
				logger.InfoContext(ctx, "[SwitchRepo] Warning: Failed to create IP %s for interface %s: %v", iface.IPAddress, interfaceName, err)
			}
		}
	}

	logger.InfoContext(ctx, "[SwitchRepo] Interface storage completed: %d successful, %d errors", successCount, errorCount)

	// Return error only if no interfaces were stored at all
	if successCount == 0 && len(interfaces) > 0 {
		return fmt.Errorf("failed to store any interfaces out of %d total", len(interfaces))
	}

	return nil
}

// storeVLANsWithTx stores VLANs within a transaction
func (r *SwitchRepository) storeVLANsWithTx(ctx context.Context, tx *gorm.DB, vlans []scannerDomain.SwitchVLAN, assetID uuid.UUID) error {
	successCount, errorCount := 0, 0

	for _, vlan := range vlans {
		if vlan.ID <= 0 || vlan.ID > 4094 {
			errorCount++
			continue
		}

		vlanRecord := types.VLANs{
			ID:                   uuid.New().String(),
			VLANNumber:           vlan.ID,
			VLANName:             r.truncateString(vlan.Name, 100),
			Description:          r.truncateString(vlan.Description, 500),
			IsNative:             vlan.ID == 1,
			DeviceType:           "switch",
			AssetID:              assetID.String(),
			VendorSpecificConfig: r.createVLANVendorConfig(vlan),
			CreatedAt:            time.Now(),
			UpdatedAt:            time.Now(),
		}

		if err := tx.Table("vlans").Create(&vlanRecord).Error; err != nil {
			logger.InfoContext(ctx, "[SwitchRepo] Error creating VLAN %d: %v", vlan.ID, err)
			errorCount++
			continue
		}

		successCount++
	}

	logger.InfoContext(ctx, "[SwitchRepo] VLAN storage completed: %d successful, %d errors", successCount, errorCount)

	if successCount == 0 && len(vlans) > 0 {
		return fmt.Errorf("failed to store any VLANs out of %d total", len(vlans))
	}

	return nil
}

// storeNeighborsWithTx stores neighbors within a transaction
func (r *SwitchRepository) storeNeighborsWithTx(ctx context.Context, tx *gorm.DB, neighbors []scannerDomain.SwitchNeighbor, assetID uuid.UUID) error {
	successCount, errorCount := 0, 0

	for _, neighbor := range neighbors {
		deviceID := strings.TrimSpace(neighbor.DeviceID)
		if deviceID == "" {
			errorCount++
			continue
		}

		localPort := strings.TrimSpace(neighbor.LocalPort)
		if localPort == "" {
			localPort = "unknown"
		}

		neighborRecord := types.SwitchNeighbor{
			ID:           uuid.New().String(),
			SwitchID:     assetID.String(),
			DeviceID:     r.truncateString(deviceID, 200),
			LocalPort:    r.truncateString(localPort, 100),
			RemotePort:   r.stringPtrOrNil(r.truncateString(neighbor.RemotePort, 100)),
			Platform:     r.stringPtrOrNil(r.truncateString(neighbor.Platform, 200)),
			IPAddress:    r.stringPtrOrNil(neighbor.IPAddress),
			Capabilities: r.stringPtrOrNil(r.truncateString(strings.Join(neighbor.Capabilities, ","), 200)),
			Software:     r.stringPtrOrNil(r.truncateString(neighbor.Software, 500)),
			Duplex:       r.stringPtrOrNil(r.truncateString(neighbor.Duplex, 20)),
			Protocol:     r.getProtocolOrDefault(neighbor.Protocol),
			CreatedAt:    time.Now(),
			UpdatedAt:    time.Now(),
		}

		if err := tx.Table("switch_neighbors").Create(&neighborRecord).Error; err != nil {
			logger.InfoContext(ctx, "[SwitchRepo] Error creating neighbor %s: %v", deviceID, err)
			errorCount++
			continue
		}

		successCount++
	}

	logger.InfoContext(ctx, "[SwitchRepo] Neighbor storage completed: %d successful, %d errors", successCount, errorCount)

	if successCount == 0 && len(neighbors) > 0 {
		return fmt.Errorf("failed to store any neighbors out of %d total", len(neighbors))
	}

	return nil
}

// storeVLANPortsWithTx stores VLAN port mappings within a transaction
func (r *SwitchRepository) storeVLANPortsWithTx(ctx context.Context, tx *gorm.DB, vlanPorts []scannerDomain.SwitchVLANPort, assetID uuid.UUID) error {
	// This is an optional table that might not exist in all setups
	successCount := 0

	for _, vlanPort := range vlanPorts {
		if vlanPort.VlanID <= 0 || vlanPort.PortName == "" {
			continue
		}

		vlanPortRecord := map[string]interface{}{
			"id":          uuid.New().String(),
			"asset_id":    assetID.String(),
			"vlan_id":     vlanPort.VlanID,
			"vlan_name":   vlanPort.VlanName,
			"port_name":   vlanPort.PortName,
			"port_type":   vlanPort.PortType,
			"port_status": vlanPort.PortStatus,
			"is_native":   vlanPort.IsNative,
			"created_at":  time.Now(),
			"updated_at":  time.Now(),
		}

		if err := tx.Table("switch_vlan_ports").Create(vlanPortRecord).Error; err != nil {
			logger.InfoContext(ctx, "[SwitchRepo] Warning: Could not store VLAN port %s: %v", vlanPort.PortName, err)
			continue
		}

		successCount++
	}

	logger.InfoContext(ctx, "[SwitchRepo] VLAN port storage completed: %d successful", successCount)
	return nil
}

// storeRoutingTableWithTx stores routing table entries within a transaction
func (r *SwitchRepository) storeRoutingTableWithTx(ctx context.Context, tx *gorm.DB, routingTable []scannerDomain.SwitchRoutingEntry, assetID uuid.UUID) error {
	// This is an optional table that might not exist in all setups
	successCount := 0

	for _, route := range routingTable {
		if route.Network == "" {
			continue
		}

		routeRecord := map[string]interface{}{
			"id":               uuid.New().String(),
			"asset_id":         assetID.String(),
			"network":          route.Network,
			"mask":             route.Mask,
			"next_hop":         route.NextHop,
			"interface":        route.Interface,
			"metric":           route.Metric,
			"admin_distance":   route.AdminDistance,
			"protocol":         route.Protocol,
			"age":              route.Age,
			"tag":              route.Tag,
			"vrf":              route.VRF,
			"route_preference": route.RoutePreference,
			"created_at":       time.Now(),
			"updated_at":       time.Now(),
		}

		if err := tx.Table("switch_routing_table").Create(routeRecord).Error; err != nil {
			logger.InfoContext(ctx, "[SwitchRepo] Warning: Could not store route %s: %v", route.Network, err)
			continue
		}

		successCount++
	}

	logger.InfoContext(ctx, "[SwitchRepo] Routing table storage completed: %d successful", successCount)
	return nil
}

// createSwitchAssetWithTx creates a switch asset within a transaction
func (r *SwitchRepository) createSwitchAssetWithTx(tx *gorm.DB, scannerID int64, config scannerDomain.SwitchConfig) (uuid.UUID, error) {
	assetID := uuid.New()

	// Create vendor service
	vendorService := NewVendorService(tx)
	vendorID, err := vendorService.GetOrCreateVendor(config.Brand)
	if err != nil {
		return uuid.Nil, fmt.Errorf("failed to get or create vendor: %w", err)
	}

	// Create asset
	asset := types.Assets{
		ID:          assetID.String(),
		VendorID:    vendorID,
		Name:        config.Name,
		Hostname:    r.generateHostname(config.IP),
		Description: fmt.Sprintf("%s switch for scanner: %s", config.Brand, config.Name),
		OSName:      fmt.Sprintf("%s IOS", config.Brand),
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	if err := tx.Table("assets").Create(&asset).Error; err != nil {
		return uuid.Nil, fmt.Errorf("failed to create asset: %w", err)
	}

	// Create asset IP
	assetIP := types.IPs{
		ID:         uuid.New().String(),
		AssetID:    assetID.String(),
		IPAddress:  config.IP,
		MacAddress: "",
		CreatedAt:  time.Now(),
	}

	if err := tx.Table("ips").Create(&assetIP).Error; err != nil {
		return uuid.Nil, fmt.Errorf("failed to create asset IP: %w", err)
	}

	// Create switch metadata
	switchMetadata := &types.SwitchMetadata{
		ID:        uuid.New().String(),
		ScannerID: scannerID,
		AssetID:   assetID.String(),
		Username:  config.Username,
		Password:  config.Password,
		Port:      config.Port,
		Brand:     config.Brand,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if err := tx.Table("switch_metadata").Create(switchMetadata).Error; err != nil {
		return uuid.Nil, fmt.Errorf("failed to create switch metadata: %w", err)
	}

	return assetID, nil
}

// updateAssetIPs updates asset IP addresses and MAC addresses
func (r *SwitchRepository) updateAssetIPs(ctx context.Context, assetID uuid.UUID, result *scannerDomain.SwitchScanResult) error {
	// Check if management IP already exists
	var count int64
	r.db.WithContext(ctx).Table("ips").
		Where("asset_id = ? AND ip_address = ?", assetID.String(), result.DeviceIP).
		Count(&count)

	if count == 0 {
		// Create management IP entry
		managementIP := types.IPs{
			ID:         uuid.New().String(),
			AssetID:    assetID.String(),
			IPAddress:  result.DeviceIP,
			MacAddress: result.SystemInfo.EthernetMAC,
			CreatedAt:  time.Now(),
		}

		if err := r.db.WithContext(ctx).Table("ips").Create(&managementIP).Error; err != nil {
			return fmt.Errorf("failed to create management IP: %w", err)
		}
	} else {
		// Update existing management IP with MAC if available
		if result.SystemInfo.EthernetMAC != "" {
			updates := map[string]interface{}{
				"mac_address": result.SystemInfo.EthernetMAC,
				"updated_at":  time.Now(),
			}

			r.db.WithContext(ctx).Table("ips").
				Where("asset_id = ? AND ip_address = ?", assetID.String(), result.DeviceIP).
				Updates(updates)
		}
	}

	return nil
}

// getSwitchInterfacesByAssetID retrieves interfaces for an asset
func (r *SwitchRepository) getSwitchInterfacesByAssetID(ctx context.Context, assetID uuid.UUID) ([]types.Interfaces, error) {
	var interfaces []types.Interfaces
	err := r.db.WithContext(ctx).Table("interfaces").
		Where("asset_id = ? AND deleted_at IS NULL", assetID.String()).
		Order("interface_name ASC").
		Find(&interfaces).Error
	return interfaces, err
}

// getSwitchVLANsByAssetID retrieves VLANs for an asset
func (r *SwitchRepository) getSwitchVLANsByAssetID(ctx context.Context, assetID uuid.UUID) ([]types.VLANs, error) {
	var vlans []types.VLANs
	err := r.db.WithContext(ctx).Table("vlans").
		Where("asset_id = ? AND deleted_at IS NULL", assetID.String()).
		Order("vlan_number ASC").
		Find(&vlans).Error
	return vlans, err
}

// getSwitchNeighborsByAssetID retrieves neighbors for an asset
func (r *SwitchRepository) getSwitchNeighborsByAssetID(ctx context.Context, assetID uuid.UUID) ([]types.SwitchNeighbor, error) {
	var neighbors []types.SwitchNeighbor
	err := r.db.WithContext(ctx).Table("switch_neighbors").
		Where("switch_id = ?", assetID.String()).
		Order("local_port ASC").
		Find(&neighbors).Error
	return neighbors, err
}

// ensureInterfaceTypesExist ensures basic interface types exist
func (r *SwitchRepository) ensureInterfaceTypesExist(ctx context.Context, tx *gorm.DB) error {
	defaultTypes := []types.InterfaceTypes{
		{TypeName: "physical", Description: "Physical network interface"},
		{TypeName: "vlan", Description: "VLAN interface"},
		{TypeName: "loopback", Description: "Loopback interface"},
		{TypeName: "tunnel", Description: "Tunnel interface"},
		{TypeName: "port-channel", Description: "Port channel interface"},
		{TypeName: "virtual", Description: "Virtual interface"},
	}

	for _, interfaceType := range defaultTypes {
		var existingType types.InterfaceTypes
		err := tx.Where("type_name = ?", interfaceType.TypeName).First(&existingType).Error

		if err == gorm.ErrRecordNotFound {
			if err := tx.Create(&interfaceType).Error; err != nil {
				logger.InfoContext(ctx, "[SwitchRepo] Error creating interface type %s: %v", interfaceType.TypeName, err)
				continue
			}
		}
	}

	return nil
}

// getInterfaceTypeIDWithFallback gets interface type ID with fallback
func (r *SwitchRepository) getInterfaceTypeIDWithFallback(ctx context.Context, tx *gorm.DB, interfaceName string) uint {
	typeName := r.determineInterfaceType(interfaceName)

	var interfaceType types.InterfaceTypes
	err := tx.Where("type_name = ?", typeName).First(&interfaceType).Error
	if err == nil {
		return interfaceType.ID
	}

	// Fallback to physical
	err = tx.Where("type_name = ?", "physical").First(&interfaceType).Error
	if err == nil {
		return interfaceType.ID
	}

	// Ultimate fallback
	return 1
}

// createInterfaceIP creates an IP record for an interface
func (r *SwitchRepository) createInterfaceIP(ctx context.Context, tx *gorm.DB, interfaceID, assetID, ipAddress, macAddress string) error {
	// Check if IP already exists for this asset
	var count int64
	tx.Table("ips").
		Where("asset_id = ? AND ip_address = ?", assetID, ipAddress).
		Count(&count)

	if count == 0 {
		interfaceIP := types.IPs{
			ID:          uuid.New().String(),
			AssetID:     assetID,
			InterfaceID: &interfaceID,
			IPAddress:   ipAddress,
			MacAddress:  r.cleanMacAddress(macAddress),
			CreatedAt:   time.Now(),
		}

		return tx.Table("ips").Create(&interfaceIP).Error
	}

	return nil
}

// convertInterfacesToDomain converts storage interfaces to domain interfaces
func (r *SwitchRepository) convertInterfacesToDomain(storageInterfaces []types.Interfaces) []scannerDomain.SwitchInterface {
	var domainInterfaces []scannerDomain.SwitchInterface
	for _, iface := range storageInterfaces {
		domainInterface := scannerDomain.SwitchInterface{
			Name:        iface.InterfaceName,
			Description: iface.Description,
			Status:      iface.OperationalStatus,
			Protocol:    iface.AdminStatus,
			MacAddress:  iface.MacAddress,
			Type:        r.getInterfaceTypeFromID(iface.InterfaceTypeID),
		}

		// Add VLAN information if available
		if iface.VLANId != nil {
			domainInterface.VLANs = []string{strconv.Itoa(*iface.VLANId)}
		}

		domainInterfaces = append(domainInterfaces, domainInterface)
	}
	return domainInterfaces
}

// convertVLANsToDomain converts storage VLANs to domain VLANs
func (r *SwitchRepository) convertVLANsToDomain(storageVLANs []types.VLANs) []scannerDomain.SwitchVLAN {
	var domainVLANs []scannerDomain.SwitchVLAN
	for _, vlan := range storageVLANs {
		domainVLAN := scannerDomain.SwitchVLAN{
			ID:          vlan.VLANNumber,
			Name:        vlan.VLANName,
			Description: vlan.Description,
			Status:      "active", // Default status
			Type:        vlan.DeviceType,
		}
		domainVLANs = append(domainVLANs, domainVLAN)
	}
	return domainVLANs
}

// convertNeighborsToDomain converts storage neighbors to domain neighbors
func (r *SwitchRepository) convertNeighborsToDomain(storageNeighbors []types.SwitchNeighbor) []scannerDomain.SwitchNeighbor {
	var domainNeighbors []scannerDomain.SwitchNeighbor
	for _, neighbor := range storageNeighbors {
		domainNeighbor := scannerDomain.SwitchNeighbor{
			DeviceID:  neighbor.DeviceID,
			LocalPort: neighbor.LocalPort,
			Protocol:  neighbor.Protocol,
		}

		if neighbor.RemotePort != nil {
			domainNeighbor.RemotePort = *neighbor.RemotePort
		}
		if neighbor.Platform != nil {
			domainNeighbor.Platform = *neighbor.Platform
		}
		if neighbor.IPAddress != nil {
			domainNeighbor.IPAddress = *neighbor.IPAddress
		}
		if neighbor.Software != nil {
			domainNeighbor.Software = *neighbor.Software
		}
		if neighbor.Duplex != nil {
			domainNeighbor.Duplex = *neighbor.Duplex
		}
		if neighbor.Capabilities != nil {
			capabilityStr := strings.TrimSpace(*neighbor.Capabilities)
			if capabilityStr != "" {
				domainNeighbor.Capabilities = strings.Split(capabilityStr, ",")
			}
		}

		domainNeighbors = append(domainNeighbors, domainNeighbor)
	}
	return domainNeighbors
}

// validateSwitchConfig validates switch configuration
func (r *SwitchRepository) validateSwitchConfig(config scannerDomain.SwitchConfig) error {
	if config.Name == "" {
		return fmt.Errorf("switch name is required")
	}
	if config.IP == "" {
		return fmt.Errorf("IP address is required")
	}
	if config.Username == "" {
		return fmt.Errorf("username is required")
	}
	if config.Password == "" {
		return fmt.Errorf("password is required")
	}
	if config.Brand == "" {
		return fmt.Errorf("brand is required")
	}
	if config.Port <= 0 || config.Port > 65535 {
		return fmt.Errorf("invalid port number: %d", config.Port)
	}
	if !r.isValidIP(config.IP) {
		return fmt.Errorf("invalid IP address: %s", config.IP)
	}
	return nil
}

// determineInterfaceType determines interface type from name
func (r *SwitchRepository) determineInterfaceType(interfaceName string) string {
	name := strings.ToLower(strings.TrimSpace(interfaceName))
	switch {
	case strings.Contains(name, "vlan"):
		return "vlan"
	case strings.Contains(name, "loopback"), strings.Contains(name, "lo"):
		return "loopback"
	case strings.Contains(name, "tunnel"), strings.Contains(name, "tu"):
		return "tunnel"
	case strings.Contains(name, "port-channel"), strings.Contains(name, "po"):
		return "port-channel"
	case strings.Contains(name, "mgmt"), strings.Contains(name, "management"):
		return "virtual"
	default:
		return "physical"
	}
}

// getInterfaceTypeFromID gets interface type name from type ID (for reverse lookup)
func (r *SwitchRepository) getInterfaceTypeFromID(typeID uint) string {
	// This would need a cache or lookup table in a real implementation
	// For now, return default based on common type IDs
	switch typeID {
	case 1:
		return "physical"
	case 2:
		return "vlan"
	case 3:
		return "loopback"
	case 4:
		return "tunnel"
	case 5:
		return "port-channel"
	case 6:
		return "virtual"
	default:
		return "physical"
	}
}

// String manipulation utilities
func (r *SwitchRepository) parseVLANID(vlanStr string) int {
	if vlanStr == "" {
		return 0
	}

	// Try direct integer conversion first
	if vlanID, err := strconv.Atoi(strings.TrimSpace(vlanStr)); err == nil {
		return vlanID
	}

	// Try extracting from "VLAN123" format
	var vlanID int
	if _, err := fmt.Sscanf(strings.TrimSpace(vlanStr), "VLAN%d", &vlanID); err == nil {
		return vlanID
	}

	// Try extracting from "vlan123" format
	if _, err := fmt.Sscanf(strings.ToLower(strings.TrimSpace(vlanStr)), "vlan%d", &vlanID); err == nil {
		return vlanID
	}

	return 0
}

func (r *SwitchRepository) normalizeStatus(status string) string {
	status = strings.ToLower(strings.TrimSpace(status))
	switch status {
	case "up", "active", "enabled", "connected", "1":
		return "up"
	case "down", "inactive", "disabled", "administratively down", "notconnect", "0":
		return "down"
	case "testing", "dormant":
		return "testing"
	default:
		if status == "" {
			return "unknown"
		}
		return status
	}
}

func (r *SwitchRepository) truncateString(s string, maxLen int) string {
	s = strings.TrimSpace(s)
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}

func (r *SwitchRepository) cleanMacAddress(mac string) string {
	if mac == "" {
		return ""
	}

	// Remove common separators and convert to lowercase
	cleaned := strings.ReplaceAll(mac, ":", "")
	cleaned = strings.ReplaceAll(cleaned, "-", "")
	cleaned = strings.ReplaceAll(cleaned, ".", "")
	cleaned = strings.ReplaceAll(cleaned, " ", "")
	cleaned = strings.ToLower(cleaned)

	// Validate length (should be 12 hex characters)
	if len(cleaned) != 12 {
		return ""
	}

	// Validate hex characters
	for _, c := range cleaned {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return ""
		}
	}

	// Format as standard MAC address (xx:xx:xx:xx:xx:xx)
	result := ""
	for i := 0; i < 12; i += 2 {
		if i > 0 {
			result += ":"
		}
		result += cleaned[i : i+2]
	}

	return result
}

func (r *SwitchRepository) isValidIP(ip string) bool {
	if ip == "" || ip == "unassigned" || ip == "0.0.0.0" {
		return false
	}

	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return false
	}

	for _, part := range parts {
		if num, err := strconv.Atoi(part); err != nil || num < 0 || num > 255 {
			return false
		}
	}

	return true
}

func (r *SwitchRepository) generateHostname(ip string) string {
	return fmt.Sprintf("switch-%s", strings.ReplaceAll(ip, ".", "-"))
}

func (r *SwitchRepository) getProtocolOrDefault(protocol string) string {
	protocol = strings.TrimSpace(protocol)
	if protocol == "" {
		return "CDP"
	}
	return r.truncateString(protocol, 20)
}

// Pointer utility methods
func (r *SwitchRepository) stringPtr(s string) *string {
	return &s
}

func (r *SwitchRepository) stringPtrOrNil(s string) *string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	trimmed := strings.TrimSpace(s)
	return &trimmed
}

// createVendorConfig creates vendor-specific configuration JSON for interfaces
func (r *SwitchRepository) createVendorConfig(iface scannerDomain.SwitchInterface) string {
	// Create a simple JSON-like string instead of using JSON marshaling
	config := fmt.Sprintf(`{"speed":"%s","duplex":"%s","mtu":%d,"mode":"%s","type":"%s"}`,
		iface.Speed, iface.Duplex, iface.MTU, iface.Mode, iface.Type)

	if len(config) > 1000 {
		return "{}"
	}
	return config
}

// createVLANVendorConfig creates vendor-specific configuration JSON for VLANs
func (r *SwitchRepository) createVLANVendorConfig(vlan scannerDomain.SwitchVLAN) string {
	// Create a simple JSON-like string instead of using JSON marshaling
	config := fmt.Sprintf(`{"status":"%s","type":"%s","parent":%d}`,
		vlan.Status, vlan.Type, vlan.Parent)

	if len(config) > 1000 {
		return "{}"
	}
	return config
}

func (r *SwitchRepository) GetSwitchByAssetID(ctx context.Context, assetID uuid.UUID) (*domain.SwitchInfo, error) {
	logger.InfoContext(ctx, "[SwitchRepo] Getting switch info by asset ID: %s", assetID.String())

	// Query to get switch information from assets and related metadata
	var result struct {
		ID              string     `json:"id"`
		Name            string     `json:"name"`
		Hostname        string     `json:"hostname"`
		IPAddress       string     `json:"ip_address"`
		Brand           string     `json:"brand"`
		Model           string     `json:"model"`
		SoftwareVersion string     `json:"software_version"`
		SerialNumber    string     `json:"serial_number"`
		SystemUptime    string     `json:"system_uptime"`
		ManagementIP    string     `json:"management_ip"`
		EthernetMAC     string     `json:"ethernet_mac"`
		Status          string     `json:"status"`
		LastScanTime    *time.Time `json:"last_scan_time"`
		LastScanStatus  string     `json:"last_scan_status"`
		CreatedAt       time.Time  `json:"created_at"`
		UpdatedAt       time.Time  `json:"updated_at"`
		ScannerID       int64      `json:"scanner_id"`
	}

	err := r.db.WithContext(ctx).Table("assets").
		Select(`
			assets.id,
			assets.name,
			assets.hostname,
			COALESCE(ips.ip_address, '') as ip_address,
			COALESCE(vendors.vendor_name, '') as brand,
			COALESCE(assets.os_name, '') as model,
			COALESCE(assets.os_version, '') as software_version,
			'' as serial_number,
			'' as system_uptime,
			COALESCE(ips.ip_address, '') as management_ip,
			COALESCE(ips.mac_address, '') as ethernet_mac,
			'online' as status,
			assets.updated_at as last_scan_time,
			'success' as last_scan_status,
			assets.created_at,
			assets.updated_at,
			COALESCE(switch_metadata.scanner_id, 0) as scanner_id
		`).
		Joins("LEFT JOIN ips ON assets.id = ips.asset_id").
		Joins("LEFT JOIN vendors ON assets.vendor_id = vendors.id").
		Joins("LEFT JOIN switch_metadata ON assets.id = switch_metadata.asset_id").
		Where("assets.id = ? AND assets.deleted_at IS NULL", assetID.String()).
		First(&result).Error

	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get switch by asset ID: %w", err)
	}

	// Get counts for interfaces, VLANs, and neighbors
	var interfaceCount, vlanCount, neighborCount int64

	r.db.WithContext(ctx).Table("interfaces").
		Where("asset_id = ? AND deleted_at IS NULL", assetID.String()).
		Count(&interfaceCount)

	r.db.WithContext(ctx).Table("vlans").
		Where("asset_id = ? AND deleted_at IS NULL", assetID.String()).
		Count(&vlanCount)

	r.db.WithContext(ctx).Table("switch_neighbors").
		Where("switch_id = ?", assetID.String()).
		Count(&neighborCount)

	switchInfo := &domain.SwitchInfo{
		ID:                result.ID,
		ScannerID:         result.ScannerID,
		Name:              result.Name,
		Hostname:          result.Hostname,
		IPAddress:         result.IPAddress,
		Brand:             result.Brand,
		Model:             result.Model,
		SoftwareVersion:   result.SoftwareVersion,
		SerialNumber:      result.SerialNumber,
		SystemUptime:      result.SystemUptime,
		ManagementIP:      result.ManagementIP,
		EthernetMAC:       result.EthernetMAC,
		NumberOfPorts:     int(interfaceCount),
		NumberOfVLANs:     int(vlanCount),
		NumberOfNeighbors: int(neighborCount),
		Status:            result.Status,
		LastScanTime:      result.LastScanTime,
		LastScanStatus:    result.LastScanStatus,
		CreatedAt:         result.CreatedAt,
		UpdatedAt:         result.UpdatedAt,
	}

	logger.InfoContext(ctx, "[SwitchRepo] Successfully retrieved switch info for asset %s", assetID.String())
	return switchInfo, nil
}

// GetSwitchByScannerID retrieves switch info by scanner ID (implements Repository interface)
func (r *SwitchRepository) GetSwitchByScannerID(ctx context.Context, scannerID int64) (*domain.SwitchInfo, error) {
	logger.InfoContext(ctx, "[SwitchRepo] Getting switch info by scanner ID: %d", scannerID)

	// First get the asset ID from switch metadata
	var metadata types.SwitchMetadata
	err := r.db.WithContext(ctx).Table("switch_metadata").
		Where("scanner_id = ?", scannerID).
		First(&metadata).Error

	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get switch metadata for scanner %d: %w", scannerID, err)
	}

	// Parse asset ID and get full switch info
	assetID, err := uuid.Parse(metadata.AssetID)
	if err != nil {
		return nil, fmt.Errorf("invalid asset ID in metadata: %w", err)
	}

	return r.GetSwitchByAssetID(ctx, assetID)
}

// ListSwitches retrieves switches with filtering and pagination (implements Repository interface)
func (r *SwitchRepository) ListSwitches(ctx context.Context, filter domain.SwitchFilter, limit, offset int, sortField, sortOrder string) ([]domain.SwitchInfo, int, error) {
	logger.InfoContext(ctx, "[SwitchRepo] Listing switches with filter: %+v", filter)

	// Build base query
	query := r.db.WithContext(ctx).Table("assets").
		Select(`
			assets.id,
			assets.name,
			assets.hostname,
			COALESCE(ips.ip_address, '') as ip_address,
			COALESCE(vendors.vendor_name, '') as brand,
			COALESCE(assets.os_name, '') as model,
			COALESCE(assets.os_version, '') as software_version,
			'' as serial_number,
			'' as system_uptime,
			COALESCE(ips.ip_address, '') as management_ip,
			COALESCE(ips.mac_address, '') as ethernet_mac,
			'online' as status,
			assets.updated_at as last_scan_time,
			'success' as last_scan_status,
			assets.created_at,
			assets.updated_at,
			COALESCE(switch_metadata.scanner_id, 0) as scanner_id
		`).
		Joins("LEFT JOIN ips ON assets.id = ips.asset_id").
		Joins("LEFT JOIN vendors ON assets.vendor_id = vendors.id").
		Joins("INNER JOIN switch_metadata ON assets.id = switch_metadata.asset_id").
		Where("assets.deleted_at IS NULL")

	// Apply filters
	if filter.Name != "" {
		query = query.Where("assets.name LIKE ?", "%"+filter.Name+"%")
	}
	if filter.Brand != "" {
		query = query.Where("vendors.vendor_name LIKE ?", "%"+filter.Brand+"%")
	}
	if filter.IPAddress != "" {
		query = query.Where("ips.ip_address LIKE ?", "%"+filter.IPAddress+"%")
	}
	if filter.ScannerID != nil {
		query = query.Where("switch_metadata.scanner_id = ?", *filter.ScannerID)
	}

	// Get total count
	var totalCount int64
	countQuery := query
	if err := countQuery.Count(&totalCount).Error; err != nil {
		return nil, 0, fmt.Errorf("failed to count switches: %w", err)
	}

	// Apply sorting
	orderClause := r.buildOrderClause(sortField, sortOrder)
	query = query.Order(orderClause)

	// Apply pagination
	if limit > 0 {
		query = query.Limit(limit)
	}
	if offset > 0 {
		query = query.Offset(offset)
	}

	// Execute query
	var results []struct {
		ID              string     `json:"id"`
		Name            string     `json:"name"`
		Hostname        string     `json:"hostname"`
		IPAddress       string     `json:"ip_address"`
		Brand           string     `json:"brand"`
		Model           string     `json:"model"`
		SoftwareVersion string     `json:"software_version"`
		SerialNumber    string     `json:"serial_number"`
		SystemUptime    string     `json:"system_uptime"`
		ManagementIP    string     `json:"management_ip"`
		EthernetMAC     string     `json:"ethernet_mac"`
		Status          string     `json:"status"`
		LastScanTime    *time.Time `json:"last_scan_time"`
		LastScanStatus  string     `json:"last_scan_status"`
		CreatedAt       time.Time  `json:"created_at"`
		UpdatedAt       time.Time  `json:"updated_at"`
		ScannerID       int64      `json:"scanner_id"`
	}

	if err := query.Find(&results).Error; err != nil {
		return nil, 0, fmt.Errorf("failed to list switches: %w", err)
	}

	// Convert to domain objects
	switches := make([]domain.SwitchInfo, len(results))
	for i, result := range results {
		switches[i] = domain.SwitchInfo{
			ID:              result.ID,
			ScannerID:       result.ScannerID,
			Name:            result.Name,
			Hostname:        result.Hostname,
			IPAddress:       result.IPAddress,
			Brand:           result.Brand,
			Model:           result.Model,
			SoftwareVersion: result.SoftwareVersion,
			SerialNumber:    result.SerialNumber,
			SystemUptime:    result.SystemUptime,
			ManagementIP:    result.ManagementIP,
			EthernetMAC:     result.EthernetMAC,
			Status:          result.Status,
			LastScanTime:    result.LastScanTime,
			LastScanStatus:  result.LastScanStatus,
			CreatedAt:       result.CreatedAt,
			UpdatedAt:       result.UpdatedAt,
		}

		// Get counts for this switch
		var interfaceCount, vlanCount, neighborCount int64
		assetID := result.ID

		r.db.WithContext(ctx).Table("interfaces").
			Where("asset_id = ? AND deleted_at IS NULL", assetID).
			Count(&interfaceCount)

		r.db.WithContext(ctx).Table("vlans").
			Where("asset_id = ? AND deleted_at IS NULL", assetID).
			Count(&vlanCount)

		r.db.WithContext(ctx).Table("switch_neighbors").
			Where("switch_id = ?", assetID).
			Count(&neighborCount)

		switches[i].NumberOfPorts = int(interfaceCount)
		switches[i].NumberOfVLANs = int(vlanCount)
		switches[i].NumberOfNeighbors = int(neighborCount)
	}

	logger.InfoContext(ctx, "[SwitchRepo] Successfully listed %d switches (total: %d)", len(switches), totalCount)
	return switches, int(totalCount), nil
}

// GetSwitchStats retrieves aggregated switch statistics (implements Repository interface)
func (r *SwitchRepository) GetSwitchStats(ctx context.Context) (map[string]interface{}, error) {
	logger.InfoContext(ctx, "[SwitchRepo] Getting switch statistics")

	stats := make(map[string]interface{})

	// Total switches
	var totalSwitches int64
	r.db.WithContext(ctx).Table("assets").
		Joins("INNER JOIN switch_metadata ON assets.id = switch_metadata.asset_id").
		Where("assets.deleted_at IS NULL").
		Count(&totalSwitches)

	// Online switches (assuming all are online for now)
	onlineSwitches := totalSwitches

	// Total interfaces
	var totalInterfaces int64
	r.db.WithContext(ctx).Table("interfaces").
		Joins("INNER JOIN switch_metadata ON interfaces.asset_id = switch_metadata.asset_id").
		Where("interfaces.deleted_at IS NULL").
		Count(&totalInterfaces)

	// Total VLANs
	var totalVLANs int64
	r.db.WithContext(ctx).Table("vlans").
		Joins("INNER JOIN switch_metadata ON vlans.asset_id = switch_metadata.asset_id").
		Where("vlans.deleted_at IS NULL").
		Count(&totalVLANs)

	// Total neighbors
	var totalNeighbors int64
	r.db.WithContext(ctx).Table("switch_neighbors").Count(&totalNeighbors)

	// Brand distribution
	var brandStats []struct {
		Brand string `json:"brand"`
		Count int64  `json:"count"`
	}
	r.db.WithContext(ctx).Table("assets").
		Select("vendors.vendor_name as brand, COUNT(*) as count").
		Joins("INNER JOIN switch_metadata ON assets.id = switch_metadata.asset_id").
		Joins("LEFT JOIN vendors ON assets.vendor_id = vendors.id").
		Where("assets.deleted_at IS NULL").
		Group("vendors.vendor_name").
		Find(&brandStats)

	stats["total_switches"] = totalSwitches
	stats["online_switches"] = onlineSwitches
	stats["offline_switches"] = totalSwitches - onlineSwitches
	stats["total_interfaces"] = totalInterfaces
	stats["total_vlans"] = totalVLANs
	stats["total_neighbors"] = totalNeighbors
	stats["brand_distribution"] = brandStats

	logger.InfoContext(ctx, "[SwitchRepo] Successfully retrieved switch statistics")
	return stats, nil
}

// buildOrderClause builds the ORDER BY clause for queries
func (r *SwitchRepository) buildOrderClause(sortField, sortOrder string) string {
	// Map API field names to database columns
	fieldMap := map[string]string{
		"name":       "assets.name",
		"hostname":   "assets.hostname",
		"ip":         "ips.ip_address",
		"ip_address": "ips.ip_address",
		"brand":      "vendors.vendor_name",
		"model":      "assets.os_name",
		"created_at": "assets.created_at",
		"updated_at": "assets.updated_at",
	}

	dbField, exists := fieldMap[sortField]
	if !exists {
		dbField = "assets.name" // Default to name
	}

	if sortOrder != "asc" && sortOrder != "desc" {
		sortOrder = "asc" // Default to ascending
	}

	return fmt.Sprintf("%s %s", dbField, strings.ToUpper(sortOrder))
}
