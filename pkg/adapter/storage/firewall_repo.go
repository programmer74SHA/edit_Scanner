package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanner/domain"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/adapter/storage/types"

	"gorm.io/gorm"
)

type FirewallRepo struct {
	db *gorm.DB
}

const (
	DeviceTypeFirewall = "firewall"
)

// TODO: check later and find replacement
func (r *FirewallRepo) getDeviceType() string {
	return DeviceTypeFirewall
}

// NewFirewallRepo creates a new firewall repository
func NewFirewallRepo(db *gorm.DB) *FirewallRepo {
	return &FirewallRepo{db: db}
}

func (r *FirewallRepo) StoreFirewallData(ctx context.Context, data domain.FirewallData, scanJobID int64) error {
	// Call the new method with empty interface asset map for backward compatibility
	return r.StoreFirewallDataWithAssets(ctx, data, scanJobID, make(map[string]string))
}

func (r *FirewallRepo) storeZones(tx *gorm.DB, zones []domain.ZoneData, firewallDetailsID string) (map[string]string, error) {
	zoneMap := make(map[string]string)

	if len(zones) == 0 {
		log.Printf("WARNING: No zones to store")
		return zoneMap, nil
	}

	for i, zone := range zones {
		log.Printf("Processing zone %d: Name='%s', Description='%s', Interfaces=%d",
			i, zone.Name, zone.Description, len(zone.Interfaces))

		if zone.Name == "" {
			log.Printf("SKIP: Zone %d has empty name", i)
			continue
		}

		zoneID := uuid.New().String()
		zoneRecord := types.Zones{
			ID:              zoneID,
			ZoneName:        zone.Name,
			ZoneType:        "",
			VendorZoneType:  "",
			Description:     zone.Description,
			ZoneMode:        "",
			IntrazoneAction: "",
			FirewallID:      firewallDetailsID,
		}

		log.Printf("Creating zone record with ID: %s", zoneID)

		var existingZone types.Zones
		var finalZoneID string
		// Check if zone exists but is soft-deleted first
		if err := tx.Unscoped().Where("zone_name = ?", zone.Name).First(&existingZone).Error; err == nil {
			if existingZone.DeletedAt != nil {
				// Zone is soft-deleted, restore it
				log.Printf("Found soft-deleted zone '%s', restoring it", zone.Name)
				finalZoneID = existingZone.ID
				if err := tx.Unscoped().Model(&existingZone).Updates(map[string]interface{}{
					"zone_name":   zone.Name,
					"description": zone.Description,
					"firewall_id": firewallDetailsID,
					"updated_at":  time.Now(),
					"deleted_at":  nil,
				}).Error; err != nil {
					log.Printf("ERROR: Failed to restore zone '%s': %v", zone.Name, err)
					continue
				}
			} else {
				// Zone exists and is not deleted
				finalZoneID = existingZone.ID
				log.Printf("Found existing zone '%s' with ID: %s", zone.Name, finalZoneID)
			}
		} else if err == gorm.ErrRecordNotFound {
			// Zone doesn't exist, create new one
			err := tx.Create(&zoneRecord).Error
			if err != nil {
				log.Printf("ERROR: Failed to create zone '%s': %v", zone.Name, err)
				continue
			}
			finalZoneID = zoneID
			log.Printf("Created new zone '%s' with ID: %s", zone.Name, finalZoneID)
		} else {
			log.Printf("ERROR: Database error checking zone '%s': %v", zone.Name, err)
			continue
		}

		zoneMap[zone.Name] = finalZoneID
	}

	log.Printf("Zone storage complete: %d zones processed, %d stored", len(zones), len(zoneMap))
	return zoneMap, nil
}

// Enhanced VLAN storage with debugging
func (r *FirewallRepo) storeVLANs(tx *gorm.DB, vlans []domain.VLANData, interfaceMap map[string]string, assetID string) (map[int]string, error) {
	vlanIDMap := make(map[int]string)
	vlanCount := 0

	// Process explicit VLANs from data
	log.Printf("Processing %d explicit VLANs", len(vlans))
	for i, vlan := range vlans {
		log.Printf("Processing VLAN %d: ID=%d, Name='%s', Parent='%s'",
			i, vlan.VLANID, vlan.VLANName, vlan.ParentInterface)

		// Validate parent interface exists
		parentInterfaceID, exists := interfaceMap[vlan.ParentInterface]
		if !exists {
			log.Printf("ERROR: Parent interface '%s' not found for VLAN %d", vlan.ParentInterface, vlan.VLANID)
			continue
		}

		vendorConfig := map[string]interface{}{
			"vlan_type": "explicit",
			"parent":    vlan.ParentInterface,
			"vlan_id":   vlan.VLANID,
		}
		vendorConfigJSON, _ := json.Marshal(vendorConfig)

		vlanRecordID := uuid.New().String()
		vlanRecord := types.VLANs{
			ID:                   vlanRecordID,
			VLANNumber:           vlan.VLANID,
			VLANName:             vlan.VLANName,
			Description:          vlan.Description,
			IsNative:             false,
			VendorSpecificConfig: string(vendorConfigJSON),
			DeviceType:           r.getDeviceType(),
			AssetID:              assetID,
		}

		var existingVLAN types.VLANs
		var finalVLANID string
		// Check if VLAN exists but is soft-deleted first
		if err := tx.Unscoped().Where("asset_id = ? AND vlan_id = ? AND device_type = ?", assetID, vlan.VLANID, r.getDeviceType()).First(&existingVLAN).Error; err == nil {
			if existingVLAN.DeletedAt != nil {
				// VLAN is soft-deleted, restore it
				log.Printf("Found soft-deleted VLAN %d, restoring it", vlan.VLANID)
				finalVLANID = existingVLAN.ID
				if err := tx.Unscoped().Model(&existingVLAN).Updates(map[string]interface{}{
					"vlan_id":                vlan.VLANID,
					"vlan_name":              vlan.VLANName,
					"description":            vlan.Description,
					"is_native":              false,
					"vendor_specific_config": string(vendorConfigJSON),
					"device_type":            r.getDeviceType(),
					"asset_id":               assetID,
					"updated_at":             time.Now(),
					"deleted_at":             nil,
				}).Error; err != nil {
					log.Printf("ERROR: Failed to restore VLAN %d: %v", vlan.VLANID, err)
					continue
				}
			} else {
				// VLAN exists and is not deleted
				finalVLANID = existingVLAN.ID
				log.Printf("Found existing VLAN %d with table ID: %s", vlan.VLANID, finalVLANID)
			}
		} else if err == gorm.ErrRecordNotFound {
			// VLAN doesn't exist, create new one
			err := tx.Create(&vlanRecord).Error
			if err != nil {
				log.Printf("ERROR: Failed to create VLAN %d: %v", vlan.VLANID, err)
				continue
			}
			finalVLANID = vlanRecordID
			log.Printf("Created new VLAN %d with table ID: %s", vlan.VLANID, finalVLANID)
		} else {
			log.Printf("ERROR: Database error checking VLAN %d: %v", vlan.VLANID, err)
			continue
		}

		// Create VLANInterface relationship with parent interface
		isNative := false
		vlanInterface := types.VLANInterface{
			VLANTableID: finalVLANID,
			InterfaceID: parentInterfaceID,
			IsNative:    &isNative,
		}
		if err := tx.FirstOrCreate(&vlanInterface, types.VLANInterface{
			VLANTableID: finalVLANID,
			InterfaceID: parentInterfaceID,
		}).Error; err != nil {
			log.Printf("ERROR: Failed to create VLAN-Interface relationship: %v", err)
			continue
		}
		log.Printf("Created VLAN-Interface relationship: VLAN %d -> Interface %s", vlan.VLANID, vlan.ParentInterface)

		vlanIDMap[vlan.VLANID] = finalVLANID
		vlanCount++
	}

	// Process VLAN sub-interfaces
	log.Printf("Processing VLAN sub-interfaces from interface map")
	for interfaceName := range interfaceMap {
		if strings.Contains(interfaceName, ".") {
			parts := strings.Split(interfaceName, ".")
			if len(parts) == 2 {
				parentName := parts[0]
				vlanIDStr := parts[1]

				vlanID, err := strconv.Atoi(vlanIDStr)
				if err != nil {
					log.Printf("ERROR: Invalid VLAN ID in interface name %s: %v", interfaceName, err)
					continue
				}

				// Validate parent interface exists
				parentID, exists := interfaceMap[parentName]
				if !exists {
					log.Printf("ERROR: Parent interface %s not found for %s", parentName, interfaceName)
					continue
				}

				// Check if VLAN already exists
				if _, exists := vlanIDMap[vlanID]; exists {
					log.Printf("SKIP: VLAN %d already exists", vlanID)
					continue
				}

				log.Printf("Creating VLAN %d from sub-interface %s", vlanID, interfaceName)

				vendorConfig := map[string]interface{}{
					"vlan_type": "sub_interface",
					"parent":    parentName,
					"vlan_id":   vlanID,
				}
				vendorConfigJSON, _ := json.Marshal(vendorConfig)

				vlanRecordID := uuid.New().String()
				vlan := types.VLANs{
					ID:                   vlanRecordID,
					VLANNumber:           vlanID,
					VLANName:             fmt.Sprintf("VLAN_%d", vlanID),
					Description:          fmt.Sprintf("VLAN %d on %s", vlanID, parentName),
					IsNative:             false,
					VendorSpecificConfig: string(vendorConfigJSON),
					DeviceType:           r.getDeviceType(),
					AssetID:              assetID,
				}

				var existingVLAN types.VLANs
				var finalVLANID string
				// Check if VLAN exists but is soft-deleted first
				if err := tx.Unscoped().Where("asset_id = ? AND vlan_id = ? AND device_type = ?", assetID, vlanID, r.getDeviceType()).First(&existingVLAN).Error; err == nil {
					if existingVLAN.DeletedAt != nil {
						// VLAN is soft-deleted, restore it
						log.Printf("Found soft-deleted VLAN %d, restoring it", vlanID)
						finalVLANID = existingVLAN.ID
						if err := tx.Unscoped().Model(&existingVLAN).Updates(map[string]interface{}{
							"vlan_id":                vlanID,
							"vlan_name":              fmt.Sprintf("VLAN_%d", vlanID),
							"description":            fmt.Sprintf("VLAN %d on %s", vlanID, parentName),
							"is_native":              false,
							"vendor_specific_config": string(vendorConfigJSON),
							"device_type":            r.getDeviceType(),
							"asset_id":               assetID,
							"updated_at":             time.Now(),
							"deleted_at":             nil,
						}).Error; err != nil {
							log.Printf("ERROR: Failed to restore VLAN %d: %v", vlanID, err)
							continue
						}
					} else {
						// VLAN exists and is not deleted
						finalVLANID = existingVLAN.ID
						log.Printf("Found existing VLAN %d with table ID: %s", vlanID, finalVLANID)
					}
				} else if err == gorm.ErrRecordNotFound {
					// VLAN doesn't exist, create new one
					err = tx.Create(&vlan).Error
					if err != nil {
						log.Printf("ERROR: Failed to create VLAN %d for interface %s: %v", vlanID, interfaceName, err)
						continue
					}
					finalVLANID = vlanRecordID
					log.Printf("Created new VLAN %d with table ID: %s", vlanID, finalVLANID)
				} else {
					log.Printf("ERROR: Database error checking VLAN %d: %v", vlanID, err)
					continue
				}

				// Create VLANInterface relationship
				isNative := false
				vlanInterface := types.VLANInterface{
					VLANTableID: finalVLANID,
					InterfaceID: parentID,
					IsNative:    &isNative,
				}
				if err := tx.FirstOrCreate(&vlanInterface, types.VLANInterface{
					VLANTableID: finalVLANID,
					InterfaceID: parentID,
				}).Error; err != nil {
					log.Printf("ERROR: Failed to create VLAN-Interface relationship: %v", err)
					continue
				}

				vlanIDMap[vlanID] = finalVLANID
				vlanCount++
				log.Printf("Created VLAN %d from interface %s with table ID: %s", vlanID, interfaceName, finalVLANID)
			}
		}
	}

	log.Printf("VLAN storage complete: %d VLANs stored", vlanCount)
	return vlanIDMap, nil
}

// Enhanced firewall details creation with debugging
func (r *FirewallRepo) ensureFirewallDetails(tx *gorm.DB, assetID string) error {
	log.Printf("Checking firewall details for asset: %s", assetID)

	var count int64
	if err := tx.Model(&types.FirewallDetails{}).Where("asset_id = ?", assetID).Count(&count).Error; err != nil {
		log.Printf("ERROR: Failed to count firewall details: %v", err)
		return err
	}

	log.Printf("Found %d existing firewall details records for asset %s", count, assetID)

	if count == 0 {
		log.Printf("Creating new firewall details record")

		// Get Fortinet vendor ID
		var vendor types.Vendors
		if err := tx.Where("vendor_code = ?", "FORTI").First(&vendor).Error; err != nil {
			log.Printf("ERROR: Failed to get Fortinet vendor: %v", err)

			// Create vendor if it doesn't exist
			log.Printf("Creating Fortinet vendor record")
			vendor = types.Vendors{
				VendorName: "Fortinet",
				VendorCode: "FORTI",
			}
			if err := tx.Create(&vendor).Error; err != nil {
				log.Printf("ERROR: Failed to create Fortinet vendor: %v", err)
				return fmt.Errorf("failed to create Fortinet vendor: %v", err)
			}
			log.Printf("Created Fortinet vendor with ID: %d", vendor.ID)
		} else {
			log.Printf("Found Fortinet vendor with ID: %d", vendor.ID)
		}

		// Create firewall details
		firewallDetailsID := uuid.New().String()
		firewallDetails := types.FirewallDetails{
			ID:              firewallDetailsID,
			AssetID:         assetID,
			Model:           "FortiGate",
			FirmwareVersion: "",
			SerialNumber:    "",
			IsHAEnabled:     false,
			HARole:          "standalone",
			ManagementIP:    "0.0.0.0",
			SiteName:        "",
			Location:        "",
			Status:          "",
			SyncStatus:      "",
		}

		if err := tx.Create(&firewallDetails).Error; err != nil {
			log.Printf("ERROR: Failed to create firewall details: %v", err)
			return err
		}

		log.Printf("Created firewall details with ID: %s", firewallDetailsID)
	} else {
		log.Printf("Using existing firewall details record")
	}

	return nil
}

// Add debugging to zone details storage
func (r *FirewallRepo) storeZoneDetails(tx *gorm.DB, interfaces []domain.InterfaceData, zoneMap map[string]string, interfaceMap map[string]string, vlanIDMap map[int]string, assetID string) error {
	relationshipCount := 0

	log.Printf("Available zones: %d", len(zoneMap))
	for zoneName := range zoneMap {
		log.Printf("- Zone: %s", zoneName)
	}

	log.Printf("Available interfaces: %d", len(interfaceMap))
	for intfName := range interfaceMap {
		log.Printf("- Interface: %s", intfName)
	}

	log.Printf("Available VLANs: %d", len(vlanIDMap))
	for vlanID := range vlanIDMap {
		log.Printf("- VLAN: %d", vlanID)
	}

	// Create a zone interface mapping from original zone data
	zoneInterfaceMap := make(map[string]string)
	for _, intf := range interfaces {
		if intf.Zone != "" {
			zoneInterfaceMap[intf.Name] = intf.Zone
			log.Printf("Interface-Zone mapping: %s -> %s", intf.Name, intf.Zone)
		}
	}

	log.Printf("Processing %d interfaces for zone relationships", len(interfaceMap))

	for interfaceName, interfaceID := range interfaceMap {
		log.Printf("Processing interface: %s (ID: %s)", interfaceName, interfaceID)

		zoneName, hasZone := zoneInterfaceMap[interfaceName]
		if !hasZone {
			log.Printf("SKIP: No zone mapping for interface %s", interfaceName)
			continue
		}

		zoneID, exists := zoneMap[zoneName]
		if !exists {
			log.Printf("ERROR: Zone %s not found in zoneMap", zoneName)
			continue
		}

		var vlanTableID string
		var vlanNumber int

		if strings.Contains(interfaceName, ".") {
			// VLAN sub-interface
			parts := strings.Split(interfaceName, ".")
			if len(parts) == 2 {
				var err error
				vlanNumber, err = strconv.Atoi(parts[1])
				if err != nil {
					log.Printf("ERROR: Invalid VLAN number in interface %s: %v", interfaceName, err)
					continue
				}

				var exists bool
				vlanTableID, exists = vlanIDMap[vlanNumber]
				if !exists {
					log.Printf("ERROR: VLAN table ID not found for VLAN %d (interface %s)", vlanNumber, interfaceName)
					continue
				}
			}
		} else {
			// Physical interface - use default VLAN (1)
			vlanNumber = 1
			var exists bool
			vlanTableID, exists = vlanIDMap[1]
			if !exists {
				log.Printf("WARNING: Default VLAN not found for physical interface %s, creating one", interfaceName)
				// Create default VLAN for this interface
				defaultVLANID := uuid.New().String()
				defaultVLAN := types.VLANs{
					ID:                   defaultVLANID,
					VLANNumber:           1,
					VLANName:             fmt.Sprintf("Default_VLAN_%s", interfaceName),
					Description:          fmt.Sprintf("Default VLAN for interface %s", interfaceName),
					IsNative:             true,
					VendorSpecificConfig: `{"vlan_type":"default","is_native":true}`,
					DeviceType:           r.getDeviceType(),
					AssetID:              assetID,
				}

				if err := tx.Table("vlans").Create(&defaultVLAN).Error; err != nil {
					log.Printf("ERROR: Failed to create default VLAN: %v", err)
					continue
				}

				// Create VLANInterface relationship for default VLAN
				isNative := true
				vlanInterface := types.VLANInterface{
					VLANTableID: defaultVLANID,
					InterfaceID: interfaceID,
					IsNative:    &isNative,
				}
				if err := tx.Create(&vlanInterface).Error; err != nil {
					log.Printf("ERROR: Failed to create default VLAN-Interface relationship: %v", err)
					continue
				}

				vlanTableID = defaultVLANID
				vlanIDMap[1] = defaultVLANID
				log.Printf("Created default VLAN with ID: %s", defaultVLANID)
			}
		}

		log.Printf("Creating zone detail: Zone %s (ID: %s) -> Interface %s (ID: %s) -> VLAN %d (Table ID: %s)",
			zoneName, zoneID, interfaceName, interfaceID, vlanNumber, vlanTableID)

		zoneDetailID := uuid.New().String()
		zoneDetail := types.ZoneDetails{
			ID:                  zoneDetailID,
			ZoneID:              zoneID,
			FirewallInterfaceID: interfaceID, // Updated field name
			VLANTableID:         vlanTableID,
		}

		err := tx.FirstOrCreate(&zoneDetail, types.ZoneDetails{
			ZoneID:              zoneID,
			FirewallInterfaceID: interfaceID, // Updated field name
			VLANTableID:         vlanTableID,
		}).Error

		if err != nil {
			log.Printf("ERROR: Failed to create zone detail for interface %s: %v", interfaceName, err)
			continue
		}

		relationshipCount++
		log.Printf("✓ Successfully created zone-interface-VLAN relationship")
	}

	log.Printf("Zone details storage complete: %d relationships created", relationshipCount)
	return nil
}

// Enhanced policy storage with debugging
func (r *FirewallRepo) storePolicies(tx *gorm.DB, firewallDetailsID string, policies []domain.PolicyData, zoneMap map[string]string) error {
	log.Printf("Firewall Details ID: %s", firewallDetailsID)
	log.Printf("Number of policies to store: %d", len(policies))

	if len(policies) == 0 {
		log.Printf("WARNING: No policies to store")
		return nil
	}

	policyCount := 0

	for i, policy := range policies {
		log.Printf("Processing policy %d: ID=%d, Name='%s', Action='%s'",
			i, policy.PolicyID, policy.Name, policy.Action)

		policyName := policy.Name
		if policyName == "" {
			policyName = fmt.Sprintf("Policy_%d", policy.PolicyID)
			log.Printf("Generated policy name: %s", policyName)
		}

		// Map source and destination zones
		var srcID, dstID *string

		// Log interfaces for debugging
		log.Printf("Source interfaces: %v", policy.SrcIntf)
		log.Printf("Destination interfaces: %v", policy.DstIntf)

		// Attempt to find zones based on interface names in policy
		if len(policy.SrcIntf) > 0 {
			for zoneName, zoneID := range zoneMap {
				for _, srcIntf := range policy.SrcIntf {
					if strings.Contains(srcIntf, zoneName) || strings.Contains(zoneName, srcIntf) {
						srcID = &zoneID
						log.Printf("Mapped source zone: %s -> %s", srcIntf, zoneName)
						break
					}
				}
				if srcID != nil {
					break
				}
			}
		}

		if len(policy.DstIntf) > 0 {
			for zoneName, zoneID := range zoneMap {
				for _, dstIntf := range policy.DstIntf {
					if strings.Contains(dstIntf, zoneName) || strings.Contains(zoneName, dstIntf) {
						dstID = &zoneID
						log.Printf("Mapped destination zone: %s -> %s", dstIntf, zoneName)
						break
					}
				}
				if dstID != nil {
					break
				}
			}
		}

		// Map FortiGate action to standard action
		action := "deny"
		if policy.Action == "accept" {
			action = "allow"
		}
		log.Printf("Mapped action: %s -> %s", policy.Action, action)

		status := "disabled"
		if policy.Status == "enable" {
			status = "enabled"
		}
		log.Printf("Mapped status: %s -> %s", policy.Status, status)

		// Build vendor config
		vendorConfig := map[string]interface{}{
			"srcintf":  policy.SrcIntf,
			"dstintf":  policy.DstIntf,
			"srcaddr":  policy.SrcAddr,
			"dstaddr":  policy.DstAddr,
			"service":  policy.Service,
			"schedule": policy.Schedule,
		}

		vendorConfigJSON, _ := json.Marshal(vendorConfig)

		policyID := uuid.New().String()
		securityPolicy := types.FirewallPolicy{
			ID:                   policyID,
			FirewallDetailsID:    firewallDetailsID,
			PolicyName:           policyName,
			PolicyID:             &policy.PolicyID,
			Source:               srcID,
			Destination:          dstID,
			Action:               action,
			PolicyType:           "",
			Status:               status,
			RuleOrder:            &policy.PolicyID,
			VendorSpecificConfig: string(vendorConfigJSON),
		}

		log.Printf("Creating policy record with ID: %s", policyID)

		var existingPolicy types.FirewallPolicy
		// Check if policy exists but is soft-deleted first
		if err := tx.Unscoped().Where("firewall_details_id = ? AND policy_id = ?", firewallDetailsID, policy.PolicyID).First(&existingPolicy).Error; err == nil {
			if existingPolicy.DeletedAt != nil {
				// Policy is soft-deleted, restore it
				log.Printf("Found soft-deleted policy '%s', restoring it", policyName)
				if err := tx.Unscoped().Model(&existingPolicy).Updates(map[string]interface{}{
					"policy_name":            policyName,
					"policy_id":              &policy.PolicyID,
					"source":                 srcID,
					"destination":            dstID,
					"action":                 action,
					"policy_type":            "",
					"status":                 status,
					"rule_order":             &policy.PolicyID,
					"vendor_specific_config": string(vendorConfigJSON),
					"updated_at":             time.Now(),
					"deleted_at":             nil,
				}).Error; err != nil {
					log.Printf("ERROR: Failed to restore policy '%s': %v", policyName, err)
					continue
				}
			} else {
				// Policy exists and is not deleted
				log.Printf("Found existing policy '%s'", policyName)
			}
		} else if err == gorm.ErrRecordNotFound {
			// Policy doesn't exist, create new one
			err := tx.Create(&securityPolicy).Error
			if err != nil {
				log.Printf("ERROR: Failed to create policy '%s': %v", policyName, err)
				continue
			}
			log.Printf("Created new policy '%s'", policyName)
		} else {
			log.Printf("ERROR: Database error checking policy '%s': %v", policyName, err)
			continue
		}

		policyCount++
		log.Printf("✓ Successfully stored policy '%s'", policyName)
	}

	log.Printf("Policy storage complete: %d policies stored out of %d", policyCount, len(policies))
	return nil
}

// Helper functions
func (r *FirewallRepo) getInterfaceTypeID(tx *gorm.DB, interfaceName string) (uint, error) {
	var interfaceType types.InterfaceTypes
	var typeName string

	interfaceNameLower := strings.ToLower(interfaceName)

	switch {
	case strings.Contains(interfaceName, ".") || strings.HasPrefix(interfaceNameLower, "vlan"):
		typeName = "vlan"
	case strings.HasPrefix(interfaceNameLower, "port"):
		typeName = "ethernet"
	case strings.HasPrefix(interfaceNameLower, "tunnel"):
		typeName = "tunnel"
	case strings.HasPrefix(interfaceNameLower, "loop"):
		typeName = "loopback"
	case strings.HasPrefix(interfaceNameLower, "agg"):
		typeName = "aggregate"
	case strings.HasPrefix(interfaceNameLower, "mgmt"):
		typeName = "management"
	default:
		typeName = "ethernet"
	}

	err := tx.Where("type_name = ?", typeName).First(&interfaceType).Error
	if err != nil {
		// Default to ethernet
		err = tx.Where("type_name = 'ethernet'").First(&interfaceType).Error
	}

	return interfaceType.ID, err
}

func (r *FirewallRepo) normalizeStatus(statusValue string, statusType string) string {
	if statusValue == "" {
		if statusType == "operational" {
			return "unknown"
		}
		return "up"
	}

	statusLower := strings.ToLower(strings.TrimSpace(statusValue))

	if statusType == "operational" {
		switch statusLower {
		case "up", "connected", "link-up":
			return "up"
		case "down", "disconnected", "link-down":
			return "down"
		default:
			return "unknown"
		}
	} else { // admin status
		switch statusLower {
		case "up", "enable", "enabled":
			return "up"
		case "down", "disable", "disabled":
			return "down"
		default:
			return "up"
		}
	}
}

func (r *FirewallRepo) normalizeMACAddress(macAddr string) string {
	if macAddr == "" || len(macAddr) > 17 {
		return ""
	}
	return macAddr
}

func (r *FirewallRepo) updateVLANParentRelationships(tx *gorm.DB, interfaceMap map[string]string) {
	log.Println("Updating parent interface relationships...")

	for interfaceName, interfaceID := range interfaceMap {
		if strings.Contains(interfaceName, ".") {
			parentName := strings.Split(interfaceName, ".")[0]
			if parentID, exists := interfaceMap[parentName]; exists {
				err := tx.Model(&types.Interfaces{}).
					Where("id = ?", interfaceID).
					Update("parent_interface_id", parentID).Error
				if err != nil {
					log.Printf("Failed to update parent relationship for '%s': %v", interfaceName, err)
				} else {
					log.Printf("Updated parent relationship: %s -> %s", interfaceName, parentName)
				}
			}
		}
	}
}

func (r *FirewallRepo) StoreFirewallDataWithAssets(ctx context.Context, data domain.FirewallData, scanJobID int64, interfaceAssetMap map[string]string) error {
	log.Printf("Asset ID: %s, Scan Job ID: %d, Interface Assets: %d", data.AssetID, scanJobID, len(interfaceAssetMap))
	log.Printf("Data summary: %d zones, %d interfaces, %d policies, %d VLANs",
		len(data.Zones), len(data.Interfaces), len(data.Policies), len(data.VLANs))

	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		log.Printf("Transaction started")

		// Step 1: Ensure firewall details exist
		log.Printf("Step 1: Ensuring firewall details exist for asset %s", data.AssetID)
		if err := r.ensureFirewallDetails(tx, data.AssetID); err != nil {
			log.Printf("ERROR: Failed to ensure firewall details: %v", err)
			return fmt.Errorf("failed to ensure firewall details: %v", err)
		}
		log.Printf("✓ Firewall details confirmed")

		// Step 2: Store zones
		log.Printf("Step 2: Storing %d zones", len(data.Zones))
		// Get firewall details first to get the ID
		var firewallDetails types.FirewallDetails
		if err := tx.Where("asset_id = ?", data.AssetID).First(&firewallDetails).Error; err != nil {
			log.Printf("ERROR: Failed to get firewall details: %v", err)
			return fmt.Errorf("failed to get firewall details: %v", err)
		}

		zoneMap, err := r.storeZones(tx, data.Zones, firewallDetails.ID)
		if err != nil {
			log.Printf("ERROR: Failed to store zones: %v", err)
			return fmt.Errorf("failed to store zones: %v", err)
		}
		log.Printf("✓ Stored %d zones successfully", len(zoneMap))

		// Step 3: Store interfaces WITH asset mappings
		log.Printf("Step 3: Storing %d interfaces with asset mappings", len(data.Interfaces))
		interfaceMap, err := r.storeInterfacesWithAssets(tx, data.AssetID, data.Interfaces, zoneMap, interfaceAssetMap)
		if err != nil {
			log.Printf("ERROR: Failed to store interfaces: %v", err)
			return fmt.Errorf("failed to store interfaces: %v", err)
		}
		log.Printf("✓ Stored %d interfaces successfully", len(interfaceMap))

		// Step 4: Update parent interface relationships
		log.Printf("Step 4: Updating VLAN parent relationships")
		r.updateVLANParentRelationships(tx, interfaceMap)

		// Step 5: Store VLANs
		log.Printf("Step 5: Storing %d VLANs", len(data.VLANs))
		vlanIDMap, err := r.storeVLANs(tx, data.VLANs, interfaceMap, data.AssetID)
		if err != nil {
			log.Printf("ERROR: Failed to store VLANs: %v", err)
			return fmt.Errorf("failed to store VLANs: %v", err)
		}
		log.Printf("✓ Stored %d VLANs successfully", len(vlanIDMap))

		// Step 6: Store zone details (relationships)
		log.Printf("Step 6: Storing zone-interface-VLAN relationships")
		if err := r.storeZoneDetails(tx, data.Interfaces, zoneMap, interfaceMap, vlanIDMap, data.AssetID); err != nil {
			log.Printf("ERROR: Failed to store zone details: %v", err)
			return fmt.Errorf("failed to store zone details: %v", err)
		}
		log.Printf("✓ Zone relationships stored successfully")

		// Step 7: Store policies (reuse firewall details from earlier)
		log.Printf("Step 7: Storing %d policies", len(data.Policies))
		if err := r.storePolicies(tx, firewallDetails.ID, data.Policies, zoneMap); err != nil {
			log.Printf("ERROR: Failed to store policies: %v", err)
			return fmt.Errorf("failed to store policies: %v", err)
		}
		log.Printf("✓ Stored policies successfully")

		log.Printf("Asset: %s, Scan Job: %d", data.AssetID, scanJobID)
		return nil
	})
}

func (r *FirewallRepo) storeInterfacesWithAssets(tx *gorm.DB, assetID string, interfaces []domain.InterfaceData, zoneMap map[string]string, interfaceAssetMap map[string]string) (map[string]string, error) {
	interfaceMap := make(map[string]string)

	if len(interfaces) == 0 {
		log.Printf("WARNING: No interfaces to store")
		return interfaceMap, nil
	}

	for i, intf := range interfaces {
		log.Printf("Processing interface %d: Name='%s', IP='%s', Zone='%s', Type='%s'",
			i, intf.Name, intf.IP, intf.Zone, intf.Type)

		if intf.Name == "" {
			log.Printf("SKIP: Interface %d has empty name", i)
			continue
		}

		// Get interface type
		interfaceTypeID, err := r.getInterfaceTypeID(tx, intf.Name)
		if err != nil {
			log.Printf("ERROR: Failed to get interface type for '%s': %v", intf.Name, err)
			continue
		}
		log.Printf("Interface type ID for '%s': %d", intf.Name, interfaceTypeID)

		var parentInterfaceID *string
		var vlanID *int
		if strings.Contains(intf.Name, ".") {
			parts := strings.Split(intf.Name, ".")
			if len(parts) == 2 {
				if vlanIDInt, err := strconv.Atoi(parts[1]); err == nil {
					vlanID = &vlanIDInt
					log.Printf("Detected VLAN interface: %s, VLAN ID: %d", intf.Name, *vlanID)
				}
			}
		}

		// Check if this interface has an associated asset
		var interfaceAssetID *string
		if assetIDStr, hasAsset := interfaceAssetMap[intf.Name]; hasAsset {
			interfaceAssetID = &assetIDStr
			log.Printf("Interface '%s' linked to asset: %s", intf.Name, assetIDStr)
		} else {
			log.Printf("Interface '%s' has no associated asset", intf.Name)
		}

		// Create vendor config
		vendorConfig := map[string]interface{}{
			"allowaccess":     intf.Allowaccess,
			"status":          intf.Status,
			"type":            intf.Type,
			"vdom":            intf.VDOM,
			"mode":            intf.Mode,
			"role":            intf.Role,
			"original_duplex": intf.Duplex,
			"original_speed":  intf.Speed,
			"secondaryip":     intf.SecondaryIPs,
			"mtu":             intf.MTU,
		}

		vendorConfigJSON, _ := json.Marshal(vendorConfig)

		interfaceID := uuid.New().String()
		firewallInterface := types.Interfaces{
			ID:                   interfaceID,
			InterfaceName:        intf.Name,
			InterfaceTypeID:      interfaceTypeID,
			AssetID:              interfaceAssetID, // Set the asset ID
			VirtualSystem:        intf.VDOM,
			Description:          intf.Description,
			OperationalStatus:    r.normalizeStatus(intf.Status, "operational"),
			AdminStatus:          r.normalizeStatus(intf.Status, "admin"),
			ParentInterfaceID:    parentInterfaceID,
			VLANId:               vlanID,
			MacAddress:           r.normalizeMACAddress(intf.MacAddr),
			VendorSpecificConfig: string(vendorConfigJSON),
		}

		log.Printf("Creating unified interface record with ID: %s, Asset ID: %v", interfaceID, interfaceAssetID)

		var existingInterface types.Interfaces
		var finalInterfaceID string
		// Check if interface exists but is soft-deleted first
		if err := tx.Unscoped().Where("interface_name = ?", intf.Name).First(&existingInterface).Error; err == nil {
			if existingInterface.DeletedAt != nil {
				// Interface is soft-deleted, restore it
				log.Printf("Found soft-deleted interface '%s', restoring it", intf.Name)
				finalInterfaceID = existingInterface.ID
				if err := tx.Unscoped().Model(&existingInterface).Updates(map[string]interface{}{
					"interface_name":         intf.Name,
					"interface_type_id":      interfaceTypeID,
					"asset_id":               interfaceAssetID,
					"virtual_system":         intf.VDOM,
					"description":            intf.Description,
					"operational_status":     r.normalizeStatus(intf.Status, "operational"),
					"admin_status":           r.normalizeStatus(intf.Status, "admin"),
					"parent_interface_id":    parentInterfaceID,
					"vlan_id":                vlanID,
					"mac_address":            r.normalizeMACAddress(intf.MacAddr),
					"vendor_specific_config": string(vendorConfigJSON),
					"updated_at":             time.Now(),
					"deleted_at":             nil,
				}).Error; err != nil {
					log.Printf("ERROR: Failed to restore interface '%s': %v", intf.Name, err)
					continue
				}
			} else {
				// Interface exists and is not deleted
				finalInterfaceID = existingInterface.ID
				// Update existing interface with asset ID if it wasn't set
				if existingInterface.AssetID == nil && interfaceAssetID != nil {
					err = tx.Model(&existingInterface).Update("asset_id", interfaceAssetID).Error
					if err != nil {
						log.Printf("ERROR: Failed to update asset_id for existing interface '%s': %v", intf.Name, err)
					} else {
						log.Printf("Updated existing interface '%s' with Asset ID: %s", intf.Name, *interfaceAssetID)
					}
				} else {
					log.Printf("Found existing interface '%s' with ID: %s", intf.Name, finalInterfaceID)
				}
			}
		} else if err == gorm.ErrRecordNotFound {
			// Interface doesn't exist, create new one
			err = tx.Create(&firewallInterface).Error
			if err != nil {
				log.Printf("ERROR: Failed to create interface '%s': %v", intf.Name, err)
				continue
			}
			finalInterfaceID = interfaceID
			log.Printf("Created new interface '%s' with ID: %s, Asset ID: %v", intf.Name, finalInterfaceID, interfaceAssetID)
		} else {
			log.Printf("ERROR: Database error checking interface '%s': %v", intf.Name, err)
			continue
		}

		interfaceMap[intf.Name] = finalInterfaceID
	}

	log.Printf("Interface storage complete: %d interfaces processed, %d stored", len(interfaces), len(interfaceMap))
	return interfaceMap, nil
}
