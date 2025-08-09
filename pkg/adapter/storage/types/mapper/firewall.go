package mapper

import (
	"time"

	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/firewall/domain"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/adapter/storage/types"
)

// FirewallStorage2Domain converts storage types to domain model
func FirewallStorage2Domain(asset types.Assets, details types.FirewallDetails, zones []types.Zones, interfaces []types.Interfaces, vlans []types.VLANs, policies []types.FirewallPolicy, ips []types.IPs, vlanInterfaces []types.VLANInterface) (*domain.FirewallDomain, error) {
	// Convert asset
	firewallAsset := domain.FirewallAsset{
		ID:               asset.ID,
		VendorCode:       asset.Vendor.VendorCode,
		Name:             asset.Name,
		Domain:           asset.Domain,
		Hostname:         asset.Hostname,
		OSName:           asset.OSName,
		OSVersion:        asset.OSVersion,
		Description:      asset.Description,
		AssetType:        asset.AssetType,
		DiscoveredBy:     asset.DiscoveredBy,
		Risk:             asset.Risk,
		LoggingCompleted: asset.LoggingCompleted,
		AssetValue:       asset.AssetValue,
		CreatedAt:        asset.CreatedAt,
		UpdatedAt:        asset.UpdatedAt,
	}

	// Convert details
	firewallDetails := domain.FirewallDetails{
		ID:              details.ID,
		AssetID:         details.AssetID,
		Model:           details.Model,
		FirmwareVersion: details.FirmwareVersion,
		SerialNumber:    details.SerialNumber,
		IsHAEnabled:     details.IsHAEnabled,
		HARole:          details.HARole,
		ManagementIP:    details.ManagementIP,
		SiteName:        details.SiteName,
		Location:        details.Location,
		Status:          details.Status,
		LastSync:        details.LastSync,
		SyncStatus:      details.SyncStatus,
	}

	// Convert zones
	firewallZones := make([]domain.FirewallZone, 0, len(zones))
	for _, zone := range zones {
		// Get zone interfaces from zone details and resolve to names
		var interfaceNames []string
		var vlanNames []string

		for _, zoneDetail := range zone.ZoneDetails {
			// Find interface name by ID
			if zoneDetail.FirewallInterfaceID != "" {
				for _, iface := range interfaces {
					if iface.ID == zoneDetail.FirewallInterfaceID {
						interfaceNames = append(interfaceNames, iface.InterfaceName)
						break
					}
				}
			}
			// Find VLAN name by ID
			if zoneDetail.VLANTableID != "" {
				for _, vlan := range vlans {
					if vlan.ID == zoneDetail.VLANTableID {
						vlanNames = append(vlanNames, vlan.VLANName)
						break
					}
				}
			}
		}

		firewallZones = append(firewallZones, domain.FirewallZone{
			ID:                    zone.ID,
			ZoneName:              zone.ZoneName,
			ZoneType:              zone.ZoneType,
			VendorZoneType:        zone.VendorZoneType,
			Description:           zone.Description,
			ZoneMode:              zone.ZoneMode,
			IntrazoneAction:       zone.IntrazoneAction,
			ZoneProtectionProfile: zone.ZoneProtectionProfile,
			LogSetting:            zone.LogSetting,
			Interfaces: domain.ZoneInterfaces{
				InterfaceName: interfaceNames,
				VLANName:      vlanNames,
			},
		})
	}

	// Convert interfaces
	firewallInterfaces := make([]domain.FirewallInterface, 0, len(interfaces))
	for _, iface := range interfaces {
		// Find primary IP for this interface
		var primaryIP string
		var cidrPrefix *int
		secondaryIPs := make([]domain.SecondaryIP, 0)

		for _, ip := range ips {
			if ip.InterfaceID != nil && *ip.InterfaceID == iface.ID {
				if primaryIP == "" {
					// First IP becomes primary
					primaryIP = ip.IPAddress
					cidrPrefix = ip.CIDRPrefix
				} else {
					// Additional IPs become secondary
					secondaryIPs = append(secondaryIPs, domain.SecondaryIP{
						IP:         ip.IPAddress,
						CIDRPrefix: ip.CIDRPrefix,
					})
				}
			}
		}

		// Resolve parent interface ID to name
		var parentInterfaceName *string
		if iface.ParentInterfaceID != nil {
			for _, parentIface := range interfaces {
				if parentIface.ID == *iface.ParentInterfaceID {
					parentInterfaceName = &parentIface.InterfaceName
					break
				}
			}
		}

		firewallInterfaces = append(firewallInterfaces, domain.FirewallInterface{
			ID:                   iface.ID,
			InterfaceName:        iface.InterfaceName,
			InterfaceType:        iface.InterfaceType.TypeName,
			VirtualRouter:        iface.VirtualRouter,
			VirtualSystem:        iface.VirtualSystem,
			Description:          iface.Description,
			OperationalStatus:    iface.OperationalStatus,
			AdminStatus:          iface.AdminStatus,
			ParentInterfaceName:  parentInterfaceName,
			VLANId:               iface.VLANId,
			MacAddress:           iface.MacAddress,
			VendorSpecificConfig: iface.VendorSpecificConfig,
			SecondaryIPs:         secondaryIPs,
			PrimaryIP:            primaryIP,
			CIDRPrefix:           cidrPrefix,
		})
	}

	// Convert VLANs
	firewallVLANs := make([]domain.FirewallVLAN, 0, len(vlans))
	for _, vlan := range vlans {
		// Find interfaces for this VLAN
		var interfaceNames []string
		for _, vlanInterface := range vlanInterfaces {
			if vlanInterface.VLANTableID == vlan.ID {
				// Find interface name by ID
				for _, iface := range interfaces {
					if iface.ID == vlanInterface.InterfaceID {
						interfaceNames = append(interfaceNames, iface.InterfaceName)
						break
					}
				}
				break
			}
		}

		firewallVLANs = append(firewallVLANs, domain.FirewallVLAN{
			ID:                   vlan.ID,
			VLANNumber:           vlan.VLANNumber,
			VLANName:             vlan.VLANName,
			Description:          vlan.Description,
			IsNative:             vlan.IsNative,
			VendorSpecificConfig: vlan.VendorSpecificConfig,
			Interfaces:           interfaceNames,
		})
	}

	// Convert policies
	firewallPolicies := make([]domain.FirewallPolicy, 0, len(policies))
	for _, policy := range policies {
		firewallPolicies = append(firewallPolicies, domain.FirewallPolicy{
			ID:                   policy.ID,
			PolicyName:           policy.PolicyName,
			PolicyID:             policy.PolicyID,
			SrcAddresses:         []string{}, // TODO: Would need to be parsed from VendorSpecificConfig or separate table
			DstAddresses:         []string{}, // TODO: Would need to be parsed from VendorSpecificConfig or separate table
			Services:             []string{}, // TODO: Would need to be parsed from VendorSpecificConfig or separate table
			Action:               policy.Action,
			PolicyType:           policy.PolicyType,
			Status:               policy.Status,
			RuleOrder:            policy.RuleOrder,
			VendorSpecificConfig: policy.VendorSpecificConfig,
			Schedule:             "", // TODO: Would need to be parsed from VendorSpecificConfig
		})
	}

	return &domain.FirewallDomain{
		Asset:      firewallAsset,
		Details:    firewallDetails,
		Zones:      firewallZones,
		Interfaces: firewallInterfaces,
		VLANs:      firewallVLANs,
		Policies:   firewallPolicies,
	}, nil
}

// ParseLastSyncTime parses last sync time safely
func ParseLastSyncTime(lastSync *time.Time) *time.Time {
	if lastSync == nil {
		return nil
	}
	return lastSync
}
