package mapper

import (
	"strings"

	"github.com/google/uuid"
	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/domain"
	Domain "gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/domain"
	ScannerDomain "gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanner/domain"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/adapter/storage/types"
)

// Keep the original function for backward compatibility
func AssetDomain2Storage(asset Domain.AssetDomain) (*types.Assets, []*types.IPs) {
	// Normalize multi-value fields before storage
	normalizedOSName := normalizeMultiValueField(asset.OSName, domain.NormalizeOSType)
	normalizedAssetType := normalizeMultiValueField(asset.Type, domain.NormalizeAssetType)

	// Convert asset value from int to float64
	assetValue := float64(asset.AssetValue)

	// Set discovered_by field if it has a value
	var discoveredByPtr *string
	if asset.DiscoveredBy != "" {
		discoveredByPtr = &asset.DiscoveredBy
	}

	assetStorage := &types.Assets{
		ID:               asset.ID.String(),
		VendorID:         1, // Default - this should be updated to use the new method
		Name:             asset.Name,
		Domain:           asset.Domain,
		Hostname:         asset.Hostname,
		OSName:           normalizedOSName,
		OSVersion:        asset.OSVersion,
		Description:      asset.Description,
		AssetType:        normalizedAssetType,
		DiscoveredBy:     discoveredByPtr,
		Risk:             asset.Risk,
		LoggingCompleted: asset.LoggingCompleted,
		AssetValue:       assetValue,
		CreatedAt:        asset.CreatedAt,
		UpdatedAt:        asset.UpdatedAt,
	}

	// Create AssetIP objects for each IP
	assetIPs := make([]*types.IPs, 0, len(asset.AssetIPs))
	for _, ip := range asset.AssetIPs {
		mac := ip.MACAddress
		if mac == "" {
			mac = "" // Leave empty if not provided
		}

		assetIPID := ip.ID
		if assetIPID == "" {
			assetIPID = uuid.New().String()
		}

		assetIP := &types.IPs{
			ID:         assetIPID,
			AssetID:    asset.ID.String(),
			IPAddress:  ip.IP,
			MacAddress: mac,
			CreatedAt:  asset.CreatedAt,
		}

		if ip.InterfaceID != "" {
			assetIP.InterfaceID = &ip.InterfaceID
		}

		if ip.CIDRPrefix != nil {
			assetIP.CIDRPrefix = ip.CIDRPrefix
		}

		assetIPs = append(assetIPs, assetIP)
	}

	return assetStorage, assetIPs
}

func AssetStorage2Domain(asset types.Assets) (*Domain.AssetDomain, error) {
	uid, err := Domain.AssetUUIDFromString(asset.ID)
	if err != nil {
		return nil, err
	}

	ports := make([]Domain.Port, 0, len(asset.Ports))
	for _, port := range asset.Ports {
		var serviceName, serviceVersion, description string
		if port.ServiceName != nil {
			serviceName = *port.ServiceName
		}
		if port.ServiceVersion != nil {
			serviceVersion = *port.ServiceVersion
		}
		if port.Description != nil {
			description = *port.Description
		}

		ports = append(ports, Domain.Port{
			ID:             port.ID,
			AssetID:        port.AssetID,
			PortNumber:     port.PortNumber,
			Protocol:       port.Protocol,
			State:          port.State,
			ServiceName:    serviceName,
			ServiceVersion: serviceVersion,
			Description:    description,
			DiscoveredAt:   port.DiscoveredAt,
		})
	}

	vms := make([]Domain.VMwareVM, 0, len(asset.VMwareVMs))
	for _, vm := range asset.VMwareVMs {
		vms = append(vms, Domain.VMwareVM{
			VMID:         vm.VMID,
			AssetID:      vm.AssetID,
			VMName:       vm.VMName,
			Hypervisor:   vm.Hypervisor,
			CPUCount:     int32(vm.CPUCount),
			MemoryMB:     int32(vm.MemoryMB),
			DiskSizeGB:   vm.DiskSizeGB,
			PowerState:   vm.PowerState,
			LastSyncedAt: vm.LastSyncedAt,
		})
	}

	ips := make([]Domain.AssetIP, 0, len(asset.IPs))
	for _, ip := range asset.IPs {
		interfaceID := ""
		if ip.InterfaceID != nil {
			interfaceID = *ip.InterfaceID
		}

		ips = append(ips, Domain.AssetIP{
			ID:          ip.ID,
			AssetID:     ip.AssetID,
			InterfaceID: interfaceID,
			IP:          ip.IPAddress,
			MACAddress:  ip.MacAddress,
			CIDRPrefix:  ip.CIDRPrefix,
		})
	}

	// Convert asset value from float64 to int
	assetValue := int(asset.AssetValue)

	// Handle deleted_at for domain model
	updatedAt := asset.UpdatedAt
	if asset.DeletedAt != nil {
		// If deleted, use deletion time as updated time
		updatedAt = *asset.DeletedAt
	}

	// Get discovered_by value
	// Handle discovered_by field
	discoveredBy := ""
	if asset.DiscoveredBy != nil {
		discoveredBy = *asset.DiscoveredBy
	}

	return &Domain.AssetDomain{
		ID:               uid,
		Name:             asset.Name,
		Domain:           asset.Domain,
		Hostname:         asset.Hostname,
		OSName:           asset.OSName,
		OSVersion:        asset.OSVersion,
		Type:             asset.AssetType,
		Description:      asset.Description,
		DiscoveredBy:     discoveredBy,
		Risk:             asset.Risk,
		LoggingCompleted: asset.LoggingCompleted,
		AssetValue:       assetValue,
		CreatedAt:        asset.CreatedAt,
		UpdatedAt:        updatedAt,
		Ports:            ports,
		VMwareVMs:        vms,
		AssetIPs:         ips,
	}, nil
}

func AssetStorage2DomainWithScannerType(asset types.Assets, scannerType string) (*Domain.AssetDomain, error) {
	assetDomain, err := AssetStorage2Domain(asset)
	if err != nil {
		return nil, err
	}

	scannerObj := &ScannerDomain.ScannerDomain{
		Type: scannerType,
	}

	assetDomain.Scanner = scannerObj
	return assetDomain, nil
}

// PortDomain2Storage maps domain.Port to storage.Port
func PortDomain2Storage(port Domain.Port) *types.Port {
	portStorage := &types.Port{
		ID:           port.ID,
		AssetID:      port.AssetID,
		PortNumber:   port.PortNumber,
		Protocol:     NormalizeProtocol(port.Protocol), // Normalize protocol to fit database enum
		State:        port.State,
		DiscoveredAt: port.DiscoveredAt,
	}

	// Only set pointer fields if they have values
	if port.ServiceName != "" {
		portStorage.ServiceName = &port.ServiceName
	}
	if port.ServiceVersion != "" {
		portStorage.ServiceVersion = &port.ServiceVersion
	}
	if port.Description != "" {
		portStorage.Description = &port.Description
	}

	return portStorage
}

// AssetIPDomain2Storage maps domain.AssetIP to storage.IPs
func AssetIPDomain2Storage(ip Domain.AssetIP) *types.IPs {
	ipID := ip.ID
	if ipID == "" {
		ipID = uuid.New().String()
	}

	ipStorage := &types.IPs{
		ID:         ipID,
		AssetID:    ip.AssetID,
		IPAddress:  ip.IP,
		MacAddress: ip.MACAddress,
	}

	if ip.InterfaceID != "" {
		ipStorage.InterfaceID = &ip.InterfaceID
	}

	if ip.CIDRPrefix != nil {
		ipStorage.CIDRPrefix = ip.CIDRPrefix
	}

	return ipStorage
}

// normalizeMultiValueField normalizes values in a multi-value field using a normalization function
// and ensures all values are unique
func normalizeMultiValueField(fieldValue string, normalizeFunc func(string) string) string {
	if fieldValue == "" {
		return ""
	}

	values := strings.Split(fieldValue, ", ")
	var normalizedValues []string
	seen := make(map[string]bool)

	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed != "" {
			normalized := normalizeFunc(trimmed)
			if normalized != "" && !seen[normalized] {
				normalizedValues = append(normalizedValues, normalized)
				seen[normalized] = true
			}
		}
	}

	return strings.Join(normalizedValues, ", ")
}
