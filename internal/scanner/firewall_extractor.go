package scanner

import (
	"context"
	"encoding/json"

	scannerDomain "gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanner/domain"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/logger"
)

// FortigateVLAN represents VLAN data from FortiGate system/vlan endpoint
type FortigateVLAN struct {
	VLANID      int           `json:"vlanid"`
	Name        string        `json:"name"`
	Description string        `json:"description"`
	Interface   string        `json:"interface"`
	Status      string        `json:"status"`
	DHCPHelper  []interface{} `json:"dhcp-helper"`
}

// LoadAllData method with better error handling and VLAN support
func (fe *FortigateExtractor) LoadAllData(ctx context.Context) error {
	logger.InfoContext(ctx, "Fetching data from FortiGate...")

	// Fetch zones
	if err := fe.loadZones(ctx); err != nil {
		logger.InfoContext(ctx, "Error fetching zones: %v", err)
		return err // Return error for critical data
	}

	// Check for cancellation
	if ctx.Err() == context.Canceled {
		return context.Canceled
	}

	// Fetch interfaces
	if err := fe.loadInterfaces(ctx); err != nil {
		logger.InfoContext(ctx, "Error fetching interfaces: %v", err)
		return err // Return error for critical data
	}

	// Check for cancellation
	if ctx.Err() == context.Canceled {
		return context.Canceled
	}

	// Fetch VLANs from the system/vlan endpoint
	if err := fe.loadVLANs(ctx); err != nil {
		logger.InfoContext(ctx, "Error fetching VLANs: %v", err)
		// Don't return error for VLANs - they can be derived from interfaces
	}

	// Check for cancellation
	if ctx.Err() == context.Canceled {
		return context.Canceled
	}

	// Fetch policies
	if err := fe.loadPolicies(ctx); err != nil {
		logger.InfoContext(ctx, "Error fetching policies: %v", err)
		// Don't return error for policies - not critical for basic functionality
	}

	// Fetch addresses
	if err := fe.loadAddresses(ctx); err != nil {
		logger.InfoContext(ctx, "Error fetching addresses: %v", err)
		// Don't return error for addresses - not critical for basic functionality
	}

	logger.InfoContext(ctx, "Loaded: %d zones, %d interfaces, %d policies, %d addresses, %d VLANs",
		len(fe.zones), len(fe.interfaces), len(fe.policies), len(fe.addresses), len(fe.vlans))

	return nil
}

// loadZones loads zone data from FortiGate API
func (fe *FortigateExtractor) loadZones(ctx context.Context) error {
	zonesData, err := fe.client.fetchData(ctx, "system/zone")
	if err != nil {
		return err
	}

	for i, zoneData := range zonesData {
		var zone scannerDomain.FortigateZone
		if err := json.Unmarshal(zoneData, &zone); err != nil {
			logger.InfoContext(ctx, "Failed to unmarshal zone %d: %v", i, err)
			continue
		}
		fe.zones = append(fe.zones, zone)
	}

	return nil
}

// loadInterfaces loads interface data from FortiGate API
func (fe *FortigateExtractor) loadInterfaces(ctx context.Context) error {
	interfacesData, err := fe.client.fetchData(ctx, "system/interface")
	if err != nil {
		return err
	}

	for i, intfData := range interfacesData {
		var intf scannerDomain.FortigateInterface
		if err := json.Unmarshal(intfData, &intf); err != nil {
			logger.InfoContext(ctx, "Failed to unmarshal interface %d: %v", i, err)
			// Try to parse as generic map to extract basic info
			intf = fe.parseGenericInterface(ctx, intfData, i)
			if intf.Name == "" {
				continue
			}
		}
		fe.interfaces = append(fe.interfaces, intf)
	}

	return nil
}

// loadVLANs loads VLAN data from FortiGate system/vlan endpoint
func (fe *FortigateExtractor) loadVLANs(ctx context.Context) error {
	vlansData, err := fe.client.fetchData(ctx, "system/vlan")
	if err != nil {
		logger.InfoContext(ctx, "Failed to fetch VLANs from system/vlan endpoint: %v", err)
		return err
	}

	logger.InfoContext(ctx, "Retrieved %d VLAN records from FortiGate", len(vlansData))

	for i, vlanData := range vlansData {
		var vlan FortigateVLAN
		if err := json.Unmarshal(vlanData, &vlan); err != nil {
			logger.InfoContext(ctx, "Failed to unmarshal VLAN %d: %v", i, err)
			continue
		}

		// Convert FortigateVLAN to domain VLANData
		vlanDomain := scannerDomain.VLANData{
			VLANID:          vlan.VLANID,
			VLANName:        vlan.Name,
			ParentInterface: vlan.Interface,
			Description:     vlan.Description,
		}

		fe.vlans = append(fe.vlans, vlanDomain)
		logger.InfoContext(ctx, "Loaded VLAN %d: %s on interface %s", vlan.VLANID, vlan.Name, vlan.Interface)
	}

	logger.InfoContext(ctx, "Successfully loaded %d VLANs from system/vlan endpoint", len(fe.vlans))
	return nil
}

// loadPolicies loads policy data from FortiGate API
func (fe *FortigateExtractor) loadPolicies(ctx context.Context) error {
	policiesData, err := fe.client.fetchData(ctx, "firewall/policy")
	if err != nil {
		return err
	}

	for _, policyData := range policiesData {
		var policy scannerDomain.FortigatePolicy
		if err := json.Unmarshal(policyData, &policy); err != nil {
			logger.InfoContext(ctx, "Failed to unmarshal policy: %v", err)
			continue
		}
		fe.policies = append(fe.policies, policy)
	}

	return nil
}

// loadAddresses loads address data from FortiGate API
func (fe *FortigateExtractor) loadAddresses(ctx context.Context) error {
	addressesData, err := fe.client.fetchData(ctx, "firewall/address")
	if err != nil {
		return err
	}

	for _, addrData := range addressesData {
		var addr scannerDomain.FortigateAddress
		if err := json.Unmarshal(addrData, &addr); err != nil {
			logger.InfoContext(ctx, "Failed to unmarshal address: %v", err)
			continue
		}
		fe.addresses = append(fe.addresses, addr)
	}

	return nil
}

// parseGenericInterface parses interface data from a generic map with flexible allowaccess handling
func (fe *FortigateExtractor) parseGenericInterface(ctx context.Context, intfData json.RawMessage, index int) scannerDomain.FortigateInterface {
	var genericIntf map[string]interface{}
	if err := json.Unmarshal(intfData, &genericIntf); err != nil {
		return scannerDomain.FortigateInterface{}
	}

	intf := scannerDomain.FortigateInterface{}

	// Extract basic fields safely
	fe.extractBasicInterfaceFields(&intf, genericIntf)

	// Parse allowaccess - handle both string and array
	if allowaccess, ok := genericIntf["allowaccess"]; ok {
		intf.Allowaccess = fe.parseAllowAccess(allowaccess)
	}

	// Parse secondary IPs
	if secondaryips, ok := genericIntf["secondaryip"].([]interface{}); ok {
		intf.SecondaryIP = fe.parseSecondaryIPs(secondaryips)
	}

	return intf
}

// extractBasicInterfaceFields extracts basic interface fields from generic map
func (fe *FortigateExtractor) extractBasicInterfaceFields(intf *scannerDomain.FortigateInterface, genericIntf map[string]interface{}) {
	if name, ok := genericIntf["name"].(string); ok {
		intf.Name = name
	}
	if ip, ok := genericIntf["ip"].(string); ok {
		intf.IP = ip
	}
	if status, ok := genericIntf["status"].(string); ok {
		intf.Status = status
	}
	if desc, ok := genericIntf["description"].(string); ok {
		intf.Description = desc
	}
	if mtu, ok := genericIntf["mtu"].(float64); ok {
		intf.MTU = int(mtu)
	}
	if speed, ok := genericIntf["speed"].(string); ok {
		intf.Speed = speed
	}
	if duplex, ok := genericIntf["duplex"].(string); ok {
		intf.Duplex = duplex
	}
	if ifType, ok := genericIntf["type"].(string); ok {
		intf.Type = ifType
	}
	if vdom, ok := genericIntf["vdom"].(string); ok {
		intf.VDOM = vdom
	}
	if mode, ok := genericIntf["mode"].(string); ok {
		intf.Mode = mode
	}
	if role, ok := genericIntf["role"].(string); ok {
		intf.Role = role
	}
	if macaddr, ok := genericIntf["macaddr"].(string); ok {
		intf.MacAddr = macaddr
	}
}

// parseAllowAccess parses allowaccess field which can be string or array
func (fe *FortigateExtractor) parseAllowAccess(allowaccess interface{}) scannerDomain.FlexibleStringArray {
	switch v := allowaccess.(type) {
	case string:
		if v != "" {
			return scannerDomain.FlexibleStringArray([]string{v})
		}
		return scannerDomain.FlexibleStringArray([]string{})
	case []interface{}:
		var allowList []string
		for _, access := range v {
			if accessStr, ok := access.(string); ok {
				allowList = append(allowList, accessStr)
			} else if accessMap, ok := access.(map[string]interface{}); ok {
				if name, ok := accessMap["name"].(string); ok {
					allowList = append(allowList, name)
				}
			}
		}
		return scannerDomain.FlexibleStringArray(allowList)
	default:
		return scannerDomain.FlexibleStringArray([]string{})
	}
}

// parseSecondaryIPs parses secondary IP data from interface
func (fe *FortigateExtractor) parseSecondaryIPs(secondaryips []interface{}) []scannerDomain.FortigateSecondaryIP {
	var result []scannerDomain.FortigateSecondaryIP

	for _, secIP := range secondaryips {
		if secIPMap, ok := secIP.(map[string]interface{}); ok {
			secIPStruct := scannerDomain.FortigateSecondaryIP{}

			if id, ok := secIPMap["id"].(float64); ok {
				secIPStruct.ID = int(id)
			}
			if ip, ok := secIPMap["ip"].(string); ok {
				secIPStruct.IP = ip
			}

			// Handle allowaccess for secondary IPs
			if allowaccess, ok := secIPMap["allowaccess"]; ok {
				secIPStruct.Allowaccess = fe.parseAllowAccess(allowaccess)
			}

			result = append(result, secIPStruct)
		}
	}

	return result
}
