package scanner

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/domain"
	assetDomain "gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/domain"
	scannerDomain "gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanner/domain"
)

// FortigateClient represents a FortiGate API client
type FortigateClient struct {
	httpClient *http.Client
	baseURL    string
	apiKey     string
	authMethod string
}

// FortigateExtractor handles extracting and storing FortiGate data
type FortigateExtractor struct {
	client     *FortigateClient
	scanner    scannerDomain.ScannerDomain
	scanJobID  int64
	zones      []scannerDomain.FortigateZone
	interfaces []scannerDomain.FortigateInterface
	policies   []scannerDomain.FortigatePolicy
	addresses  []scannerDomain.FortigateAddress
	vlans      []scannerDomain.VLANData // Add VLANs field
}

// FirewallHelper contains helper functions for firewall operations
type FirewallHelper struct {
	validator *FirewallValidator
}

// NewFirewallHelper creates a new helper instance
func NewFirewallHelper() *FirewallHelper {
	return &FirewallHelper{
		validator: NewFirewallValidator(),
	}
}

// CreateFortigateClient creates an HTTP client configured for FortiGate API
func (h *FirewallHelper) CreateFortigateClient(ip, port, apiKey string) *FortigateClient {
	tr := &http.Transport{
		TLSClientConfig:    &tls.Config{InsecureSkipVerify: true},
		DisableCompression: false,
		IdleConnTimeout:    30 * time.Second,
	}

	client := &http.Client{
		Transport: tr,
		Timeout:   30 * time.Second,
	}

	baseURL := fmt.Sprintf("https://%s:%s/api/v2/cmdb", ip, port)

	return &FortigateClient{
		httpClient: client,
		baseURL:    baseURL,
		apiKey:     apiKey,
		authMethod: "bearer", // Start with bearer
	}
}

// FetchData makes a generic API call to FortiGate with flexible authentication
func (fg *FortigateClient) fetchData(ctx context.Context, endpoint string) ([]json.RawMessage, error) {
	url := fmt.Sprintf("%s/%s", fg.baseURL, endpoint)

	// Add API key as query parameter for query method
	if fg.authMethod == "query" {
		if strings.Contains(url, "?") {
			url += "&access_token=" + fg.apiKey
		} else {
			url += "?access_token=" + fg.apiKey
		}
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	// Set authentication header based on method
	switch fg.authMethod {
	case "bearer":
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", fg.apiKey))
	case "apikey":
		req.Header.Set("Authorization", fmt.Sprintf("Api-Key %s", fg.apiKey))
		req.Header.Set("X-API-Key", fg.apiKey)
	case "query":
		// API key already added to URL, no header needed
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "AssetDiscovery/1.0")

	resp, err := fg.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("connection error fetching %s: %v", endpoint, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		if strings.Contains(string(body), "<html>") || strings.Contains(string(body), "<!DOCTYPE") {
			return nil, fmt.Errorf("error fetching %s: %d - Authentication failed (received HTML error page)", endpoint, resp.StatusCode)
		}
		return nil, fmt.Errorf("error fetching %s: %d - %s", endpoint, resp.StatusCode, string(body))
	}

	var response scannerDomain.FortigateResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, err
	}

	if response.Status != "success" && response.Status != "" {
		return nil, fmt.Errorf("FortiGate API returned status: %s", response.Status)
	}

	return response.Results, nil
}

// ParseIPNetmask parses IP and netmask from FortiGate format
func (h *FirewallHelper) ParseIPNetmask(ipString string) (string, string) {
	if ipString == "" || ipString == "0.0.0.0 0.0.0.0" {
		return "", ""
	}

	parts := strings.Fields(ipString)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}

	return ipString, ""
}

// SanitizeMACAddress ensures MAC address fits in database column
func (h *FirewallHelper) SanitizeMACAddress(macAddr string) string {
	if macAddr == "" {
		return ""
	}

	// Check if it's a valid MAC address format
	if h.validator.ValidateMACFormat(macAddr) {
		return macAddr
	}

	// If it's too long or invalid format, return empty string
	if len(macAddr) > 17 {
		return ""
	}

	return macAddr
}

// CreateFirewallDeviceAsset creates a summary asset for the firewall device
func (h *FirewallHelper) CreateFirewallDeviceAsset(firewallIP string, scanJobID int64, zoneCount, interfaceCount, policyCount int) assetDomain.AssetDomain {
	assetID := uuid.New()

	description := fmt.Sprintf("FortiGate firewall device discovered by firewall scan (Job ID: %d). "+
		"Zones: %d, Interfaces: %d, Policies: %d", scanJobID, zoneCount, interfaceCount, policyCount)

	asset := assetDomain.AssetDomain{
		ID:          assetID,
		Name:        fmt.Sprintf("FortiGate-%s", firewallIP),
		Hostname:    fmt.Sprintf("fortigate-%s", strings.ReplaceAll(firewallIP, ".", "-")),
		Type:        "Firewall Device",
		Description: description,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		AssetIPs:    make([]assetDomain.AssetIP, 0),
	}

	// Add management IP with proper MAC address handling
	if h.validator.ValidateIPFormat(firewallIP) {
		asset.AssetIPs = append(asset.AssetIPs, assetDomain.AssetIP{
			ID:          uuid.New().String(),
			AssetID:     assetID.String(),
			InterfaceID: "", // Will be set when linked to interface
			IP:          firewallIP,
			MACAddress:  "", // Empty MAC address
		})
	}

	return asset
}

// CreateAssetFromInterface creates an asset from a firewall interface
func (h *FirewallHelper) CreateAssetFromInterface(intf scannerDomain.FortigateInterface, firewallIP string, scanJobID int64) assetDomain.AssetDomain {
	assetID := uuid.New()

	assetName := fmt.Sprintf("%s-%s", firewallIP, intf.Name)
	if intf.Description != "" {
		assetName = fmt.Sprintf("%s (%s)", assetName, intf.Description)
	}

	description := fmt.Sprintf("Firewall interface discovered by FortiGate scan (Job ID: %d). Type: %s, Status: %s",
		scanJobID, intf.Type, intf.Status)

	if intf.VDOM != "" {
		description += fmt.Sprintf(", VDOM: %s", intf.VDOM)
	}
	if intf.Role != "" {
		description += fmt.Sprintf(", Role: %s", intf.Role)
	}

	asset := assetDomain.AssetDomain{
		ID:          assetID,
		Name:        assetName,
		Hostname:    intf.Name,
		Type:        "Network Interface",
		Description: description,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		AssetIPs:    make([]assetDomain.AssetIP, 0),
	}

	// Extract and add IP addresses
	if intf.IP != "" && intf.IP != "0.0.0.0 0.0.0.0" && intf.IP != "0.0.0.0" {
		ip, _ := h.ParseIPNetmask(intf.IP)
		if ip != "" && h.validator.ValidateIPFormat(ip) {
			macAddress := h.SanitizeMACAddress(intf.MacAddr)

			asset.AssetIPs = append(asset.AssetIPs, assetDomain.AssetIP{
				ID:          uuid.New().String(),
				AssetID:     assetID.String(),
				InterfaceID: "", // Will be set when linked to interface
				IP:          ip,
				MACAddress:  macAddress,
			})
		}
	}

	// Add secondary IPs
	for _, secIP := range intf.SecondaryIP {
		if secIP.IP != "" && secIP.IP != "0.0.0.0 0.0.0.0" && secIP.IP != "0.0.0.0" {
			ip, _ := h.ParseIPNetmask(secIP.IP)
			if ip != "" && h.validator.ValidateIPFormat(ip) {
				macAddress := h.SanitizeMACAddress(intf.MacAddr)

				asset.AssetIPs = append(asset.AssetIPs, assetDomain.AssetIP{
					ID:          uuid.New().String(),
					AssetID:     assetID.String(),
					InterfaceID: "", // Will be set when linked to interface
					IP:          ip,
					MACAddress:  macAddress,
				})
			}
		}
	}

	return asset
}

// ConvertToFirewallData converts FortiGate extractor data to new firewall repository format
func (h *FirewallHelper) ConvertToFirewallData(extractor *FortigateExtractor, assetID string) scannerDomain.FirewallData {
	firewallData := scannerDomain.FirewallData{
		AssetID:    assetID,
		Zones:      make([]scannerDomain.ZoneData, 0),
		Interfaces: make([]scannerDomain.InterfaceData, 0),
		Policies:   make([]scannerDomain.PolicyData, 0),
		VLANs:      make([]scannerDomain.VLANData, 0),
	}

	// Convert zones
	for _, zone := range extractor.zones {
		if !h.validator.ValidateZoneData(zone) {
			continue
		}

		zoneData := scannerDomain.ZoneData{
			Name:        zone.Name,
			Description: zone.Description,
			Interfaces:  make([]string, 0),
		}

		// Add interfaces to zone
		for _, intf := range zone.Interface {
			if intf.InterfaceName != "" {
				zoneData.Interfaces = append(zoneData.Interfaces, intf.InterfaceName)
			} else if intf.Name != "" {
				zoneData.Interfaces = append(zoneData.Interfaces, intf.Name)
			}
		}

		firewallData.Zones = append(firewallData.Zones, zoneData)
	}

	// Create zone mapping for interface assignment
	zoneInterfaceMap := h.createZoneInterfaceMap(extractor.zones)

	// Convert interfaces
	firewallData.Interfaces = h.convertInterfaces(extractor.interfaces, zoneInterfaceMap)

	// Convert policies
	firewallData.Policies = h.convertPolicies(extractor.policies)

	// Use VLANs from API first, then generate from interfaces as fallback
	if len(extractor.vlans) > 0 {
		// Use VLANs from the system/vlan API endpoint
		firewallData.VLANs = extractor.vlans
	} else {
		// Fallback: Generate VLANs from interface names
		firewallData.VLANs = h.generateVLANsFromInterfaces(extractor.interfaces)
	}

	return firewallData
}

// createZoneInterfaceMap creates a mapping between interfaces and zones
func (h *FirewallHelper) createZoneInterfaceMap(zones []scannerDomain.FortigateZone) map[string]string {
	zoneInterfaceMap := make(map[string]string)
	for _, zone := range zones {
		for _, intf := range zone.Interface {
			interfaceName := intf.InterfaceName
			if interfaceName == "" {
				interfaceName = intf.Name
			}
			if interfaceName != "" {
				zoneInterfaceMap[interfaceName] = zone.Name
			}
		}
	}
	return zoneInterfaceMap
}

// convertInterfaces converts interface data to storage format
func (h *FirewallHelper) convertInterfaces(interfaces []scannerDomain.FortigateInterface, zoneInterfaceMap map[string]string) []scannerDomain.InterfaceData {
	var result []scannerDomain.InterfaceData

	for _, intf := range interfaces {
		if !h.validator.ValidateInterfaceData(intf) {
			continue
		}

		interfaceData := scannerDomain.InterfaceData{
			Name:         intf.Name,
			IP:           intf.IP,
			Status:       intf.Status,
			Description:  intf.Description,
			MTU:          intf.MTU,
			Speed:        intf.Speed,
			Duplex:       intf.Duplex,
			Type:         intf.Type,
			VDOM:         intf.VDOM,
			Mode:         intf.Mode,
			Role:         intf.Role,
			MacAddr:      intf.MacAddr,
			Allowaccess:  intf.Allowaccess.ToStringSlice(),
			SecondaryIPs: make([]scannerDomain.SecondaryIPData, 0),
			Zone:         zoneInterfaceMap[intf.Name],
		}

		// Convert secondary IPs
		for _, secIP := range intf.SecondaryIP {
			interfaceData.SecondaryIPs = append(interfaceData.SecondaryIPs, scannerDomain.SecondaryIPData{
				ID:          secIP.ID,
				IP:          secIP.IP,
				Allowaccess: secIP.Allowaccess.ToStringSlice(),
			})
		}

		result = append(result, interfaceData)
	}

	return result
}

// convertPolicies converts policy data to storage format
func (h *FirewallHelper) convertPolicies(policies []scannerDomain.FortigatePolicy) []scannerDomain.PolicyData {
	var result []scannerDomain.PolicyData

	for _, policy := range policies {
		if !h.validator.ValidatePolicyData(policy) {
			continue
		}

		policyData := scannerDomain.PolicyData{
			PolicyID: policy.PolicyID,
			Name:     policy.Name,
			SrcIntf:  h.extractInterfaceNames(policy.SrcIntf),
			DstIntf:  h.extractInterfaceNames(policy.DstIntf),
			SrcAddr:  h.extractAddressNames(policy.SrcAddr),
			DstAddr:  h.extractAddressNames(policy.DstAddr),
			Service:  h.extractServiceNames(policy.Service),
			Action:   policy.Action,
			Status:   policy.Status,
			Schedule: policy.Schedule,
		}

		result = append(result, policyData)
	}

	return result
}

// generateVLANsFromInterfaces generates VLAN data from interface names (fallback method)
func (h *FirewallHelper) generateVLANsFromInterfaces(interfaces []scannerDomain.FortigateInterface) []scannerDomain.VLANData {
	var result []scannerDomain.VLANData

	for _, intf := range interfaces {
		if strings.Contains(intf.Name, ".") {
			parts := strings.Split(intf.Name, ".")
			if len(parts) == 2 {
				parentInterface := parts[0]
				vlanIDStr := parts[1]

				// Try to parse VLAN ID
				var vlanID int
				if _, err := fmt.Sscanf(vlanIDStr, "%d", &vlanID); err == nil {
					vlanData := scannerDomain.VLANData{
						VLANID:          vlanID,
						VLANName:        fmt.Sprintf("VLAN_%d", vlanID),
						ParentInterface: parentInterface,
						Description:     fmt.Sprintf("VLAN %d on %s (derived from interface)", vlanID, parentInterface),
					}

					result = append(result, vlanData)
				}
			}
		}
	}

	return result
}

// Helper functions for extracting names from slices
func (h *FirewallHelper) extractInterfaceNames(interfaces []scannerDomain.FortigatePolicyInterface) []string {
	names := make([]string, len(interfaces))
	for i, intf := range interfaces {
		names[i] = intf.Name
	}
	return names
}

func (h *FirewallHelper) extractAddressNames(addresses []scannerDomain.FortigateAddress) []string {
	names := make([]string, len(addresses))
	for i, addr := range addresses {
		names[i] = addr.Name
	}
	return names
}

func (h *FirewallHelper) extractServiceNames(services []scannerDomain.FortigateService) []string {
	names := make([]string, len(services))
	for i, svc := range services {
		names[i] = svc.Name
	}
	return names
}

// MaskAPIKey masks an API key for logging
func (h *FirewallHelper) MaskAPIKey(apiKey string) string {
	if len(apiKey) <= 8 {
		return "****"
	}
	return apiKey[:4] + "****"
}

// NewFortigateExtractor creates a new FortiGate data extractor
func NewFortigateExtractor(client *FortigateClient, scanner scannerDomain.ScannerDomain, scanJobID int64) *FortigateExtractor {
	return &FortigateExtractor{
		client:     client,
		scanner:    scanner,
		scanJobID:  scanJobID,
		zones:      make([]scannerDomain.FortigateZone, 0),
		interfaces: make([]scannerDomain.FortigateInterface, 0),
		policies:   make([]scannerDomain.FortigatePolicy, 0),
		addresses:  make([]scannerDomain.FortigateAddress, 0),
		vlans:      make([]scannerDomain.VLANData, 0), // Initialize VLANs slice
	}
}

func (h *FirewallHelper) CreateFirewallDeviceAssetWithJobID(firewallIP string, scanJobID int64, zoneCount, interfaceCount, policyCount int) domain.AssetDomain {
	assetID := uuid.New()

	// Include job ID in hostname to make it unique
	hostname := fmt.Sprintf("fortigate-%s-job%d", strings.ReplaceAll(firewallIP, ".", "-"), scanJobID)

	description := fmt.Sprintf("FortiGate firewall device discovered by firewall scan (Job ID: %d). "+
		"Zones: %d, Interfaces: %d, Policies: %d", scanJobID, zoneCount, interfaceCount, policyCount)

	asset := domain.AssetDomain{
		ID:          assetID,
		Name:        fmt.Sprintf("FortiGate-%s", firewallIP),
		Hostname:    hostname, // Use unique hostname
		Type:        "Firewall Device",
		Description: description,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		AssetIPs:    make([]domain.AssetIP, 0),
	}

	// Add management IP with proper validation
	if h.validator.ValidateIPFormat(firewallIP) {
		asset.AssetIPs = append(asset.AssetIPs, domain.AssetIP{
			ID:          uuid.New().String(),
			AssetID:     assetID.String(),
			InterfaceID: "", // Will be set when linked to interface
			IP:          firewallIP,
			MACAddress:  "", // Empty MAC address
		})
	}

	return asset
}

func (h *FirewallHelper) ConvertToFirewallDataWithAssets(extractor *FortigateExtractor, assetID string, interfaceAssetMap map[string]string) scannerDomain.FirewallData {
	firewallData := h.ConvertToFirewallData(extractor, assetID)

	// Populate asset IDs in interface data
	for i := range firewallData.Interfaces {
		if assetIDStr, hasAsset := interfaceAssetMap[firewallData.Interfaces[i].Name]; hasAsset {
			firewallData.Interfaces[i].SetAssetID(assetIDStr)
		}
	}

	return firewallData
}

func (h *FirewallHelper) CreateInterfaceAssetMap(ctx context.Context, interfaces []scannerDomain.FortigateInterface,
	firewallIP string, scanJobID int64, assetRepo interface{}) (map[string]string, error) {

	interfaceAssetMap := make(map[string]string)

	// Type assertion for asset repository (you may need to adjust this based on your actual interface)
	repo, ok := assetRepo.(interface {
		Create(ctx context.Context, asset interface{}) (interface{}, error)
		LinkAssetToScanJob(ctx context.Context, assetID interface{}, scanJobID int64) error
	})
	if !ok {
		return interfaceAssetMap, fmt.Errorf("invalid asset repository type")
	}

	for _, intf := range interfaces {
		if h.ShouldCreateInterfaceAsset(intf) {
			asset := h.CreateAssetFromInterface(intf, firewallIP, scanJobID)

			assetID, err := repo.Create(ctx, asset)
			if err != nil {
				continue // Skip this interface if asset creation fails
			}

			if err := repo.LinkAssetToScanJob(ctx, assetID, scanJobID); err != nil {
				continue // Skip linking if it fails
			}

			// Convert asset ID to string (adjust based on your actual return type)
			if assetUUID, ok := assetID.(fmt.Stringer); ok {
				interfaceAssetMap[intf.Name] = assetUUID.String()
			}
		}
	}

	return interfaceAssetMap, nil
}

// ShouldCreateInterfaceAsset determines if an interface should have an asset created
func (h *FirewallHelper) ShouldCreateInterfaceAsset(intf scannerDomain.FortigateInterface) bool {
	return intf.IP != "" && intf.IP != "0.0.0.0 0.0.0.0" && intf.IP != "0.0.0.0"
}
