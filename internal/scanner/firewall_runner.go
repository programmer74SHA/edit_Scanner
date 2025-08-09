package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/domain"
	assetPort "gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/port"
	scannerDomain "gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanner/domain"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/adapter/storage"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/logger"
	"gorm.io/gorm"
)

// FirewallRunner handles executing firewall scans with new schema
// Asset creation and IP management is delegated to AssetRepo
type FirewallRunner struct {
	assetRepo     assetPort.Repo
	firewallRepo  *storage.FirewallRepo
	cancelManager *ScanCancelManager
	db            *gorm.DB
	helper        *FirewallHelper
}

// NewFirewallRunner creates a new firewall runner with repositories
func NewFirewallRunner(assetRepo assetPort.Repo, db *gorm.DB) *FirewallRunner {
	return &FirewallRunner{
		assetRepo:     assetRepo,
		firewallRepo:  storage.NewFirewallRepo(db),
		cancelManager: NewScanCancelManager(),
		db:            db,
		helper:        NewFirewallHelper(),
	}
}

// Execute implements the scheduler.Scanner interface
func (r *FirewallRunner) Execute(ctx context.Context, scanner scannerDomain.ScannerDomain, scanJobID int64) error {
	return r.ExecuteFirewallScan(ctx, scanner, scanJobID)
}

func (r *FirewallRunner) createFirewallAsset(ctx context.Context, firewallIP string, scanJobID int64) (string, error) {
	logger.InfoContext(ctx, "Creating/updating firewall device asset for IP: %s", firewallIP)

	// First, check if an asset already exists with this IP
	filter := domain.AssetFilters{IP: firewallIP}
	assets, err := r.assetRepo.Get(ctx, filter)
	if err == nil && len(assets) > 0 {
		// Found existing asset - use it directly
		existingAsset := assets[0]
		logger.InfoContext(ctx, "Found existing asset: ID=%s, Type=%s - reusing for firewall scan",
			existingAsset.ID, existingAsset.Type)

		// Ensure it's marked as a firewall device (update if needed)
		if existingAsset.Type != "Firewall Device" {
			existingAsset.Type = "Firewall Device"
			existingAsset.Name = fmt.Sprintf("FortiGate-%s", firewallIP)
			existingAsset.UpdatedAt = time.Now()
			r.assetRepo.Update(ctx, existingAsset) // Ignore errors - asset exists and that's what matters
		}

		// Link to scan job (ignore errors - not critical)
		r.assetRepo.LinkAssetToScanJob(ctx, existingAsset.ID, scanJobID)

		logger.InfoContext(ctx, "Successfully reusing existing asset: %s", existingAsset.ID)
		return existingAsset.ID.String(), nil
	}

	// No existing asset found, create new one
	assetID := uuid.New()
	timestamp := time.Now().Unix()
	hostname := fmt.Sprintf("fortigate-%s-job%d-%d", strings.ReplaceAll(firewallIP, ".", "-"), scanJobID, timestamp)

	asset := domain.AssetDomain{
		ID:           assetID,
		Name:         fmt.Sprintf("FortiGate-%s", firewallIP),
		Hostname:     hostname,
		Type:         "Firewall Device",
		Description:  fmt.Sprintf("FortiGate firewall device discovered by firewall scan (Job ID: %d, IP: %s)", scanJobID, firewallIP),
		DiscoveredBy: "Firewall Scanner", // Standardized discovery source
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
		AssetIPs:     make([]domain.AssetIP, 0),
	}

	// Add management IP if valid
	if r.helper.validator.ValidateIPFormat(firewallIP) {
		asset.AssetIPs = append(asset.AssetIPs, domain.AssetIP{
			ID:          uuid.New().String(),
			AssetID:     assetID.String(),
			InterfaceID: "", // Will be set when linked to interface
			IP:          firewallIP,
			MACAddress:  "",
		})
	}

	// Create the asset
	createdAssetID, err := r.assetRepo.Create(ctx, asset)
	if err != nil {
		return "", fmt.Errorf("failed to create firewall asset: %w", err)
	}

	// Link to scan job (ignore errors - not critical)
	r.assetRepo.LinkAssetToScanJob(ctx, createdAssetID, scanJobID)

	logger.InfoContext(ctx, "Successfully created new firewall device asset: %s", createdAssetID)
	return createdAssetID.String(), nil
}

// createInterfaceAssetsAndIPs creates assets for interfaces with IPs using AssetRepo
func (r *FirewallRunner) createInterfaceAssetsAndIPs(ctx context.Context, extractor *FortigateExtractor, scanJobID int64, firewallIP string, mainAssetID string) (int, error) {
	logger.InfoContext(ctx, "Creating interface assets and IPs for scan job ID: %d", scanJobID)

	assetsCreated := 0
	var lastError error

	// Create assets for interfaces with IP addresses using AssetRepo
	for _, intf := range extractor.interfaces {
		if r.shouldCreateInterfaceAsset(intf) {
			asset := r.helper.CreateAssetFromInterface(intf, firewallIP, scanJobID)

			assetID, err := r.assetRepo.Create(ctx, asset)
			if err != nil {
				logger.InfoContext(ctx, "Error creating interface asset for %s: %v", intf.Name, err)
				lastError = err
				continue
			}

			if err := r.assetRepo.LinkAssetToScanJob(ctx, assetID, scanJobID); err != nil {
				logger.InfoContext(ctx, "Error linking interface asset to scan job: %v", err)
				lastError = err
				continue
			}

			assetsCreated++
			logger.InfoContext(ctx, "Created interface asset: %s for interface: %s", assetID, intf.Name)
		}
	}

	logger.InfoContext(ctx, "Created %d interface assets", assetsCreated)

	// If we created at least one asset, consider it successful even if some failed
	if assetsCreated > 0 {
		return assetsCreated, nil
	}

	// If no assets were created and we have an error, return it
	if lastError != nil {
		return 0, lastError
	}

	// No assets created but no errors either
	return 0, nil
}

// shouldCreateInterfaceAsset determines if an interface should have an asset created
func (r *FirewallRunner) shouldCreateInterfaceAsset(intf scannerDomain.FortigateInterface) bool {
	return intf.IP != "" && intf.IP != "0.0.0.0 0.0.0.0" && intf.IP != "0.0.0.0"
}

// testConnection tests the connection to FortiGate with different auth methods
func (r *FirewallRunner) testConnection(ctx context.Context, client *FortigateClient) error {
	var lastErr error

	for _, auth := range scannerDomain.FortigateAuthMethods {
		client.authMethod = auth.Method

		err := r.testSingleConnection(ctx, client)
		if err == nil {
			return nil
		}
		lastErr = err
	}

	return fmt.Errorf("all authentication methods failed, last error: %w", lastErr)
}

// testSingleConnection tests a single connection attempt
func (r *FirewallRunner) testSingleConnection(ctx context.Context, client *FortigateClient) error {
	_, err := client.fetchData(ctx, "system/interface")
	if err != nil {
		return fmt.Errorf("FortiGate API test failed: %w", err)
	}
	return nil
}

// parseGenericInterface parses interface data from a generic map with flexible allowaccess handling
func (r *FirewallRunner) parseGenericInterface(ctx context.Context, intfData json.RawMessage, index int) scannerDomain.FortigateInterface {
	var genericIntf map[string]interface{}
	if err := json.Unmarshal(intfData, &genericIntf); err != nil {
		return scannerDomain.FortigateInterface{}
	}

	intf := scannerDomain.FortigateInterface{}

	// Extract basic fields
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

	// Parse allowaccess - handle both string and array
	if allowaccess, ok := genericIntf["allowaccess"]; ok {
		intf.Allowaccess = r.parseAllowAccess(allowaccess)
	}

	// Parse secondary IPs
	if secondaryips, ok := genericIntf["secondaryip"].([]interface{}); ok {
		intf.SecondaryIP = r.parseSecondaryIPs(secondaryips)
	}

	return intf
}

func (r *FirewallRunner) parseAllowAccess(allowaccess interface{}) scannerDomain.FlexibleStringArray {
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

// parseSecondaryIPs parses secondary IP data from generic interface
func (r *FirewallRunner) parseSecondaryIPs(secondaryips []interface{}) []scannerDomain.FortigateSecondaryIP {
	var result []scannerDomain.FortigateSecondaryIP

	for _, secIP := range secondaryips {
		if secIPMap, ok := secIP.(map[string]interface{}); ok {
			var secIPStruct scannerDomain.FortigateSecondaryIP
			if id, ok := secIPMap["id"].(float64); ok {
				secIPStruct.ID = int(id)
			}
			if ip, ok := secIPMap["ip"].(string); ok {
				secIPStruct.IP = ip
			}

			// Handle allowaccess for secondary IPs
			if allowaccess, ok := secIPMap["allowaccess"]; ok {
				secIPStruct.Allowaccess = r.parseAllowAccess(allowaccess)
			}

			result = append(result, secIPStruct)
		}
	}

	return result
}

// Basic validation functions (minimal validation - detailed validation should be at HTTP layer)
func (r *FirewallRunner) validateInterfaceData(intf scannerDomain.FortigateInterface) bool {
	return intf.Name != ""
}

func (r *FirewallRunner) validateZoneData(zone scannerDomain.FortigateZone) bool {
	return zone.Name != ""
}

func (r *FirewallRunner) validatePolicyData(policy scannerDomain.FortigatePolicy) bool {
	return policy.PolicyID != 0
}

// CancelScan cancels a running scan job
func (r *FirewallRunner) CancelScan(jobID int64) bool {
	return r.cancelManager.CancelScan(jobID)
}

// StatusScan checks if a scan job is currently running
func (r *FirewallRunner) StatusScan(jobID int64) bool {
	return r.cancelManager.HasActiveScan(jobID)
}

func (r *FirewallRunner) ExecuteFirewallScan(ctx context.Context, scanner scannerDomain.ScannerDomain, scanJobID int64) error {
	logger.InfoContext(ctx, "=== STARTING FIREWALL SCAN ===")
	logger.InfoContext(ctx, "Scanner ID: %d, Job ID: %d", scanner.ID, scanJobID)
	logger.InfoContext(ctx, "Scanner details: IP=%s, Port=%s, API Key length=%d",
		scanner.IP, scanner.Port, len(scanner.ApiKey))

	// Create a cancellable context
	scanCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Register this scan with the cancel manager
	r.cancelManager.RegisterScan(scanJobID, cancel)
	defer r.cancelManager.UnregisterScan(scanJobID)

	// Determine port to use (default to 443 for HTTPS)
	port := "443"
	if scanner.Port != "" {
		port = scanner.Port
	}

	// Create FortiGate client
	logger.InfoContext(ctx, "Creating FortiGate client for %s:%s", scanner.IP, port)
	client := r.helper.CreateFortigateClient(scanner.IP, port, scanner.ApiKey)

	// Test connection with multiple authentication methods
	logger.InfoContext(ctx, "Testing connection to FortiGate...")
	if err := r.testConnection(scanCtx, client); err != nil {
		logger.InfoContext(ctx, "CRITICAL: All connection tests failed: %v", err)
		return fmt.Errorf("FortiGate connection failed: %w", err)
	}

	logger.InfoContext(ctx, "✓ Successfully connected to FortiGate")

	// Create firewall asset using AssetRepo
	logger.InfoContext(ctx, "Creating firewall asset...")
	assetID, err := r.createFirewallAsset(scanCtx, scanner.IP, scanJobID)
	if err != nil {
		logger.InfoContext(ctx, "ERROR: Failed to create firewall asset: %v", err)
		return fmt.Errorf("failed to create firewall asset: %w", err)
	}

	logger.InfoContext(ctx, "✓ Created/updated firewall asset with ID: %s", assetID)

	// Create firewall extractor
	extractor := NewFortigateExtractor(client, scanner, scanJobID)

	// Load all data from FortiGate with enhanced debugging
	if err := r.loadAllData(scanCtx, extractor); err != nil {
		logger.InfoContext(ctx, "CRITICAL: Failed to load firewall data: %v", err)
		return fmt.Errorf("failed to load firewall data: %w", err)
	}

	// Convert and store data with interface asset creation
	if err := r.convertAndStoreFirewallDataWithAssets(scanCtx, extractor, assetID, scanJobID, scanner.IP); err != nil {
		return err
	}

	logger.InfoContext(ctx, "=== FIREWALL SCAN COMPLETED SUCCESSFULLY ===")
	logger.InfoContext(ctx, "Scan job ID: %d", scanJobID)

	return nil
}

func (r *FirewallRunner) convertAndStoreFirewallDataWithAssets(ctx context.Context, extractor *FortigateExtractor, assetID string, scanJobID int64, firewallIP string) error {
	// Convert FortiGate data to firewall repository format
	logger.InfoContext(ctx, "Converting extracted data to storage format...")
	firewallData := r.helper.ConvertToFirewallData(extractor, assetID)

	logger.InfoContext(ctx, "Conversion results:")
	logger.InfoContext(ctx, "- Zones: %d", len(firewallData.Zones))
	logger.InfoContext(ctx, "- Interfaces: %d", len(firewallData.Interfaces))
	logger.InfoContext(ctx, "- Policies: %d", len(firewallData.Policies))
	logger.InfoContext(ctx, "- VLANs: %d", len(firewallData.VLANs))

	if len(firewallData.Zones) == 0 && len(firewallData.Interfaces) == 0 {
		logger.InfoContext(ctx, "ERROR: No data to store after conversion!")
		return fmt.Errorf("no firewall data available after conversion")
	}

	// Create a map to store interface name -> asset ID mappings
	interfaceAssetMap := make(map[string]string)

	// Create assets for interfaces that should have assets and populate the map
	for _, intf := range extractor.interfaces {
		if r.shouldCreateInterfaceAsset(intf) {
			asset := r.helper.CreateAssetFromInterface(intf, firewallIP, scanJobID)

			interfaceAssetID, err := r.assetRepo.Create(ctx, asset)
			if err != nil {
				logger.InfoContext(ctx, "Error creating interface asset for %s: %v", intf.Name, err)
				continue
			}

			if err := r.assetRepo.LinkAssetToScanJob(ctx, interfaceAssetID, scanJobID); err != nil {
				logger.InfoContext(ctx, "Error linking interface asset to scan job: %v", err)
				continue
			}

			interfaceAssetMap[intf.Name] = interfaceAssetID.String()
			logger.InfoContext(ctx, "Created interface asset: %s for interface: %s", interfaceAssetID, intf.Name)
		}
	}

	// Store the converted data with interface asset mappings
	if err := r.firewallRepo.StoreFirewallDataWithAssets(ctx, firewallData, scanJobID, interfaceAssetMap); err != nil {
		logger.InfoContext(ctx, "ERROR: Failed to store firewall data: %v", err)
		return fmt.Errorf("failed to store firewall data: %w", err)
	}

	logger.InfoContext(ctx, "✓ Successfully stored firewall configuration data with %d interface assets", len(interfaceAssetMap))
	return nil
}

// Enhanced data loading with detailed logging and proper error handling
func (r *FirewallRunner) loadAllData(ctx context.Context, extractor *FortigateExtractor) error {
	logger.InfoContext(ctx, "=== STARTING FIREWALL DATA LOADING ===")

	// Step 1: Load zones
	logger.InfoContext(ctx, "Step 1: Loading zones...")
	if err := r.loadZones(ctx, extractor); err != nil {
		logger.InfoContext(ctx, "CRITICAL: Zone loading failed: %v", err)
		return fmt.Errorf("zone loading failed: %w", err)
	}
	logger.InfoContext(ctx, "✓ Zones loaded successfully: %d zones", len(extractor.zones))

	// Check for cancellation
	if ctx.Err() == context.Canceled {
		return context.Canceled
	}

	// Step 2: Load interfaces
	logger.InfoContext(ctx, "Step 2: Loading interfaces...")
	if err := r.loadInterfaces(ctx, extractor); err != nil {
		logger.InfoContext(ctx, "CRITICAL: Interface loading failed: %v", err)
		return fmt.Errorf("interface loading failed: %w", err)
	}
	logger.InfoContext(ctx, "✓ Interfaces loaded successfully: %d interfaces", len(extractor.interfaces))

	// Check for cancellation
	if ctx.Err() == context.Canceled {
		return context.Canceled
	}

	// Step 3: Load VLANs (NEW - from system/vlan endpoint)
	logger.InfoContext(ctx, "Step 3: Loading VLANs from system/vlan endpoint...")
	if err := r.loadVLANs(ctx, extractor); err != nil {
		logger.InfoContext(ctx, "WARNING: VLAN loading failed (will generate from interfaces): %v", err)
		// Don't return error - VLANs can be generated from interfaces
	}
	logger.InfoContext(ctx, "✓ VLANs loaded: %d VLANs", len(extractor.vlans))

	// Check for cancellation
	if ctx.Err() == context.Canceled {
		return context.Canceled
	}

	// Step 4: Load policies
	logger.InfoContext(ctx, "Step 4: Loading policies...")
	if err := r.loadPolicies(ctx, extractor); err != nil {
		logger.InfoContext(ctx, "WARNING: Policy loading failed: %v", err)
		// Don't return error - policies are not critical for basic functionality
	}
	logger.InfoContext(ctx, "✓ Policies loaded: %d policies", len(extractor.policies))

	// Step 5: Load addresses
	logger.InfoContext(ctx, "Step 5: Loading addresses...")
	if err := r.loadAddresses(ctx, extractor); err != nil {
		logger.InfoContext(ctx, "WARNING: Address loading failed: %v", err)
		// Don't return error - addresses are not critical for basic functionality
	}
	logger.InfoContext(ctx, "✓ Addresses loaded: %d addresses", len(extractor.addresses))

	logger.InfoContext(ctx, "=== DATA LOADING SUMMARY ===")
	logger.InfoContext(ctx, "Total loaded: %d zones, %d interfaces, %d VLANs, %d policies, %d addresses",
		len(extractor.zones), len(extractor.interfaces), len(extractor.vlans), len(extractor.policies), len(extractor.addresses))

	return nil
}

// Enhanced zone loading with detailed debugging
func (r *FirewallRunner) loadZones(ctx context.Context, extractor *FortigateExtractor) error {
	logger.InfoContext(ctx, "Fetching zones from FortiGate API endpoint: system/zone")

	zonesData, err := extractor.client.fetchData(ctx, "system/zone")
	if err != nil {
		logger.InfoContext(ctx, "ERROR: Failed to fetch zones from API: %v", err)
		return err
	}

	logger.InfoContext(ctx, "Raw zones data received: %d zone records", len(zonesData))

	if len(zonesData) == 0 {
		logger.InfoContext(ctx, "WARNING: No zone data returned from FortiGate API")
		return nil
	}

	validZones := 0
	for i, zoneData := range zonesData {
		var zone scannerDomain.FortigateZone
		if err := json.Unmarshal(zoneData, &zone); err != nil {
			logger.InfoContext(ctx, "ERROR: Failed to unmarshal zone %d: %v", i, err)
			logger.InfoContext(ctx, "Raw zone data: %s", string(zoneData))
			continue
		}

		logger.InfoContext(ctx, "Parsed zone %d: Name='%s', Description='%s', Interfaces=%d",
			i, zone.Name, zone.Description, len(zone.Interface))

		if r.validateZoneData(zone) {
			extractor.zones = append(extractor.zones, zone)
			validZones++
			logger.InfoContext(ctx, "✓ Zone '%s' validated and added", zone.Name)
		} else {
			logger.InfoContext(ctx, "✗ Zone %d failed validation (Name='%s')", i, zone.Name)
		}
	}

	logger.InfoContext(ctx, "Zone loading complete: %d valid zones out of %d total", validZones, len(zonesData))
	return nil
}

// Enhanced interface loading with detailed debugging
func (r *FirewallRunner) loadInterfaces(ctx context.Context, extractor *FortigateExtractor) error {
	logger.InfoContext(ctx, "Fetching interfaces from FortiGate API endpoint: system/interface")

	interfacesData, err := extractor.client.fetchData(ctx, "system/interface")
	if err != nil {
		logger.InfoContext(ctx, "ERROR: Failed to fetch interfaces from API: %v", err)
		return err
	}

	logger.InfoContext(ctx, "Raw interfaces data received: %d interface records", len(interfacesData))

	if len(interfacesData) == 0 {
		logger.InfoContext(ctx, "WARNING: No interface data returned from FortiGate API")
		return nil
	}

	validInterfaces := 0
	for i, intfData := range interfacesData {
		var intf scannerDomain.FortigateInterface
		if err := json.Unmarshal(intfData, &intf); err != nil {
			logger.InfoContext(ctx, "ERROR: Failed to unmarshal interface %d: %v", i, err)
			logger.InfoContext(ctx, "Trying generic parsing for interface %d", i)

			// Try to parse as generic map to extract basic info
			intf = r.parseGenericInterface(ctx, intfData, i)
			if intf.Name == "" {
				logger.InfoContext(ctx, "✗ Interface %d: Failed both structured and generic parsing", i)
				continue
			}
		}

		logger.InfoContext(ctx, "Parsed interface %d: Name='%s', IP='%s', Status='%s', Type='%s'",
			i, intf.Name, intf.IP, intf.Status, intf.Type)

		if r.validateInterfaceData(intf) {
			extractor.interfaces = append(extractor.interfaces, intf)
			validInterfaces++
			logger.InfoContext(ctx, "✓ Interface '%s' validated and added", intf.Name)
		} else {
			logger.InfoContext(ctx, "✗ Interface %d failed validation (Name='%s')", i, intf.Name)
		}
	}

	logger.InfoContext(ctx, "Interface loading complete: %d valid interfaces out of %d total", validInterfaces, len(interfacesData))
	return nil
}

// NEW: Enhanced VLAN loading with detailed debugging
func (r *FirewallRunner) loadVLANs(ctx context.Context, extractor *FortigateExtractor) error {
	logger.InfoContext(ctx, "Fetching VLANs from FortiGate API endpoint: system/vlan")

	vlansData, err := extractor.client.fetchData(ctx, "system/vlan")
	if err != nil {
		logger.InfoContext(ctx, "ERROR: Failed to fetch VLANs from API: %v", err)
		return err
	}

	logger.InfoContext(ctx, "Raw VLANs data received: %d VLAN records", len(vlansData))

	if len(vlansData) == 0 {
		logger.InfoContext(ctx, "WARNING: No VLAN data returned from FortiGate API")
		return nil
	}

	validVLANs := 0
	for i, vlanData := range vlansData {
		// Using the FortigateVLAN struct from firewall_extractor.go
		var vlan struct {
			VLANID      int    `json:"vlanid"`
			Name        string `json:"name"`
			Description string `json:"description"`
			Interface   string `json:"interface"`
			Status      string `json:"status"`
		}

		if err := json.Unmarshal(vlanData, &vlan); err != nil {
			logger.InfoContext(ctx, "ERROR: Failed to unmarshal VLAN %d: %v", i, err)
			logger.InfoContext(ctx, "Raw VLAN data: %s", string(vlanData))
			continue
		}

		logger.InfoContext(ctx, "Parsed VLAN %d: ID=%d, Name='%s', Interface='%s', Status='%s'",
			i, vlan.VLANID, vlan.Name, vlan.Interface, vlan.Status)

		if vlan.VLANID > 0 && vlan.Interface != "" {
			vlanDomain := scannerDomain.VLANData{
				VLANID:          vlan.VLANID,
				VLANName:        vlan.Name,
				ParentInterface: vlan.Interface,
				Description:     vlan.Description,
			}

			extractor.vlans = append(extractor.vlans, vlanDomain)
			validVLANs++
			logger.InfoContext(ctx, "✓ VLAN %d ('%s') validated and added", vlan.VLANID, vlan.Name)
		} else {
			logger.InfoContext(ctx, "✗ VLAN %d failed validation (ID=%d, Interface='%s')", i, vlan.VLANID, vlan.Interface)
		}
	}

	logger.InfoContext(ctx, "VLAN loading complete: %d valid VLANs out of %d total", validVLANs, len(vlansData))
	return nil
}

// Enhanced policy loading with detailed debugging
func (r *FirewallRunner) loadPolicies(ctx context.Context, extractor *FortigateExtractor) error {
	logger.InfoContext(ctx, "Fetching policies from FortiGate API endpoint: firewall/policy")

	policiesData, err := extractor.client.fetchData(ctx, "firewall/policy")
	if err != nil {
		logger.InfoContext(ctx, "ERROR: Failed to fetch policies from API: %v", err)
		return err
	}

	logger.InfoContext(ctx, "Raw policies data received: %d policy records", len(policiesData))

	if len(policiesData) == 0 {
		logger.InfoContext(ctx, "WARNING: No policy data returned from FortiGate API")
		return nil
	}

	validPolicies := 0
	for i, policyData := range policiesData {
		var policy scannerDomain.FortigatePolicy
		if err := json.Unmarshal(policyData, &policy); err != nil {
			logger.InfoContext(ctx, "ERROR: Failed to unmarshal policy %d: %v", i, err)
			continue
		}

		logger.InfoContext(ctx, "Parsed policy %d: ID=%d, Name='%s', Action='%s', Status='%s'",
			i, policy.PolicyID, policy.Name, policy.Action, policy.Status)

		if r.validatePolicyData(policy) {
			extractor.policies = append(extractor.policies, policy)
			validPolicies++
			logger.InfoContext(ctx, "✓ Policy ID %d validated and added", policy.PolicyID)
		} else {
			logger.InfoContext(ctx, "✗ Policy %d failed validation (PolicyID=%d)", i, policy.PolicyID)
		}
	}

	logger.InfoContext(ctx, "Policy loading complete: %d valid policies out of %d total", validPolicies, len(policiesData))
	return nil
}

// Enhanced address loading with detailed debugging
func (r *FirewallRunner) loadAddresses(ctx context.Context, extractor *FortigateExtractor) error {
	logger.InfoContext(ctx, "Fetching addresses from FortiGate API endpoint: firewall/address")

	addressesData, err := extractor.client.fetchData(ctx, "firewall/address")
	if err != nil {
		logger.InfoContext(ctx, "ERROR: Failed to fetch addresses from API: %v", err)
		return err
	}

	logger.InfoContext(ctx, "Raw addresses data received: %d address records", len(addressesData))

	if len(addressesData) == 0 {
		logger.InfoContext(ctx, "WARNING: No address data returned from FortiGate API")
		return nil
	}

	validAddresses := 0
	for i, addrData := range addressesData {
		var addr scannerDomain.FortigateAddress
		if err := json.Unmarshal(addrData, &addr); err != nil {
			logger.InfoContext(ctx, "ERROR: Failed to unmarshal address %d: %v", i, err)
			continue
		}

		logger.InfoContext(ctx, "Parsed address %d: Name='%s', Subnet='%s', Type='%s'",
			i, addr.Name, addr.Subnet, addr.Type)

		extractor.addresses = append(extractor.addresses, addr)
		validAddresses++
		logger.InfoContext(ctx, "✓ Address '%s' added", addr.Name)
	}

	logger.InfoContext(ctx, "Address loading complete: %d valid addresses out of %d total", validAddresses, len(addressesData))
	return nil
}
