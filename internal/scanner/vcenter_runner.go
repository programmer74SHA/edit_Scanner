package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/vmware/govmomi"
	"github.com/vmware/govmomi/find"
	"github.com/vmware/govmomi/object"
	"github.com/vmware/govmomi/property"
	"github.com/vmware/govmomi/session"
	"github.com/vmware/govmomi/vim25"
	"github.com/vmware/govmomi/vim25/mo"
	"github.com/vmware/govmomi/vim25/soap"
	"github.com/vmware/govmomi/vim25/types"

	assetDomain "gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/domain"
	assetPort "gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/port"
	scannerDomain "gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanner/domain"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/logger"
)

// VCenterRunner handles executing vCenter scans
type VCenterRunner struct {
	assetRepo     assetPort.Repo
	cancelManager *ScanCancelManager
}

// NewVCenterRunner creates a new vCenter runner with asset repository
func NewVCenterRunner(assetRepo assetPort.Repo) *VCenterRunner {
	return &VCenterRunner{
		assetRepo:     assetRepo,
		cancelManager: NewScanCancelManager(),
	}
}

// Execute implements the scheduler.Scanner interface
func (r *VCenterRunner) Execute(ctx context.Context, scanner scannerDomain.ScannerDomain, scanJobID int64) error {
	return r.ExecuteVCenterScan(ctx, scanner, scanJobID)
}

// ExecuteVCenterScan runs a vCenter scan based on scanner configuration
func (r *VCenterRunner) ExecuteVCenterScan(ctx context.Context, scanner scannerDomain.ScannerDomain, scanJobID int64) error {
	logger.InfoContext(ctx, "[VCenterScanner] Starting vCenter scan for scanner ID: %d, job ID: %d", scanner.ID, scanJobID)
	logger.InfoContext(ctx, "[VCenterScanner] Scanner details: IP=%s, Port=%s, Username=%s",
		scanner.IP, scanner.Port, scanner.Username)

	// Create a cancellable context
	scanCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Register this scan with the cancel manager
	r.cancelManager.RegisterScan(scanJobID, cancel)
	defer r.cancelManager.UnregisterScan(scanJobID)

	// Build the vCenter connection URL
	vcenterURL := &url.URL{
		Scheme: "https",
		Host:   fmt.Sprintf("%s:%s", scanner.IP, scanner.Port),
		Path:   "/sdk",
	}

	// Set credentials
	vcenterURL.User = url.UserPassword(scanner.Username, scanner.Password)

	logger.InfoContext(ctx, "[VCenterScanner] Connecting to vCenter at: %s (without credentials)",
		fmt.Sprintf("https://%s:%s/sdk", scanner.IP, scanner.Port))

	// Set insecure flag to true to bypass certificate verification (for self-signed certs)
	insecure := true

	// Try to create a client with the standard method first
	client, err := govmomi.NewClient(scanCtx, vcenterURL, insecure)
	if err != nil {
		logger.InfoContext(ctx, "[VCenterScanner] Error connecting to vCenter using NewClient: %v", err)
		logger.InfoContext(ctx, "[VCenterScanner] Trying alternative connection method...")

		// Configure SOAP client with appropriate TLS settings
		soapClient := soap.NewClient(vcenterURL, insecure)
		soapClient.Timeout = time.Minute * 5

		// Create vim25 client
		vim25Client, err := vim25.NewClient(scanCtx, soapClient)
		if err != nil {
			logger.InfoContext(ctx, "[VCenterScanner] Error creating vim25 client: %v", err)
			return fmt.Errorf("vim25 client creation error: %w", err)
		}

		// Create govmomi client using the vim25 client
		client = &govmomi.Client{
			Client:         vim25Client,
			SessionManager: session.NewManager(vim25Client),
		}

		// Login
		err = client.Login(scanCtx, vcenterURL.User)
		if err != nil {
			logger.InfoContext(ctx, "[VCenterScanner] Login failed: %v", err)
			return fmt.Errorf("vCenter login error: %w", err)
		}
	}

	// Be sure to logout when done
	defer func() {
		logger.InfoContext(ctx, "[VCenterScanner] Logging out of vCenter")
		if logoutErr := client.Logout(context.Background()); logoutErr != nil {
			logger.InfoContext(ctx, "[VCenterScanner] Warning: Logout failed: %v", logoutErr)
		}
	}()

	// Print session info for logging purposes
	userSession, err := client.SessionManager.UserSession(scanCtx)
	if err != nil {
		logger.InfoContext(ctx, "[VCenterScanner] Unable to get session: %v", err)
		return fmt.Errorf("session retrieval error: %w", err)
	}
	logger.InfoContext(ctx, "[VCenterScanner] Successfully logged in to vCenter %s as: %s", scanner.IP, userSession.UserName)
	logger.InfoContext(ctx, "[VCenterScanner] Session details: FullName='%s', LoginTime='%v'",
		userSession.FullName, userSession.LoginTime)

	// Check if the context was cancelled
	if scanCtx.Err() == context.Canceled {
		logger.InfoContext(ctx, "[VCenterScanner] vCenter scan was cancelled for job ID: %d", scanJobID)
		return context.Canceled
	}

	// Create finder and get default datacenter
	finder := find.NewFinder(client.Client, true)

	// List all datacenters
	dcs, err := finder.DatacenterList(scanCtx, "*")
	if err != nil {
		logger.InfoContext(ctx, "[VCenterScanner] Error finding datacenters: %v", err)
		return fmt.Errorf("datacenter listing error: %w", err)
	}

	logger.InfoContext(ctx, "[VCenterScanner] Found %d datacenter(s)", len(dcs))

	// Process each datacenter and collect infrastructure data
	for i, dc := range dcs {
		logger.InfoContext(ctx, "[VCenterScanner] Processing datacenter %d: %s", i+1, dc.Name())
		finder.SetDatacenter(dc)

		// Process datacenter entity first and get the database UUID
		datacenterDatabaseID, err := r.processDatacenter(scanCtx, client, dc, scanner.IP)
		if err != nil {
			logger.InfoContext(ctx, "[VCenterScanner] Error processing datacenter %s: %v", dc.Name(), err)
			// Continue with next datacenter
			continue
		}

		// Use the database UUID for foreign key relationships
		logger.InfoContext(ctx, "[VCenterScanner] Using datacenter database ID: %s", datacenterDatabaseID)

		// Process clusters in this datacenter first
		if err := r.processClusters(scanCtx, client, finder, datacenterDatabaseID, scanner.IP); err != nil {
			logger.InfoContext(ctx, "[VCenterScanner] Error processing clusters in datacenter %s: %v", dc.Name(), err)
			// Continue processing other entities
		}

		// Process datastores in this datacenter (before hosts so they can reference them)
		if err := r.processDatastores(scanCtx, client, finder, datacenterDatabaseID, scanner.IP); err != nil {
			logger.InfoContext(ctx, "[VCenterScanner] Error processing datastores in datacenter %s: %v", dc.Name(), err)
			// Continue processing other entities
		}

		// Process hosts in this datacenter
		if err := r.processHosts(scanCtx, client, finder, datacenterDatabaseID, scanner.IP); err != nil {
			logger.InfoContext(ctx, "[VCenterScanner] Error processing hosts in datacenter %s: %v", dc.Name(), err)
			// Continue processing other entities
		}

		// Process networks in this datacenter
		if err := r.processNetworks(scanCtx, client, finder, datacenterDatabaseID, scanner.IP); err != nil {
			logger.InfoContext(ctx, "[VCenterScanner] Error processing networks in datacenter %s: %v", dc.Name(), err)
			// Continue processing other entities
		}

		// Find all VMs in this datacenter
		vms, err := finder.VirtualMachineList(scanCtx, "*")
		if err != nil {
			logger.InfoContext(ctx, "[VCenterScanner] Error listing VMs in datacenter %s: %v", dc.Name(), err)
			// Continue with next datacenter
			continue
		}

		logger.InfoContext(ctx, "[VCenterScanner] Found %d VMs in datacenter %s", len(vms), dc.Name())

		// Create a property collector for efficient retrieval of VM properties
		pc := property.DefaultCollector(client.Client)
		var vmRefs []types.ManagedObjectReference
		for _, vm := range vms {
			vmRefs = append(vmRefs, vm.Reference())
		}

		// Define properties to retrieve
		var vmProps []mo.VirtualMachine
		err = pc.Retrieve(scanCtx, vmRefs, []string{"summary", "guest", "config", "runtime", "storage"}, &vmProps)
		if err != nil {
			logger.InfoContext(ctx, "[VCenterScanner] Error retrieving properties for VMs: %v", err)
			return fmt.Errorf("VM property retrieval error: %w", err)
		}

		// Process the VM list and store as assets
		for i, vmProp := range vmProps {
			// Check for cancellation periodically
			if i%10 == 0 && scanCtx.Err() == context.Canceled {
				logger.InfoContext(ctx, "[VCenterScanner] vCenter scan was cancelled during VM processing for job ID: %d", scanJobID)
				return context.Canceled
			}

			// Process this VM
			if err := r.processVM(scanCtx, client, vmProp, scanJobID, scanner.IP); err != nil {
				logger.InfoContext(ctx, "[VCenterScanner] Error processing VM %s: %v", vmProp.Name, err)
				// Continue with other VMs
			}
		}
	}

	logger.InfoContext(ctx, "[VCenterScanner] Completed vCenter scan for scanner ID: %d, job ID: %d", scanner.ID, scanJobID)
	return nil
}

// Helper function to extract OS name and version from the full OS string
func extractOSInfo(fullOSName string) (osName string, osVersion string) {
	logger.Info("[VCenterScanner] Extracting OS info from: %s", fullOSName)

	// Default values
	osName = fullOSName
	osVersion = ""

	// Common patterns:
	// Windows: "Microsoft Windows Server 2019 (64-bit)" or "Microsoft Windows 10 (64-bit)"
	// Linux: "Debian GNU/Linux 10 (64-bit)" or "Ubuntu Linux (64-bit)" or "CentOS 7 (64-bit)"
	// macOS: "macOS 12.3 (64-bit)"

	// Remove architecture info
	cleanName := fullOSName
	if idx := strings.Index(cleanName, "(64-bit)"); idx > 0 {
		cleanName = strings.TrimSpace(cleanName[:idx])
	} else if idx := strings.Index(cleanName, "(32-bit)"); idx > 0 {
		cleanName = strings.TrimSpace(cleanName[:idx])
	}

	// Extract OS family and version for different OS types
	switch {
	case strings.Contains(cleanName, "Windows"):
		osName = "Windows"

		// Handle Windows Server specifically
		if strings.Contains(cleanName, "Server") {
			osName = "Windows Server"

			// Extract version: Windows Server 2019, 2016, 2012, etc.
			parts := strings.Fields(cleanName)
			for _, part := range parts {
				if part == "2008" || part == "2012" || part == "2016" || part == "2019" || part == "2022" {
					osVersion = part
					break
				}
			}
		} else {
			// Extract version: Windows 10, 11, etc.
			parts := strings.Fields(cleanName)
			for _, part := range parts {
				if part == "7" || part == "8" || part == "8.1" || part == "10" || part == "11" {
					osVersion = part
					break
				}
			}
		}

	case strings.Contains(cleanName, "CentOS"):
		osName = "CentOS"
		parts := strings.Fields(cleanName)
		for _, part := range parts {
			if len(part) > 0 && (part[0] >= '0' && part[0] <= '9') {
				osVersion = part
				break
			}
		}

	case strings.Contains(cleanName, "Red Hat") || strings.Contains(cleanName, "RedHat") || strings.Contains(cleanName, "RHEL"):
		osName = "Red Hat Enterprise Linux"
		parts := strings.Fields(cleanName)
		for _, part := range parts {
			if len(part) > 0 && (part[0] >= '0' && part[0] <= '9') {
				osVersion = part
				break
			}
		}

	case strings.Contains(cleanName, "Ubuntu"):
		osName = "Ubuntu"
		parts := strings.Fields(cleanName)
		for _, part := range parts {
			// Check for patterns like "20.04" or "18.04"
			if strings.Contains(part, ".") && len(part) > 0 && (part[0] >= '0' && part[0] <= '9') {
				osVersion = part
				break
			}
		}

	case strings.Contains(cleanName, "Debian"):
		osName = "Debian"
		parts := strings.Fields(cleanName)
		for _, part := range parts {
			if len(part) > 0 && (part[0] >= '0' && part[0] <= '9') {
				osVersion = part
				break
			}
		}

	case strings.Contains(cleanName, "SUSE") || strings.Contains(cleanName, "SuSE"):
		osName = "SUSE Linux"
		parts := strings.Fields(cleanName)
		for _, part := range parts {
			if len(part) > 0 && (part[0] >= '0' && part[0] <= '9') {
				osVersion = part
				break
			}
		}

	case strings.Contains(cleanName, "macOS") || strings.Contains(cleanName, "Mac OS"):
		osName = "macOS"
		parts := strings.Fields(cleanName)
		for _, part := range parts {
			if strings.Contains(part, ".") && len(part) > 0 && (part[0] >= '0' && part[0] <= '9') {
				osVersion = part
				break
			}
		}
	}

	if osVersion == "" {
		// Try a general approach to extract version numbers if specific patterns didn't work
		for _, part := range strings.Fields(cleanName) {
			// Look for numbers or numbers with dots (like 10.15)
			if strings.ContainsAny(part, "0123456789") &&
				(len(part) <= 5 || strings.Contains(part, ".")) {
				osVersion = part
				break
			}
		}
	}

	logger.Info("[VCenterScanner] Extracted OS Name: %s, Version: %s", osName, osVersion)
	return osName, osVersion
}

// Helper function to extract MAC addresses from VM hardware configuration
func extractMACAddresses(vm mo.VirtualMachine) map[string]string {
	deviceToMAC := make(map[string]string)

	if vm.Config == nil || vm.Config.Hardware.Device == nil {
		return deviceToMAC
	}

	// Process each device in the VM configuration
	for _, device := range vm.Config.Hardware.Device {
		// Try to convert to network device
		if nic, ok := device.(types.BaseVirtualEthernetCard); ok {
			card := nic.GetVirtualEthernetCard()
			if card.MacAddress != "" {
				deviceKey := fmt.Sprintf("%d", card.Key)
				deviceToMAC[deviceKey] = card.MacAddress
				logger.Info("[VCenterScanner] Found MAC address %s for device key %s", card.MacAddress, deviceKey)
			}
		}
	}

	return deviceToMAC
}

// processVM processes a single VM and stores it as an asset
func (r *VCenterRunner) processVM(ctx context.Context, client *govmomi.Client, vm mo.VirtualMachine, scanJobID int64, vcenterServer string) error {
	// Validate VM name first
	vmName := strings.TrimSpace(vm.Name)
	if vmName == "" {
		logger.InfoContext(ctx, "[VCenterScanner] ERROR: VM has empty name, trying to get from Config")
		if vm.Config != nil && vm.Config.Name != "" {
			vmName = strings.TrimSpace(vm.Config.Name)
			logger.InfoContext(ctx, "[VCenterScanner] Using name from Config: %s", vmName)
		} else {
			logger.InfoContext(ctx, "[VCenterScanner] ERROR: VM still has empty name even from Config, skipping")
			return fmt.Errorf("VM has empty name")
		}
	}

	logger.InfoContext(ctx, "[VCenterScanner] Processing VM: '%s' (length: %d)", vmName, len(vmName))

	// We'll collect IP addresses from all network interfaces
	var ipAddresses []string
	var hostname string

	// Extract guest info
	if vm.Guest != nil {
		hostname = vm.Guest.HostName
		logger.InfoContext(ctx, "[VCenterScanner] VM %s - Guest hostname: %s", vmName, hostname)

		// Primary IP
		if vm.Guest.IpAddress != "" {
			ipAddresses = append(ipAddresses, vm.Guest.IpAddress)
			logger.InfoContext(ctx, "[VCenterScanner] VM %s - Primary IP: %s", vmName, vm.Guest.IpAddress)
		}

		// Additional IPs from network interfaces
		if vm.Guest.Net != nil {
			for _, net := range vm.Guest.Net {
				logger.InfoContext(ctx, "[VCenterScanner] VM %s - Network adapter: %s", vmName, net.Network)
				for _, ip := range net.IpAddress {
					// Check if this IP is already in our list
					alreadyAdded := false
					for _, existingIP := range ipAddresses {
						if existingIP == ip {
							alreadyAdded = true
							break
						}
					}

					if !alreadyAdded {
						// Skip IPv6 addresses (optional - remove if you want IPv6)
						if strings.Contains(ip, ":") {
							logger.InfoContext(ctx, "[VCenterScanner] VM %s - Skipping IPv6 address: %s", vmName, ip)
							continue
						}

						ipAddresses = append(ipAddresses, ip)
						logger.InfoContext(ctx, "[VCenterScanner] VM %s - Additional IP: %s", vmName, ip)
					}
				}
			}
		}
	}

	// Use name as hostname if guest hostname is not available
	if hostname == "" {
		hostname = vmName
		logger.InfoContext(ctx, "[VCenterScanner] VM %s - Using VM name as hostname", vmName)
	}

	// Get power state
	powerState := "Off"
	if vm.Runtime.PowerState == "poweredOn" {
		powerState = "On"
	} else if vm.Runtime.PowerState == "suspended" {
		powerState = "Suspended"
	}
	logger.InfoContext(ctx, "[VCenterScanner] VM %s - Power state: %s", vmName, powerState)

	// Get OS info
	var fullOSName string
	if vm.Guest != nil && vm.Guest.GuestFullName != "" {
		fullOSName = vm.Guest.GuestFullName
		logger.InfoContext(ctx, "[VCenterScanner] VM %s - OS (from Guest): %s", vmName, fullOSName)
	} else if vm.Config != nil && vm.Config.GuestFullName != "" {
		fullOSName = vm.Config.GuestFullName
		logger.InfoContext(ctx, "[VCenterScanner] VM %s - OS (from Config): %s", vmName, fullOSName)
	} else {
		fullOSName = "Unknown"
	}

	// Extract OS name and version
	osName, osVersion := extractOSInfo(fullOSName)
	logger.InfoContext(ctx, "[VCenterScanner] VM %s - Parsed OS: %s, Version: %s", vmName, osName, osVersion)

	// Create a new asset record
	assetID := uuid.New()
	asset := assetDomain.AssetDomain{
		ID:           assetID,
		Name:         vmName, // Use the validated VM name
		Hostname:     hostname,
		OSName:       osName,
		OSVersion:    osVersion,
		Type:         "VM", // Standardized asset type
		Description:  fmt.Sprintf("VMware virtual machine discovered by vCenter scan (Job ID: %d)", scanJobID),
		DiscoveredBy: "Vcenter", // Standardized discovery source
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
		AssetIPs:     make([]assetDomain.AssetIP, 0), // Initialize AssetIPs
	}

	// Validate that Name is set before continuing
	if asset.Name == "" {
		logger.InfoContext(ctx, "[VCenterScanner] ERROR: Asset name is empty after setting, this shouldn't happen!")
		return fmt.Errorf("asset name is empty")
	}

	// Get MAC addresses from hardware configuration
	macAddresses := extractMACAddresses(vm)

	// Create a map to associate MAC addresses with IPs from Guest.Net
	macToIPs := make(map[string][]string)
	deviceToMAC := make(map[string]string)

	// First pass: collect all MAC addresses and their associated IPs from Guest.Net
	if vm.Guest.Net != nil {
		for _, net := range vm.Guest.Net {
			if net.MacAddress != "" {
				logger.InfoContext(ctx, "[VCenterScanner] VM %s - Network adapter: %s, MAC: %s", vmName, net.Network, net.MacAddress)

				// Store MAC address
				for _, ip := range net.IpAddress {
					// Skip IPv6 addresses if that's still desired
					if strings.Contains(ip, ":") {
						continue
					}
					macToIPs[net.MacAddress] = append(macToIPs[net.MacAddress], ip)
				}
			}

			// Also map device key to MAC address for correlating with hardware config
			if net.DeviceConfigId > 0 {
				deviceKey := fmt.Sprintf("%d", net.DeviceConfigId)
				if mac, exists := macAddresses[deviceKey]; exists {
					deviceToMAC[deviceKey] = mac
				}
			}
		}
	}

	// Now add each IP with its corresponding MAC address
	for _, ip := range ipAddresses {
		mac := ""

		// First try to find the MAC address for this IP from Guest.Net
		for macAddr, ips := range macToIPs {
			for _, macIP := range ips {
				if macIP == ip {
					mac = macAddr
					break
				}
			}
			if mac != "" {
				break
			}
		}

		// If MAC not found and this is the primary IP, try the hardware configuration
		if mac == "" && ip == vm.Guest.IpAddress && vm.Guest.Net != nil && len(vm.Guest.Net) > 0 {
			// Use MAC from first network adapter as fallback for primary IP
			if vm.Guest.Net[0].MacAddress != "" {
				mac = vm.Guest.Net[0].MacAddress
			} else if vm.Guest.Net[0].DeviceConfigId > 0 {
				deviceKey := fmt.Sprintf("%d", vm.Guest.Net[0].DeviceConfigId)
				if hwMac, exists := macAddresses[deviceKey]; exists {
					mac = hwMac
				}
			}
		}

		asset.AssetIPs = append(asset.AssetIPs, assetDomain.AssetIP{
			AssetID:    asset.ID.String(),
			IP:         ip,
			MACAddress: mac,
		})

		if mac != "" {
			logger.InfoContext(ctx, "[VCenterScanner] VM %s - Added IP: %s with MAC: %s", vmName, ip, mac)
		} else {
			logger.InfoContext(ctx, "[VCenterScanner] VM %s - Added IP: %s (no MAC available)", vmName, ip)
		}
	}

	logger.InfoContext(ctx, "[VCenterScanner] Creating asset for VM '%s' with ID %s and %d IPs (Name field: '%s')",
		vmName, assetID, len(asset.AssetIPs), asset.Name)

	// Log the asset details before storing
	logger.InfoContext(ctx, "[VCenterScanner] Asset to be stored - Name: '%s', Hostname: '%s', Type: '%s'",
		asset.Name, asset.Hostname, asset.Type)
	// Update the processVM method in vcenter_runner.go

	// Store the asset with scanner type information
	var err error
	var storedAssetID assetDomain.AssetUUID
	var isNewAsset bool = true

	// We'll retry a few times in case of transient issues
	for retries := 0; retries < 3; retries++ {
		logger.InfoContext(ctx, "[VCenterScanner] Attempting to create asset (retry %d) - Name: '%s'", retries, asset.Name)
		storedAssetID, err = r.assetRepo.Create(ctx, asset, "VCENTER")
		if err == nil {
			isNewAsset = true
			logger.InfoContext(ctx, "[VCenterScanner] Successfully created new asset with ID: %s, Name: '%s', discovered by VCENTER", storedAssetID, asset.Name)
			break
		}

		// Check if it's a duplicate error (asset may already exist)
		if strings.Contains(err.Error(), "Duplicate") {
			logger.InfoContext(ctx, "[VCenterScanner] VM %s - Duplicate asset, searching for existing asset", vm.Name)

			// Try to find the existing asset by hostname or IP
			filter := assetDomain.AssetFilters{
				Hostname: hostname,
			}

			// If we have IPs, search by the first one
			if len(ipAddresses) > 0 && ipAddresses[0] != "" {
				filter.IP = ipAddresses[0]
			}

			existingAssets, err := r.assetRepo.Get(ctx, filter)
			if err == nil && len(existingAssets) > 0 {
				// Update the existing asset with new information
				existingAsset := existingAssets[0]
				storedAssetID = existingAsset.ID
				isNewAsset = false

				logger.InfoContext(ctx, "[VCenterScanner] VM %s - Found existing asset with ID: %s, current name: '%s'",
					vmName, storedAssetID, existingAsset.Name)

				// Update the existing asset with the latest information and append VCENTER to discovered_by
				existingAsset.Name = vmName // Use the validated VM name
				existingAsset.Hostname = hostname
				existingAsset.OSName = osName
				existingAsset.OSVersion = osVersion
				existingAsset.Type = "Virtual"

				vCenterDescription := fmt.Sprintf("VMware virtual machine discovered by vCenter scan (Job ID: %d)", scanJobID)
				if !strings.Contains(existingAsset.Description, "VMware virtual machine discovered by vCenter scan") {
					existingAsset.Description = vCenterDescription
				}

				existingAsset.UpdatedAt = time.Now()
				existingAsset.AssetIPs = asset.AssetIPs // Update IP addresses

				// Update discovered_by field
				if existingAsset.DiscoveredBy == "" {
					existingAsset.DiscoveredBy = "VCENTER"
				} else if !strings.Contains(existingAsset.DiscoveredBy, "VCENTER") {
					existingAsset.DiscoveredBy = existingAsset.DiscoveredBy + ", VCENTER"
				}

				logger.InfoContext(ctx, "[VCenterScanner] VM %s - Updating asset with Name='%s', Hostname='%s', DiscoveredBy='%s'",
					vmName, existingAsset.Name, existingAsset.Hostname, existingAsset.DiscoveredBy)

				// Update the asset in the database
				err = r.assetRepo.Update(ctx, existingAsset)
				if err != nil {
					logger.InfoContext(ctx, "[VCenterScanner] VM %s - Error updating existing asset: %v", vmName, err)
					// Continue with retry
				} else {
					logger.InfoContext(ctx, "[VCenterScanner] VM %s - Successfully updated existing asset with ID: %s (Name: '%s', DiscoveredBy: '%s')",
						vmName, storedAssetID, existingAsset.Name, existingAsset.DiscoveredBy)
					break
				}
			}

			// If we couldn't find or update an existing asset, try with a new ID
			assetID = uuid.New()
			asset.ID = assetID
			logger.InfoContext(ctx, "[VCenterScanner] VM %s - Retrying with new asset ID: %s", vm.Name, assetID)
		} else {
			// Some other error
			logger.InfoContext(ctx, "[VCenterScanner] Error creating asset for VM %s: %v", vm.Name, err)
			time.Sleep(500 * time.Millisecond) // Brief pause before retry
		}
	}

	if err != nil && !isNewAsset {
		logger.InfoContext(ctx, "[VCenterScanner] Failed to create or update asset after retries: %v", err)
		return err
	}

	// Ensure we have a valid asset ID before linking
	if storedAssetID.String() == "00000000-0000-0000-0000-000000000000" {
		logger.InfoContext(ctx, "[VCenterScanner] Asset ID is null UUID, cannot link to scan job: %s", vm.Name)
		return fmt.Errorf("asset ID is null UUID for VM %s", vm.Name)
	}

	// Link the asset to the scan job
	err = r.assetRepo.LinkAssetToScanJob(ctx, storedAssetID, scanJobID)
	if err != nil {
		logger.InfoContext(ctx, "[VCenterScanner] Error linking asset to scan job: %v", err)
		// Non-fatal error, continue processing
	}

	// Get hardware info
	var cpuCount int32 = 0
	var memoryMB int32 = 0
	var totalDiskGB int = 0

	if vm.Config != nil && vm.Config.Hardware.NumCPU > 0 {
		cpuCount = vm.Config.Hardware.NumCPU
		memoryMB = vm.Config.Hardware.MemoryMB

		logger.InfoContext(ctx, "[VCenterScanner] VM %s - Hardware: CPU=%d, Memory=%d MB",
			vm.Name, cpuCount, memoryMB)
	}

	// Calculate total disk size
	if vm.Storage != nil {
		var totalStorage int64
		for _, usage := range vm.Storage.PerDatastoreUsage {
			totalStorage += usage.Committed + usage.Uncommitted
		}
		totalDiskGB = int(totalStorage / (1024 * 1024 * 1024))
		logger.InfoContext(ctx, "[VCenterScanner] VM %s - Total disk size: %d GB", vm.Name, totalDiskGB)
	}

	// Get hypervisor info and host ID
	hypervisor := "VMware vSphere"
	var hostID *string
	var clusterID *string
	if vm.Runtime.Host != nil {
		vSphereHostRef := vm.Runtime.Host.Value

		// Look up the database UUID for this host
		if hostDatabaseID, err := r.assetRepo.GetVCenterHostID(ctx, vSphereHostRef, vcenterServer); err == nil && hostDatabaseID != "" {
			hostID = &hostDatabaseID
			logger.InfoContext(ctx, "[VCenterScanner] VM %s - Found host database ID: %s for vSphere host: %s", vm.Name, hostDatabaseID, vSphereHostRef)
		} else {
			logger.InfoContext(ctx, "[VCenterScanner] VM %s - Could not find database ID for host %s: %v", vm.Name, vSphereHostRef, err)
		}

		var host mo.HostSystem
		err := client.RetrieveOne(ctx, *vm.Runtime.Host, []string{"config.product", "parent"}, &host)
		if err == nil && host.Config != nil {
			hypervisor = fmt.Sprintf("%s %s (Build %s)",
				host.Config.Product.Name,
				host.Config.Product.Version,
				host.Config.Product.Build)
			if hostID != nil {
				logger.InfoContext(ctx, "[VCenterScanner] VM %s - Hypervisor: %s, Host Database ID: %s", vm.Name, hypervisor, *hostID)
			}

			// Get cluster ID if host is in a cluster
			if host.Parent != nil && host.Parent.Type == "ClusterComputeResource" {
				if clusterDatabaseID, err := r.assetRepo.GetVCenterClusterID(ctx, host.Parent.Value, vcenterServer); err == nil && clusterDatabaseID != "" {
					clusterID = &clusterDatabaseID
					logger.InfoContext(ctx, "[VCenterScanner] VM %s - Found cluster database ID: %s", vm.Name, clusterDatabaseID)
				}
			}
		}
	}

	// Create VMware VM record with validated VM name and host relationship
	vmRecord := assetDomain.VMwareVM{
		VMID:         vm.Config.InstanceUuid,
		AssetID:      storedAssetID.String(),
		VMName:       vmName,    // Use the validated VM name
		HostID:       hostID,    // Link to host
		ClusterID:    clusterID, // Link to cluster
		Hypervisor:   hypervisor,
		CPUCount:     cpuCount,
		MemoryMB:     memoryMB,
		DiskSizeGB:   totalDiskGB,
		PowerState:   powerState,
		LastSyncedAt: time.Now(),
	}

	logger.InfoContext(ctx, "[VCenterScanner] Storing VMware VM data - VMName: '%s', AssetID: %s", vmRecord.VMName, storedAssetID)

	// Store VMware VM data
	if err := r.storeVMwareVMData(ctx, vmRecord); err != nil {
		logger.InfoContext(ctx, "[VCenterScanner] Error storing VMware VM data for %s: %v", vm.Name, err)
		// Continue processing - this is supplementary data
	}

	// Process VM-datastore relationships
	if err := r.processVMDatastoreRelations(ctx, vm, vmRecord.VMID, vcenterServer); err != nil {
		logger.InfoContext(ctx, "[VCenterScanner] Error processing VM datastore relations for %s: %v", vm.Name, err)
		// Continue processing - this is supplementary data
	}

	// Process VM-network relationships
	if err := r.processVMNetworkRelations(ctx, vm, vmRecord.VMID, vcenterServer); err != nil {
		logger.InfoContext(ctx, "[VCenterScanner] Error processing VM network relations for %s: %v", vm.Name, err)
		// Continue processing - this is supplementary data
	}

	logger.InfoContext(ctx, "[VCenterScanner] Successfully processed VM: %s (Asset ID: %s)", vm.Name, storedAssetID)
	return nil
}

// Helper method to store VMware VM data
func (r *VCenterRunner) storeVMwareVMData(ctx context.Context, vmData assetDomain.VMwareVM) error {
	logger.InfoContext(ctx, "[VCenterScanner] Storing VM data for '%s' to database (Asset ID: %s)", vmData.VMName, vmData.AssetID)

	// First, verify that the asset exists in the assets table
	assetID, err := assetDomain.AssetUUIDFromString(vmData.AssetID)
	if err != nil {
		logger.InfoContext(ctx, "[VCenterScanner] Invalid asset UUID format for VM %s: %v", vmData.VMName, err)
		return fmt.Errorf("invalid asset UUID: %w", err)
	}

	var assetIdsList []assetDomain.AssetUUID
	assetIdsList = append(assetIdsList, assetID)

	// Check if the asset exists
	assets, err := r.assetRepo.GetByIDs(ctx, assetIdsList)
	if err != nil {
		logger.InfoContext(ctx, "[VCenterScanner] Error retrieving asset for VM %s: %v", vmData.VMName, err)
		return fmt.Errorf("error checking asset existence: %w", err)
	}

	if len(assets) == 0 {
		logger.InfoContext(ctx, "[VCenterScanner] Asset with ID %s does not exist for VM %s, cannot store VM data", vmData.AssetID, vmData.VMName)
		return fmt.Errorf("asset with ID %s does not exist", vmData.AssetID)
	}

	// Ensure the VM name is properly set before storing
	if vmData.VMName == "" {
		logger.InfoContext(ctx, "[VCenterScanner] Warning: VM name is empty for VM ID %s, this shouldn't happen", vmData.VMID)
	}

	// Now we know the asset exists, proceed with storing VM data
	err = r.assetRepo.StoreVMwareVM(ctx, vmData)
	if err != nil {
		logger.InfoContext(ctx, "[VCenterScanner] Error storing VM data for %s in database: %v", vmData.VMName, err)
		return err
	}

	logger.InfoContext(ctx, "[VCenterScanner] Successfully stored VM data for '%s' (VM ID: %s, Asset ID: %s)",
		vmData.VMName, vmData.VMID, vmData.AssetID)
	return nil
}

// processDatacenter processes a single datacenter and stores it, returning the database UUID
func (r *VCenterRunner) processDatacenter(ctx context.Context, client *govmomi.Client, dc *object.Datacenter, vcenterServer string) (string, error) {
	logger.InfoContext(ctx, "[VCenterScanner] Processing datacenter: %s", dc.Name())

	// Get datacenter managed object reference
	dcRef := dc.Reference()
	vSphereDatacenterID := dcRef.Value

	// Check if datacenter already exists and get its database UUID
	existingID, err := r.assetRepo.GetVCenterDatacenterID(ctx, vSphereDatacenterID, vcenterServer)
	if err == nil && existingID != "" {
		logger.InfoContext(ctx, "[VCenterScanner] Found existing datacenter with database ID: %s", existingID)

		// Update the existing record
		datacenterRecord := assetDomain.VCenterDatacenter{
			ID:            existingID,
			VsphereID:     vSphereDatacenterID,
			Name:          dc.Name(),
			Moref:         dcRef.String(),
			VCenterServer: vcenterServer,
			UpdatedAt:     time.Now(),
			LastSyncedAt:  time.Now(),
		}

		if err := r.assetRepo.StoreVCenterDatacenter(ctx, datacenterRecord); err != nil {
			logger.InfoContext(ctx, "[VCenterScanner] Error updating datacenter data for %s: %v", dc.Name(), err)
			return "", err
		}

		logger.InfoContext(ctx, "[VCenterScanner] Successfully updated datacenter: %s", dc.Name())
		return existingID, nil
	}

	// Create new datacenter record
	databaseUUID := uuid.New().String()
	datacenterRecord := assetDomain.VCenterDatacenter{
		ID:            databaseUUID,
		VsphereID:     vSphereDatacenterID,
		Name:          dc.Name(),
		Moref:         dcRef.String(),
		VCenterServer: vcenterServer,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
		LastSyncedAt:  time.Now(),
	}

	// Store datacenter data
	if err := r.assetRepo.StoreVCenterDatacenter(ctx, datacenterRecord); err != nil {
		logger.InfoContext(ctx, "[VCenterScanner] Error storing datacenter data for %s: %v", dc.Name(), err)
		return "", err
	}

	logger.InfoContext(ctx, "[VCenterScanner] Successfully processed datacenter: %s", dc.Name())
	return databaseUUID, nil
}

// processClusters processes all clusters in a datacenter
func (r *VCenterRunner) processClusters(ctx context.Context, client *govmomi.Client, finder *find.Finder, datacenterID string, vcenterServer string) error {
	logger.InfoContext(ctx, "[VCenterScanner] Processing clusters in datacenter: %s", datacenterID)

	// Find all clusters in this datacenter
	clusters, err := finder.ComputeResourceList(ctx, "*")
	if err != nil {
		logger.InfoContext(ctx, "[VCenterScanner] Error finding clusters: %v", err)
		return err
	}

	logger.InfoContext(ctx, "[VCenterScanner] Found %d cluster(s)", len(clusters))

	// Process each cluster
	for _, cluster := range clusters {
		if err := r.processSingleCluster(ctx, client, cluster, datacenterID, vcenterServer); err != nil {
			logger.InfoContext(ctx, "[VCenterScanner] Error processing cluster %s: %v", cluster.Name(), err)
			// Continue with next cluster
		}
	}

	return nil
}

// processSingleCluster processes a single cluster
func (r *VCenterRunner) processSingleCluster(ctx context.Context, client *govmomi.Client, cluster *object.ComputeResource, datacenterID string, vcenterServer string) error {
	logger.InfoContext(ctx, "[VCenterScanner] Processing cluster: %s", cluster.Name())

	// Get cluster properties
	var clusterObj mo.ComputeResource
	err := cluster.Properties(ctx, cluster.Reference(), []string{
		"summary", "configuration", "configurationEx"}, &clusterObj)
	if err != nil {
		logger.InfoContext(ctx, "[VCenterScanner] Error getting cluster properties for %s: %v", cluster.Name(), err)
		return err
	}

	clusterRef := cluster.Reference()

	// Extract cluster information
	var totalCPUMhz, usedCPUMhz *int32
	var totalMemoryMB, usedMemoryMB *int64
	var numHosts, numVMs *int32
	var drsEnabled, haEnabled *bool

	// Get resource information
	if clusterObj.Summary != nil {
		summary := clusterObj.Summary.GetComputeResourceSummary()
		if summary != nil {

			if summary.TotalCpu > 0 {
				totalCPU := int32(summary.TotalCpu)
				totalCPUMhz = &totalCPU
			}

			if summary.EffectiveCpu > 0 {
				effectiveCPU := int32(summary.EffectiveCpu)
				usedCPUMhz = &effectiveCPU
			}

			if summary.TotalMemory > 0 {
				totalMem := int64(summary.TotalMemory / (1024 * 1024)) // Convert bytes to MB
				totalMemoryMB = &totalMem
			}

			if summary.EffectiveMemory > 0 {
				effectiveMem := int64(summary.EffectiveMemory) // Already in MB
				usedMemoryMB = &effectiveMem
			}

			if summary.NumHosts > 0 {
				hosts := int32(summary.NumHosts)
				numHosts = &hosts
			}
		}
	}

	if clusterRef.Type == "ClusterComputeResource" {
		var clusterComputeObj mo.ClusterComputeResource
		err := cluster.Properties(ctx, cluster.Reference(), []string{
			"summary", "configuration"}, &clusterComputeObj)
		if err == nil {
			if clusterComputeObj.Configuration.DrsConfig.Enabled != nil {
				drsEnabled = clusterComputeObj.Configuration.DrsConfig.Enabled
			}
			if clusterComputeObj.Configuration.DasConfig.Enabled != nil {
				haEnabled = clusterComputeObj.Configuration.DasConfig.Enabled
			}
		}

		// Count VMs in the cluster
		if vmCount, err := r.countVMsInCluster(ctx, client, cluster); err == nil {
			numVMs = &vmCount
		}
	} else {
		// This is a standalone host, set DRS/HA to false
		drsEnabledVal := false
		drsEnabled = &drsEnabledVal
		haEnabledVal := false
		haEnabled = &haEnabledVal

		if vmCount, err := r.countVMsInCluster(ctx, client, cluster); err == nil {
			numVMs = &vmCount
		}
	}

	// Check if cluster already exists and get its database ID
	existingID, err := r.assetRepo.GetVCenterClusterID(ctx, clusterRef.Value, vcenterServer)
	var clusterDatabaseID string
	if err == nil && existingID != "" {
		clusterDatabaseID = existingID
		logger.DebugContext(ctx, "[VCenterScanner] Found existing cluster with database ID: %s", existingID)
	} else {
		clusterDatabaseID = uuid.New().String()
		logger.DebugContext(ctx, "[VCenterScanner] Creating new cluster with database ID: %s", clusterDatabaseID)
	}

	clusterRecord := assetDomain.VCenterCluster{
		ID:            clusterDatabaseID,
		DatacenterID:  datacenterID,
		VsphereID:     clusterRef.Value,
		Name:          cluster.Name(),
		Moref:         clusterRef.String(),
		TotalCPUMhz:   totalCPUMhz,
		UsedCPUMhz:    usedCPUMhz,
		TotalMemoryMB: totalMemoryMB,
		UsedMemoryMB:  usedMemoryMB,
		NumHosts:      numHosts,
		NumVMs:        numVMs,
		DRSEnabled:    drsEnabled,
		HAEnabled:     haEnabled,
		VCenterServer: vcenterServer,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
		LastSyncedAt:  time.Now(),
	}

	// Store cluster data
	if err := r.assetRepo.StoreVCenterCluster(ctx, clusterRecord); err != nil {
		logger.InfoContext(ctx, "[VCenterScanner] Error storing cluster data for %s: %v", cluster.Name(), err)
		return err
	}

	logger.InfoContext(ctx, "[VCenterScanner] Successfully processed cluster: %s", cluster.Name())
	return nil
}

// processHosts processes all hosts in a datacenter
func (r *VCenterRunner) processHosts(ctx context.Context, client *govmomi.Client, finder *find.Finder, datacenterID string, vcenterServer string) error {
	logger.InfoContext(ctx, "[VCenterScanner] Processing hosts in datacenter: %s", datacenterID)

	// Find all hosts in this datacenter
	hosts, err := finder.HostSystemList(ctx, "*")
	if err != nil {
		logger.InfoContext(ctx, "[VCenterScanner] Error finding hosts: %v", err)
		return err
	}

	logger.InfoContext(ctx, "[VCenterScanner] Found %d host(s)", len(hosts))

	// Process each host
	for _, host := range hosts {
		if err := r.processSingleHost(ctx, client, host, datacenterID, vcenterServer); err != nil {
			logger.InfoContext(ctx, "[VCenterScanner] Error processing host %s: %v", host.Name(), err)
			// Continue with next host
		}
	}

	return nil
}

// processSingleHost processes a single ESXi host
func (r *VCenterRunner) processSingleHost(ctx context.Context, client *govmomi.Client, host *object.HostSystem, datacenterID string, vcenterServer string) error {
	logger.InfoContext(ctx, "[VCenterScanner] Processing host: %s", host.Name())

	// Get host properties
	var hostObj mo.HostSystem
	err := host.Properties(ctx, host.Reference(), []string{
		"summary", "runtime", "hardware", "config"}, &hostObj)
	if err != nil {
		logger.InfoContext(ctx, "[VCenterScanner] Error getting host properties for %s: %v", host.Name(), err)
		return err
	}

	hostRef := host.Reference()

	// Extract host information
	var cpuUsage *int32
	var memoryUsage *int64
	var totalMemory *int64
	var cpuCores *int32
	var cpuThreads *int32
	var cpuMhz *int32
	var numNICs *int32
	var numVMs *int32
	var uptimeSeconds *int64
	var vendor, model, biosVersion string
	var hypervisorType, hypervisorVersion string
	var cpuModel string
	var clusterID *string

	// Get resource usage from QuickStats
	cpuUsageValue := int32(hostObj.Summary.QuickStats.OverallCpuUsage)
	cpuUsage = &cpuUsageValue
	memUsageValue := int64(hostObj.Summary.QuickStats.OverallMemoryUsage) * 1024 * 1024 // Convert MB to bytes
	memoryUsage = &memUsageValue

	// Get hardware information
	totalMemValue := int64(hostObj.Summary.Hardware.MemorySize)
	totalMemory = &totalMemValue
	coresValue := int32(hostObj.Summary.Hardware.NumCpuCores)
	cpuCores = &coresValue
	threadsValue := int32(hostObj.Summary.Hardware.NumCpuThreads)
	cpuThreads = &threadsValue
	cpuMhzValue := int32(hostObj.Summary.Hardware.CpuMhz)
	cpuMhz = &cpuMhzValue
	nicsValue := int32(hostObj.Summary.Hardware.NumNics)
	numNICs = &nicsValue
	vendor = hostObj.Summary.Hardware.Vendor
	model = hostObj.Summary.Hardware.Model

	// Get CPU model details
	if hostObj.Hardware != nil && len(hostObj.Hardware.CpuPkg) > 0 {
		cpuModel = hostObj.Hardware.CpuPkg[0].Description
	}

	// Get VM count
	vmCount, err := r.countVMsOnHost(ctx, client, host)
	if err != nil {
		logger.DebugContext(ctx, "[VCenterScanner] Error counting VMs on host %s: %v", host.Name(), err)
		// Set to 0 if we can't count
		vmsValue := int32(0)
		numVMs = &vmsValue
	} else {
		numVMs = &vmCount
		logger.DebugContext(ctx, "[VCenterScanner] Host %s has %d VMs", host.Name(), vmCount)
	}

	// Get uptime
	if hostObj.Summary.QuickStats.Uptime > 0 {
		uptimeValue := int64(hostObj.Summary.QuickStats.Uptime)
		uptimeSeconds = &uptimeValue
	}

	// Get product information
	if hostObj.Summary.Config.Product != nil {
		hypervisorType = hostObj.Summary.Config.Product.Name
		hypervisorVersion = hostObj.Summary.Config.Product.Version
	}

	if hostObj.Hardware != nil && hostObj.Hardware.BiosInfo != nil {
		biosVersion = hostObj.Hardware.BiosInfo.BiosVersion
	}

	// Get cluster information
	var hostParentObj mo.HostSystem
	if err := host.Properties(ctx, host.Reference(), []string{"parent"}, &hostParentObj); err == nil {
		if hostParentObj.Parent != nil {
			parentRef := *hostParentObj.Parent
			if parentRef.Type == "ClusterComputeResource" {
				// Get cluster database ID
				if clusterDatabaseID, err := r.assetRepo.GetVCenterClusterID(ctx, parentRef.Value, vcenterServer); err == nil && clusterDatabaseID != "" {
					clusterID = &clusterDatabaseID
					logger.InfoContext(ctx, "[VCenterScanner] Host %s belongs to cluster database ID: %s", host.Name(), clusterDatabaseID)
				}
			}
		}
	}

	connectionState := string(hostObj.Runtime.ConnectionState)
	powerState := string(hostObj.Runtime.PowerState)

	hostRecord := assetDomain.VCenterHost{
		ID:                uuid.New().String(),
		DatacenterID:      datacenterID,
		ClusterID:         clusterID,
		VsphereID:         hostRef.Value,
		Name:              host.Name(),
		Moref:             hostRef.String(),
		ConnectionState:   connectionState,
		PowerState:        powerState,
		CPUUsageMhz:       cpuUsage,
		MemoryUsageMB:     memoryUsage,
		TotalMemoryMB:     totalMemory,
		CPUCores:          cpuCores,
		CPUThreads:        cpuThreads,
		CPUModel:          cpuModel,
		CPUMhz:            cpuMhz,
		NumNICs:           numNICs,
		NumVMs:            numVMs,
		UptimeSeconds:     uptimeSeconds,
		Vendor:            vendor,
		Model:             model,
		BiosVersion:       biosVersion,
		HypervisorType:    hypervisorType,
		HypervisorVersion: hypervisorVersion,
		VCenterServer:     vcenterServer,
		CreatedAt:         time.Now(),
		UpdatedAt:         time.Now(),
		LastSyncedAt:      time.Now(),
	}

	// Store host data
	if err := r.assetRepo.StoreVCenterHost(ctx, hostRecord); err != nil {
		logger.InfoContext(ctx, "[VCenterScanner] Error storing host data for %s: %v", host.Name(), err)
		return err
	}

	// Create host as an asset with discovered_by field
	if err := r.createHostAsset(ctx, hostRecord, host.Name()); err != nil {
		logger.InfoContext(ctx, "[VCenterScanner] Error creating host asset for %s: %v", host.Name(), err)
		// Continue processing - this is supplementary
	}

	// Process host IP addresses
	if err := r.processHostIPs(ctx, hostObj, hostRecord.ID); err != nil {
		logger.InfoContext(ctx, "[VCenterScanner] Error processing host IPs for %s: %v", host.Name(), err)
		// Continue processing - this is supplementary data
	}

	// Process host NICs
	if err := r.processHostNICs(ctx, hostObj, hostRecord.ID); err != nil {
		logger.InfoContext(ctx, "[VCenterScanner] Error processing host NICs for %s: %v", host.Name(), err)
		// Continue processing - this is supplementary data
	}

	// Process host virtual switches
	if err := r.processHostVirtualSwitches(ctx, client, host, hostRecord.ID); err != nil {
		logger.InfoContext(ctx, "[VCenterScanner] Error processing host virtual switches for %s: %v", host.Name(), err)
		// Continue processing - this is supplementary data
	}

	// Process host-datastore relationships
	if err := r.processHostDatastoreRelations(ctx, client, host, hostRecord.ID, vcenterServer); err != nil {
		logger.InfoContext(ctx, "[VCenterScanner] Error processing host datastore relations for %s: %v", host.Name(), err)
		// Continue processing - this is supplementary data
	}

	logger.InfoContext(ctx, "[VCenterScanner] Successfully processed host: %s", host.Name())
	return nil
}

// processDatastores processes all datastores in a datacenter
func (r *VCenterRunner) processDatastores(ctx context.Context, client *govmomi.Client, finder *find.Finder, datacenterID string, vcenterServer string) error {
	logger.InfoContext(ctx, "[VCenterScanner] Processing datastores in datacenter: %s", datacenterID)

	// Find all datastores in this datacenter
	datastores, err := finder.DatastoreList(ctx, "*")
	if err != nil {
		logger.InfoContext(ctx, "[VCenterScanner] Error finding datastores: %v", err)
		return err
	}

	logger.InfoContext(ctx, "[VCenterScanner] Found %d datastore(s)", len(datastores))

	// Process each datastore
	for _, ds := range datastores {
		if err := r.processSingleDatastore(ctx, client, ds, datacenterID, vcenterServer); err != nil {
			logger.InfoContext(ctx, "[VCenterScanner] Error processing datastore %s: %v", ds.Name(), err)
			// Continue with next datastore
		}
	}

	return nil
}

// processSingleDatastore processes a single datastore
func (r *VCenterRunner) processSingleDatastore(ctx context.Context, client *govmomi.Client, ds *object.Datastore, datacenterID string, vcenterServer string) error {
	logger.InfoContext(ctx, "[VCenterScanner] Processing datastore: %s", ds.Name())

	// Get datastore properties
	var dsObj mo.Datastore
	err := ds.Properties(ctx, ds.Reference(), []string{"summary", "info", "capability"}, &dsObj)
	if err != nil {
		logger.InfoContext(ctx, "[VCenterScanner] Error getting datastore properties for %s: %v", ds.Name(), err)
		return err
	}

	dsRef := ds.Reference()

	// Extract datastore information
	var capacityGB, freeSpaceGB, provisionedSpaceGB *int64
	var accessible, multipleHostAccess *bool
	var datastoreType string

	// Get datastore summary information
	capacity := int64(dsObj.Summary.Capacity / (1024 * 1024 * 1024)) // Convert to GB
	capacityGB = &capacity

	freeSpace := int64(dsObj.Summary.FreeSpace / (1024 * 1024 * 1024)) // Convert to GB
	freeSpaceGB = &freeSpace

	// Calculate provisioned space (used space)
	provisionedSpace := capacity - freeSpace
	provisionedSpaceGB = &provisionedSpace

	accessible = &dsObj.Summary.Accessible
	if dsObj.Summary.MultipleHostAccess != nil {
		multipleHostAccess = dsObj.Summary.MultipleHostAccess
	}
	datastoreType = dsObj.Summary.Type

	// Check if datastore already exists and get its database ID
	existingID, err := r.assetRepo.GetVCenterDatastoreID(ctx, dsRef.Value, vcenterServer)
	var datastoreDatabaseID string
	if err == nil && existingID != "" {
		datastoreDatabaseID = existingID
		logger.DebugContext(ctx, "[VCenterScanner] Found existing datastore with database ID: %s", existingID)
	} else {
		datastoreDatabaseID = uuid.New().String()
		logger.DebugContext(ctx, "[VCenterScanner] Creating new datastore with database ID: %s", datastoreDatabaseID)
	}

	datastoreRecord := assetDomain.VCenterDatastore{
		ID:                 datastoreDatabaseID,
		DatacenterID:       datacenterID,
		VsphereID:          dsRef.Value,
		Name:               ds.Name(),
		Moref:              dsRef.String(),
		Type:               datastoreType,
		CapacityGB:         capacityGB,
		FreeSpaceGB:        freeSpaceGB,
		ProvisionedSpaceGB: provisionedSpaceGB,
		Accessible:         accessible,
		MultipleHostAccess: multipleHostAccess,
		VCenterServer:      vcenterServer,
		CreatedAt:          time.Now(),
		UpdatedAt:          time.Now(),
		LastSyncedAt:       time.Now(),
	}

	// Store datastore data
	if err := r.assetRepo.StoreVCenterDatastore(ctx, datastoreRecord); err != nil {
		logger.InfoContext(ctx, "[VCenterScanner] Error storing datastore data for %s: %v", ds.Name(), err)
		return err
	}

	logger.InfoContext(ctx, "[VCenterScanner] Successfully processed datastore: %s", ds.Name())
	return nil
}

// processNetworks processes all networks in a datacenter
func (r *VCenterRunner) processNetworks(ctx context.Context, client *govmomi.Client, finder *find.Finder, datacenterID string, vcenterServer string) error {
	logger.InfoContext(ctx, "[VCenterScanner] Processing networks in datacenter: %s", datacenterID)

	// Find all networks in this datacenter
	networks, err := finder.NetworkList(ctx, "*")
	if err != nil {
		logger.InfoContext(ctx, "[VCenterScanner] Error finding networks: %v", err)
		return err
	}

	logger.InfoContext(ctx, "[VCenterScanner] Found %d network(s)", len(networks))

	// Process each network
	for _, network := range networks {
		if err := r.processSingleNetwork(ctx, client, network, datacenterID, vcenterServer); err != nil {
			logger.InfoContext(ctx, "[VCenterScanner] Error processing network %s: %v", network.GetInventoryPath(), err)
			// Continue with next network
		}
	}

	return nil
}

// processSingleNetwork processes a single network
func (r *VCenterRunner) processSingleNetwork(ctx context.Context, client *govmomi.Client, network object.NetworkReference, datacenterID string, vcenterServer string) error {
	networkName := network.GetInventoryPath()
	logger.InfoContext(ctx, "[VCenterScanner] Processing network: %s", networkName)

	netRef := network.Reference()
	networkType := netRef.Type

	var accessible *bool
	var vlanID *int
	var switchName string

	// Handle different network types
	switch networkType {
	case "Network":
		// Standard network
		var netObj mo.Network
		err := client.RetrieveOne(ctx, netRef, []string{"summary", "name"}, &netObj)
		if err != nil {
			logger.InfoContext(ctx, "[VCenterScanner] Error getting network properties for %s: %v", networkName, err)
			return err
		}
		networkName = netObj.Name
		if netObj.Summary != nil {
			if summary, ok := netObj.Summary.(*types.NetworkSummary); ok {
				isAccessible := summary.Accessible
				accessible = &isAccessible
			}
		}

	case "DistributedVirtualPortgroup":
		// Distributed virtual port group
		var dvpgObj mo.DistributedVirtualPortgroup
		err := client.RetrieveOne(ctx, netRef, []string{"config", "summary"}, &dvpgObj)
		if err != nil {
			logger.InfoContext(ctx, "[VCenterScanner] Error getting DVPortgroup properties for %s: %v", networkName, err)
			return err
		}

		if dvpgObj.Config.Name != "" {
			networkName = dvpgObj.Config.Name
		}

		// Extract VLAN info if available
		if dvpgObj.Config.DefaultPortConfig != nil {
			if portConfig, ok := dvpgObj.Config.DefaultPortConfig.(*types.VMwareDVSPortSetting); ok {
				if portConfig.Vlan != nil {
					if vlanInfo, ok := portConfig.Vlan.(*types.VmwareDistributedVirtualSwitchVlanIdSpec); ok {
						vlanValue := int(vlanInfo.VlanId)
						vlanID = &vlanValue
					}
				}
			}
		}

		// Get distributed switch name
		if dvpgObj.Config.DistributedVirtualSwitch != nil {
			var dvsObj mo.VmwareDistributedVirtualSwitch
			err := client.RetrieveOne(ctx, *dvpgObj.Config.DistributedVirtualSwitch, []string{"name"}, &dvsObj)
			if err == nil {
				switchName = dvsObj.Name
			}
		}
	}

	networkRecord := assetDomain.VCenterNetwork{
		ID:            uuid.New().String(),
		DatacenterID:  datacenterID,
		VsphereID:     netRef.Value,
		Name:          networkName,
		Moref:         netRef.String(),
		NetworkType:   networkType,
		VLanID:        vlanID,
		SwitchName:    switchName,
		Accessible:    accessible,
		VCenterServer: vcenterServer,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
		LastSyncedAt:  time.Now(),
	}

	// Store network data
	if err := r.assetRepo.StoreVCenterNetwork(ctx, networkRecord); err != nil {
		logger.InfoContext(ctx, "[VCenterScanner] Error storing network data for %s: %v", networkName, err)
		return err
	}

	logger.InfoContext(ctx, "[VCenterScanner] Successfully processed network: %s", networkName)
	return nil
}

// processHostIPs processes IP addresses for a host
func (r *VCenterRunner) processHostIPs(ctx context.Context, hostObj mo.HostSystem, hostDatabaseID string) error {
	logger.InfoContext(ctx, "[VCenterScanner] Processing IP addresses for host %s", hostDatabaseID)

	// Try to get IPs from Config.Network.Vnic first
	if hostObj.Config != nil && hostObj.Config.Network.Vnic != nil {
		// Process virtual NICs (vmkernel interfaces)
		for _, vnic := range hostObj.Config.Network.Vnic {
			if vnic.Spec.Ip != nil {
				// Determine IP type based on port group or interface purpose
				ipType := "management"
				if vnic.Portgroup != "" {
					if strings.Contains(strings.ToLower(vnic.Portgroup), "vmotion") {
						ipType = "vmotion"
					} else if strings.Contains(strings.ToLower(vnic.Portgroup), "storage") {
						ipType = "storage"
					} else if strings.Contains(strings.ToLower(vnic.Portgroup), "fault") {
						ipType = "fault_tolerance"
					}
				}

				hostIP := assetDomain.VCenterHostIP{
					ID:         uuid.New().String(),
					HostID:     hostDatabaseID,
					IPAddress:  vnic.Spec.Ip.IpAddress,
					IPType:     ipType,
					SubnetMask: vnic.Spec.Ip.SubnetMask,
					DHCP:       &vnic.Spec.Ip.Dhcp,
					CreatedAt:  time.Now(),
					UpdatedAt:  time.Now(),
				}

				if err := r.assetRepo.StoreVCenterHostIP(ctx, hostIP); err != nil {
					logger.InfoContext(ctx, "[VCenterScanner] Error storing host IP %s: %v", vnic.Spec.Ip.IpAddress, err)
					// Continue with other IPs
				} else {
					logger.InfoContext(ctx, "[VCenterScanner] Stored host IP %s (%s)", vnic.Spec.Ip.IpAddress, ipType)
				}
			}
		}
	} else {
		logger.InfoContext(ctx, "[VCenterScanner] No detailed network configuration found for host, trying to get basic management IP from summary")

		if hostObj.Summary.ManagementServerIp != "" {
			hostIP := assetDomain.VCenterHostIP{
				ID:        uuid.New().String(),
				HostID:    hostDatabaseID,
				IPAddress: hostObj.Summary.ManagementServerIp,
				IPType:    "management",
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			}

			if err := r.assetRepo.StoreVCenterHostIP(ctx, hostIP); err != nil {
				logger.InfoContext(ctx, "[VCenterScanner] Error storing host management IP %s: %v", hostObj.Summary.ManagementServerIp, err)
			} else {
				logger.InfoContext(ctx, "[VCenterScanner] Stored host management IP %s", hostObj.Summary.ManagementServerIp)
			}
		}
	}

	return nil
}

// processHostNICs processes physical NICs for a host
func (r *VCenterRunner) processHostNICs(ctx context.Context, hostObj mo.HostSystem, hostDatabaseID string) error {
	logger.InfoContext(ctx, "[VCenterScanner] Processing NICs for host %s", hostDatabaseID)

	if hostObj.Config == nil || hostObj.Config.Network.Pnic == nil {
		logger.InfoContext(ctx, "[VCenterScanner] No physical NIC configuration found for host, skipping NIC processing")
		return nil
	}

	// Process physical NICs
	for _, pnic := range hostObj.Config.Network.Pnic {
		linkSpeed := int32(0)
		if pnic.LinkSpeed != nil && pnic.LinkSpeed.SpeedMb > 0 {
			linkSpeed = pnic.LinkSpeed.SpeedMb
		}

		var wakeOnLAN *bool
		wakeOnLANValue := pnic.WakeOnLanSupported
		wakeOnLAN = &wakeOnLANValue

		duplex := "unknown"
		if pnic.LinkSpeed != nil {
			if pnic.LinkSpeed.Duplex {
				duplex = "full"
			} else {
				duplex = "half"
			}
		}

		hostNIC := assetDomain.VCenterHostNIC{
			ID:         uuid.New().String(),
			HostID:     hostDatabaseID,
			Device:     pnic.Device,
			Driver:     pnic.Driver,
			LinkSpeed:  &linkSpeed,
			Duplex:     duplex,
			MacAddress: pnic.Mac,
			PCI:        pnic.Pci,
			WakeOnLAN:  wakeOnLAN,
			CreatedAt:  time.Now(),
			UpdatedAt:  time.Now(),
		}

		if err := r.assetRepo.StoreVCenterHostNIC(ctx, hostNIC); err != nil {
			logger.InfoContext(ctx, "[VCenterScanner] Error storing host NIC %s: %v", pnic.Device, err)
			// Continue with other NICs
		} else {
			logger.InfoContext(ctx, "[VCenterScanner] Stored host NIC %s", pnic.Device)
		}
	}

	return nil
}

// processHostVirtualSwitches processes virtual switches for a host
func (r *VCenterRunner) processHostVirtualSwitches(ctx context.Context, client *govmomi.Client, host *object.HostSystem, hostDatabaseID string) error {
	logger.InfoContext(ctx, "[VCenterScanner] Processing virtual switches for host %s", hostDatabaseID)

	// Get host network system
	hostNetworkSystem, err := host.ConfigManager().NetworkSystem(ctx)
	if err != nil {
		logger.InfoContext(ctx, "[VCenterScanner] Error getting host network system: %v", err)
		return err
	}

	// Get network configuration
	var netConfig mo.HostNetworkSystem
	err = hostNetworkSystem.Properties(ctx, hostNetworkSystem.Reference(), []string{"networkInfo"}, &netConfig)
	if err != nil {
		logger.InfoContext(ctx, "[VCenterScanner] Error getting network info: %v", err)
		return err
	}

	if netConfig.NetworkInfo == nil {
		logger.InfoContext(ctx, "[VCenterScanner] No network info available for host")
		return nil
	}

	// Process standard virtual switches
	if netConfig.NetworkInfo.Vswitch != nil {
		for _, vswitch := range netConfig.NetworkInfo.Vswitch {
			numPorts := int32(0)
			if vswitch.Spec.NumPorts > 0 {
				numPorts = vswitch.Spec.NumPorts
			}

			// Count used ports by counting connected pNICs and port groups
			usedPorts := int32(0)
			if vswitch.Pnic != nil {
				usedPorts += int32(len(vswitch.Pnic))
			}
			if vswitch.Portgroup != nil {
				usedPorts += int32(len(vswitch.Portgroup))
			}

			mtu := int32(1500) // Default MTU
			if vswitch.Mtu > 0 {
				mtu = vswitch.Mtu
			}

			virtualSwitch := assetDomain.VCenterVirtualSwitch{
				ID:           uuid.New().String(),
				HostID:       hostDatabaseID,
				VsphereID:    vswitch.Key,
				Name:         vswitch.Name,
				SwitchType:   "standard",
				NumPorts:     &numPorts,
				UsedPorts:    &usedPorts,
				MTU:          &mtu,
				CreatedAt:    time.Now(),
				UpdatedAt:    time.Now(),
				LastSyncedAt: time.Now(),
			}

			if err := r.assetRepo.StoreVCenterVirtualSwitch(ctx, virtualSwitch); err != nil {
				logger.InfoContext(ctx, "[VCenterScanner] Error storing virtual switch %s: %v", vswitch.Name, err)
				// Continue with other switches
			} else {
				logger.InfoContext(ctx, "[VCenterScanner] Stored virtual switch %s", vswitch.Name)
			}
		}
	}

	return nil
}

// processHostDatastoreRelations processes datastore relationships for a host
func (r *VCenterRunner) processHostDatastoreRelations(ctx context.Context, client *govmomi.Client, host *object.HostSystem, hostDatabaseID string, vcenterServer string) error {
	logger.InfoContext(ctx, "[VCenterScanner] Processing datastore relations for host %s", hostDatabaseID)

	// Get datastores accessible
	datastoreSystem, err := host.ConfigManager().DatastoreSystem(ctx)
	if err != nil {
		logger.InfoContext(ctx, "[VCenterScanner] Error getting datastore system: %v", err)
		return err
	}

	var datastoreSystemObj mo.HostDatastoreSystem
	err = datastoreSystem.Properties(ctx, datastoreSystem.Reference(), []string{"datastore"}, &datastoreSystemObj)
	if err != nil {
		logger.InfoContext(ctx, "[VCenterScanner] Error getting datastore system properties: %v", err)
		return err
	}

	for _, dsRef := range datastoreSystemObj.Datastore {
		// Get datastore properties to check accessibility
		var dsObj mo.Datastore
		err := client.RetrieveOne(ctx, dsRef, []string{"summary", "host"}, &dsObj)
		if err != nil {
			logger.InfoContext(ctx, "[VCenterScanner] Error getting datastore properties: %v", err)
			continue
		}

		// Get datastore database ID
		datastoreID, err := r.getDatastoreID(ctx, dsRef.Value, vcenterServer)
		if err != nil {
			logger.InfoContext(ctx, "[VCenterScanner] Error getting datastore database ID: %v", err)
			continue
		}

		// Check if datastore is accessible and mounted for this host
		accessible := dsObj.Summary.Accessible
		mounted := true // Default assumption

		// Look for host-specific mount info
		if dsObj.Host != nil {
			for _, hostMount := range dsObj.Host {
				if hostMount.Key.Value == host.Reference().Value {
					mountedPtr := hostMount.MountInfo.Mounted
					if mountedPtr != nil {
						mounted = *mountedPtr
					}
					break
				}
			}
		}

		relation := assetDomain.HostDatastoreRelation{
			ID:          uuid.New().String(),
			HostID:      hostDatabaseID,
			DatastoreID: datastoreID,
			Accessible:  &accessible,
			Mounted:     &mounted,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		}

		if err := r.assetRepo.StoreHostDatastoreRelation(ctx, relation); err != nil {
			logger.InfoContext(ctx, "[VCenterScanner] Error storing host-datastore relation: %v", err)
			// Continue with other relations
		} else {
			logger.InfoContext(ctx, "[VCenterScanner] Stored host-datastore relation")
		}
	}

	return nil
}

// getDatastoreID gets the database ID for a datastore by its vSphere ID
func (r *VCenterRunner) getDatastoreID(ctx context.Context, datastoreVSphereID, vcenterServer string) (string, error) {
	return r.assetRepo.GetVCenterDatastoreID(ctx, datastoreVSphereID, vcenterServer)
}

// processVMDatastoreRelations processes datastore relationships for a VM
func (r *VCenterRunner) processVMDatastoreRelations(ctx context.Context, vm mo.VirtualMachine, vmID string, vcenterServer string) error {
	logger.InfoContext(ctx, "[VCenterScanner] Processing VM datastore relations for %s", vm.Name)

	if vm.Storage == nil || vm.Storage.PerDatastoreUsage == nil {
		logger.InfoContext(ctx, "[VCenterScanner] No storage information available for VM %s", vm.Name)
		return nil
	}

	// Process each datastore usage
	for _, datastoreUsage := range vm.Storage.PerDatastoreUsage {
		// Get datastore database ID
		datastoreID, err := r.getDatastoreID(ctx, datastoreUsage.Datastore.Value, vcenterServer)
		if err != nil {
			logger.InfoContext(ctx, "[VCenterScanner] Error getting datastore database ID for VM %s: %v", vm.Name, err)
			continue
		}

		// Convert storage values from bytes to GB
		committedGB := int64(datastoreUsage.Committed / (1024 * 1024 * 1024))
		uncommittedGB := int64(datastoreUsage.Uncommitted / (1024 * 1024 * 1024))
		usedSpaceGB := committedGB + uncommittedGB

		relation := assetDomain.VMDatastoreRelation{
			ID:            uuid.New().String(),
			VMID:          vmID,
			DatastoreID:   datastoreID,
			UsedSpaceGB:   &usedSpaceGB,
			CommittedGB:   &committedGB,
			UncommittedGB: &uncommittedGB,
			CreatedAt:     time.Now(),
			UpdatedAt:     time.Now(),
		}

		if err := r.assetRepo.StoreVMDatastoreRelation(ctx, relation); err != nil {
			logger.InfoContext(ctx, "[VCenterScanner] Error storing VM-datastore relation: %v", err)
			// Continue with other relations
		} else {
			logger.InfoContext(ctx, "[VCenterScanner] Stored VM-datastore relation for VM %s", vm.Name)
		}
	}

	return nil
}

// processVMNetworkRelations processes network relationships for a VM
func (r *VCenterRunner) processVMNetworkRelations(ctx context.Context, vm mo.VirtualMachine, vmID string, vcenterServer string) error {
	logger.InfoContext(ctx, "[VCenterScanner] Processing VM network relations for %s", vm.Name)

	if vm.Guest == nil || vm.Guest.Net == nil {
		logger.InfoContext(ctx, "[VCenterScanner] No guest network information available for VM %s", vm.Name)
		return nil
	}

	// Process each network interface
	for _, netInfo := range vm.Guest.Net {
		if netInfo.Network == "" {
			continue
		}

		networkID, err := r.getNetworkIDByName(ctx, netInfo.Network, vcenterServer)
		if err != nil {
			logger.InfoContext(ctx, "[VCenterScanner] Error getting network database ID for VM %s, network %s: %v", vm.Name, netInfo.Network, err)
			continue
		}

		// Serialize IP addresses to JSON
		ipAddressesJSON := ""
		if len(netInfo.IpAddress) > 0 {
			ipBytes, _ := json.Marshal(netInfo.IpAddress)
			ipAddressesJSON = string(ipBytes)
		}

		connected := netInfo.Connected
		startConnected := true

		relation := assetDomain.VMNetworkRelation{
			ID:             uuid.New().String(),
			VMID:           vmID,
			NetworkID:      networkID,
			MacAddress:     netInfo.MacAddress,
			IPAddresses:    ipAddressesJSON,
			Connected:      &connected,
			StartConnected: &startConnected,
			CreatedAt:      time.Now(),
			UpdatedAt:      time.Now(),
		}

		if err := r.assetRepo.StoreVMNetworkRelation(ctx, relation); err != nil {
			logger.InfoContext(ctx, "[VCenterScanner] Error storing VM-network relation: %v", err)
			// Continue with other relations
		} else {
			logger.InfoContext(ctx, "[VCenterScanner] Stored VM-network relation for VM %s", vm.Name)
		}
	}

	return nil
}

// getNetworkIDByName gets the database ID for a network by name
func (r *VCenterRunner) getNetworkIDByName(ctx context.Context, networkName string, vcenterServer string) (string, error) {
	logger.InfoContext(ctx, "[VCenterScanner] Looking up network ID by name: %s", networkName)

	// Try to get network database ID by name
	networkID, err := r.assetRepo.GetVCenterNetworkIDByName(ctx, networkName, vcenterServer)
	if err != nil {
		logger.InfoContext(ctx, "[VCenterScanner] Network '%s' not found in database, creating placeholder", networkName)

		networkRecord := assetDomain.VCenterNetwork{
			ID:            uuid.New().String(),
			VsphereID:     fmt.Sprintf("network-%s", strings.ToLower(strings.ReplaceAll(networkName, " ", "-"))),
			Name:          networkName,
			Moref:         fmt.Sprintf("Network:%s", networkName),
			NetworkType:   "DistributedVirtualPortgroup",
			VCenterServer: vcenterServer,
			CreatedAt:     time.Now(),
			UpdatedAt:     time.Now(),
			LastSyncedAt:  time.Now(),
		}

		if err := r.assetRepo.StoreVCenterNetwork(ctx, networkRecord); err != nil {
			return "", fmt.Errorf("failed to create placeholder network for %s: %w", networkName, err)
		}

		logger.InfoContext(ctx, "[VCenterScanner] Created placeholder network record for %s with ID: %s", networkName, networkRecord.ID)
		return networkRecord.ID, nil
	}

	return networkID, nil
}

// CancelScan cancels a running scan job
func (r *VCenterRunner) CancelScan(jobID int64) bool {
	logger.Info("[VCenterScanner] Cancelling scan job ID: %d", jobID)
	return r.cancelManager.CancelScan(jobID)
}

// StatusScan checks if a scan job is currently running
func (r *VCenterRunner) StatusScan(jobID int64) bool {
	status := r.cancelManager.HasActiveScan(jobID)
	logger.Info("[VCenterScanner] Status for scan job ID %d: %v", jobID, status)
	return status
}

// createHostAsset creates a host as an asset with discovered_by field
func (r *VCenterRunner) createHostAsset(ctx context.Context, hostRecord assetDomain.VCenterHost, hostName string) error {
	// Extract primary IP address from host network configuration
	var hostIPs []string

	logger.InfoContext(ctx, "[VCenterScanner] Creating asset for host: %s", hostName)

	// Create the asset
	asset := assetDomain.AssetDomain{
		ID:           uuid.MustParse(uuid.New().String()),
		Name:         hostName,
		Hostname:     hostName,
		Type:         "Physical", // ESXi hosts are physical
		DiscoveredBy: "VCENTER",
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	// Convert to required format for repository
	var assetIPs []assetDomain.AssetIP
	for _, ip := range hostIPs {
		assetIP := assetDomain.AssetIP{
			ID:      uuid.New().String(),
			AssetID: asset.ID.String(),
			IP:      ip,
		}
		assetIPs = append(assetIPs, assetIP)
	}

	// Store the asset
	_, err := r.assetRepo.Create(ctx, asset, "VCENTER")
	if err != nil {
		// Check if this is a duplicate hostname error
		if strings.Contains(err.Error(), "already exists") {
			logger.InfoContext(ctx, "[VCenterScanner] Host asset %s already exists, skipping creation", hostName)
			return nil
		}
		return fmt.Errorf("failed to create host asset: %w", err)
	}

	logger.InfoContext(ctx, "[VCenterScanner] Successfully created host asset for %s with ID: %s", hostName, asset.ID)
	return nil
}

// countVMsInCluster counts the number of VMs in a cluster or compute resource
func (r *VCenterRunner) countVMsInCluster(ctx context.Context, client *govmomi.Client, cluster *object.ComputeResource) (int32, error) {
	logger.InfoContext(ctx, "[VCenterScanner] Counting VMs in cluster: %s", cluster.Name())

	// Get cluster properties including resource pool
	var clusterObj mo.ComputeResource
	err := cluster.Properties(ctx, cluster.Reference(), []string{"resourcePool"}, &clusterObj)
	if err != nil {
		logger.InfoContext(ctx, "[VCenterScanner] Error getting cluster properties for VM count %s: %v", cluster.Name(), err)
		return 0, err
	}

	vmCount := int32(0)

	// Get the resource pool and count VMs recursively
	if clusterObj.ResourcePool != nil {
		vmCount, err = r.countVMsInResourcePool(ctx, client, *clusterObj.ResourcePool)
		if err != nil {
			logger.InfoContext(ctx, "[VCenterScanner] Error counting VMs in resource pool for cluster %s: %v", cluster.Name(), err)
			// Fall back to simple count using hosts
			vmCount = r.countVMsFromHosts(ctx, client, cluster)
		}
	} else {
		// Fall back to counting VMs from hosts
		vmCount = r.countVMsFromHosts(ctx, client, cluster)
	}

	logger.InfoContext(ctx, "[VCenterScanner] Found %d VMs in cluster %s", vmCount, cluster.Name())
	return vmCount, nil
}

// countVMsInResourcePool counts VMs in a resource pool recursively
func (r *VCenterRunner) countVMsInResourcePool(ctx context.Context, client *govmomi.Client, rpRef types.ManagedObjectReference) (int32, error) {
	var rp mo.ResourcePool
	err := client.RetrieveOne(ctx, rpRef, []string{"vm", "resourcePool"}, &rp)
	if err != nil {
		return 0, err
	}

	vmCount := int32(len(rp.Vm))

	// Count VMs in child resource pools recursively
	for _, childRP := range rp.ResourcePool {
		childCount, err := r.countVMsInResourcePool(ctx, client, childRP)
		if err != nil {
			logger.InfoContext(ctx, "[VCenterScanner] Warning: Error counting VMs in child resource pool: %v", err)
			continue
		}
		vmCount += childCount
	}

	return vmCount, nil
}

// countVMsFromHosts counts VMs by examining cluster hosts (fallback method)
func (r *VCenterRunner) countVMsFromHosts(ctx context.Context, client *govmomi.Client, cluster *object.ComputeResource) int32 {
	var clusterObj mo.ComputeResource
	err := cluster.Properties(ctx, cluster.Reference(), []string{"host"}, &clusterObj)
	if err != nil {
		logger.InfoContext(ctx, "[VCenterScanner] Error getting hosts for VM count: %v", err)
		return 0
	}

	totalVMs := int32(0)
	for _, hostRef := range clusterObj.Host {
		var host mo.HostSystem
		err := client.RetrieveOne(ctx, hostRef, []string{"vm"}, &host)
		if err != nil {
			logger.InfoContext(ctx, "[VCenterScanner] Error getting VMs for host %s: %v", hostRef.Value, err)
			continue
		}
		totalVMs += int32(len(host.Vm))
	}

	return totalVMs
}

// countVMsOnHost counts the number of VMs running on a specific host
func (r *VCenterRunner) countVMsOnHost(ctx context.Context, client *govmomi.Client, host *object.HostSystem) (int32, error) {
	var hostObj mo.HostSystem
	err := host.Properties(ctx, host.Reference(), []string{"vm"}, &hostObj)
	if err != nil {
		return 0, err
	}

	return int32(len(hostObj.Vm)), nil
}
