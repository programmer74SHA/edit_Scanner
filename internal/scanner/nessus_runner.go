package scanner

import (
	"context"
	"fmt"
	"log"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	assetDomain "gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/domain"
	assetPort "gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/port"
	scannerDomain "gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanner/domain"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/adapter/storage/types"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/logger"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/nessus"
)

// NessusRunner handles executing Nessus scans
type NessusRunner struct {
	assetRepo     assetPort.Repo
	cancelManager *ScanCancelManager
}

// NewNessusRunner creates a new Nessus runner with asset repository
func NewNessusRunner(assetRepo assetPort.Repo) *NessusRunner {
	return &NessusRunner{
		assetRepo:     assetRepo,
		cancelManager: NewScanCancelManager(),
	}
}

// Execute implements the scheduler.Scanner interface
func (r *NessusRunner) Execute(ctx context.Context, scanner scannerDomain.ScannerDomain, scanJobID int64) error {
	return r.ExecuteNessusScan(ctx, scanner, scanJobID)
}

// ExecuteNessusScan runs a Nessus scan based on scanner configuration
func (r *NessusRunner) ExecuteNessusScan(ctx context.Context, scanner scannerDomain.ScannerDomain, scanJobID int64) error {
	log.Printf("NessusRunner: Starting Nessus scan for scanner ID: %d, job ID: %d", scanner.ID, scanJobID)
	log.Printf("NessusRunner: Scanner metadata - Domain: %s, Username: %s, ApiKey: %s", scanner.Domain, scanner.Username, scanner.ApiKey)

	// Create a cancellable context
	scanCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Register this scan with the cancel manager
	r.cancelManager.RegisterScan(scanJobID, cancel)
	defer r.cancelManager.UnregisterScan(scanJobID)

	// Get Nessus metadata
	nessusMeta, err := r.getNessusMetadata(scanner)
	if err != nil {
		log.Printf("NessusRunner: Failed to get Nessus metadata: %v", err)
		return fmt.Errorf("failed to get Nessus metadata: %w", err)
	}
	log.Printf("NessusRunner: Successfully got Nessus metadata - URL: %s, Username: %s", nessusMeta.URL, nessusMeta.Username)

	// Create Nessus scanner asset
	log.Printf("NessusRunner: Creating Nessus scanner asset...")
	scannerAssetID, err := r.createNessusScannerAsset(scanCtx, nessusMeta, scanJobID)
	if err != nil {
		log.Printf("NessusRunner: Failed to create Nessus scanner asset: %v", err)
		return fmt.Errorf("failed to create Nessus scanner asset: %w", err)
	}
	log.Printf("NessusRunner: Successfully created/updated Nessus scanner asset with ID: %s", scannerAssetID)

	// Create Nessus client
	client, err := r.createNessusClient(nessusMeta)
	if err != nil {
		log.Printf("NessusRunner: Failed to create Nessus client: %v", err)
		return fmt.Errorf("failed to create Nessus client: %w", err)
	}
	log.Printf("NessusRunner: Successfully created Nessus client")

	// Login if using username/password authentication
	if nessusMeta.Username != "" && nessusMeta.Password != "" {
		log.Printf("NessusRunner: Attempting to login with username/password")
		if err := client.Login(scanCtx); err != nil {
			log.Printf("NessusRunner: Failed to login to Nessus: %v", err)
			return fmt.Errorf("failed to login to Nessus: %w", err)
		}
		log.Printf("NessusRunner: Successfully logged in to Nessus")
		defer func() {
			if logoutErr := client.Logout(context.Background()); logoutErr != nil {
				log.Printf("NessusRunner: Failed to logout from Nessus: %v", logoutErr)
			}
		}()
	} else {
		log.Printf("NessusRunner: Using API key authentication")
	}

	// Fetch and process scans
	log.Printf("NessusRunner: Starting to fetch and process scans")
	if err := r.fetchAndProcessScans(scanCtx, client, scanJobID); err != nil {
		log.Printf("NessusRunner: Failed to fetch and process scans: %v", err)
		return fmt.Errorf("failed to fetch and process scans: %w", err)
	}

	log.Printf("NessusRunner: Completed Nessus scan for scanner ID: %d, job ID: %d", scanner.ID, scanJobID)
	return nil
}

// CancelScan cancels a running scan job
func (r *NessusRunner) CancelScan(jobID int64) bool {
	return r.cancelManager.CancelScan(jobID)
}

// StatusScan checks the status of a running scan job
func (r *NessusRunner) StatusScan(jobID int64) bool {
	return r.cancelManager.HasActiveScan(jobID)
}

// createNessusScannerAsset creates an asset representing the Nessus server itself
func (r *NessusRunner) createNessusScannerAsset(ctx context.Context, nessusMeta *scannerDomain.NessusMetadata, scanJobID int64) (string, error) {
	logger.InfoContext(ctx, "Creating/updating Nessus scanner asset for URL: %s", nessusMeta.URL)

	// Extract server host from URL for IP/hostname
	serverHost := r.extractHostFromURL(nessusMeta.URL)

	filter := assetDomain.AssetFilters{}
	if r.isValidIPFormat(serverHost) {
		filter.IP = serverHost
	} else {
		filter.Hostname = serverHost
	}

	assets, err := r.assetRepo.Get(ctx, filter)
	if err == nil && len(assets) > 0 {
		// Found existing asset - use it directly
		existingAsset := assets[0]
		logger.InfoContext(ctx, "Found existing asset: ID=%s, Type=%s - reusing for Nessus scan",
			existingAsset.ID, existingAsset.Type)

		// Ensure it's marked as a Nessus Scanner (update if needed)
		if existingAsset.Type != "Nessus Scanner" {
			existingAsset.Type = "Nessus Scanner"
			existingAsset.Name = fmt.Sprintf("Nessus-Scanner-%s", serverHost)
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
	hostname := fmt.Sprintf("nessus-scanner-%s-job%d-%d", strings.ReplaceAll(serverHost, ".", "-"), scanJobID, timestamp)

	asset := assetDomain.AssetDomain{
		ID:          assetID,
		Name:        fmt.Sprintf("Nessus-Scanner-%s", serverHost),
		Hostname:    hostname,
		Type:        "Nessus Scanner",
		Description: fmt.Sprintf("Nessus vulnerability scanner (Job ID: %d, URL: %s)", scanJobID, nessusMeta.URL),
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		AssetIPs:    make([]assetDomain.AssetIP, 0),
	}

	// Add IP address if server host is a valid IP
	if r.isValidIPFormat(serverHost) {
		asset.AssetIPs = append(asset.AssetIPs, assetDomain.AssetIP{
			ID:          uuid.New().String(),
			AssetID:     assetID.String(),
			InterfaceID: "",
			IP:          serverHost,
			MACAddress:  "",
		})
	}

	// Create the asset
	createdAssetID, err := r.assetRepo.Create(ctx, asset, "NESSUS")
	if err != nil {
		return "", fmt.Errorf("failed to create Nessus scanner asset: %w", err)
	}

	// Link to scan job (ignore errors - not critical)
	r.assetRepo.LinkAssetToScanJob(ctx, createdAssetID, scanJobID)

	logger.InfoContext(ctx, "Successfully created new Nessus scanner asset: %s", createdAssetID)
	return createdAssetID.String(), nil
}

// getNessusMetadata extracts Nessus metadata from scanner domain
func (r *NessusRunner) getNessusMetadata(scanner scannerDomain.ScannerDomain) (*scannerDomain.NessusMetadata, error) {
	// For Nessus scanners, prefer Domain field (for full URLs) over IP field
	nessusURL := scanner.Domain
	if nessusURL == "" {
		nessusURL = scanner.IP
	}

	nessusMeta := &scannerDomain.NessusMetadata{
		ID:        0,
		ScannerID: scanner.ID,
		URL:       nessusURL,
		Username:  scanner.Username,
		Password:  scanner.Password,
		APIKey:    scanner.ApiKey,
	}

	// Validate required fields
	if nessusMeta.URL == "" {
		return nil, fmt.Errorf("nessus URL is required")
	}

	// Ensure URL has proper format
	if !strings.HasPrefix(nessusMeta.URL, "http://") && !strings.HasPrefix(nessusMeta.URL, "https://") {
		nessusMeta.URL = "https://" + nessusMeta.URL
	}

	// Validate authentication method
	if nessusMeta.APIKey == "" && (nessusMeta.Username == "" || nessusMeta.Password == "") {
		return nil, fmt.Errorf("either API key or username/password must be provided")
	}

	return nessusMeta, nil
}

// createNessusClient creates a Nessus client based on metadata
func (r *NessusRunner) createNessusClient(metadata *scannerDomain.NessusMetadata) (*nessus.Client, error) {
	// Parse URL to ensure it's valid
	parsedURL, err := url.Parse(metadata.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid Nessus URL: %w", err)
	}

	baseURL := fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)

	// Create client based on authentication type
	// Use insecure clients since most Nessus installations use self-signed certificates
	if metadata.APIKey != "" {
		return nessus.NewClientInsecure(baseURL, metadata.APIKey), nil
	} else {
		return nessus.NewClientWithCredentialsInsecure(baseURL, metadata.Username, metadata.Password), nil
	}
}

// fetchAndProcessScans fetches all scans from Nessus and processes them
func (r *NessusRunner) fetchAndProcessScans(ctx context.Context, client *nessus.Client, scanJobID int64) error {
	log.Printf("NessusRunner: Fetching scans from Nessus")

	// Get all scans
	scansResp, err := client.GetScans(ctx, nil)
	if err != nil {
		log.Printf("NessusRunner: Failed to get scans: %v", err)
		return fmt.Errorf("failed to get scans: %w", err)
	}

	log.Printf("NessusRunner: Found %d scans to process", len(scansResp.Scans))

	// Process each scan
	for _, scan := range scansResp.Scans {
		// Check if context was cancelled
		if ctx.Err() == context.Canceled {
			log.Printf("NessusRunner: Scan processing was cancelled")
			return context.Canceled
		}

		log.Printf("NessusRunner: Processing scan: %s (ID: %d, Status: %s)", scan.Name, scan.ID, scan.Status)

		// Only process completed scans
		if scan.Status != "completed" {
			log.Printf("NessusRunner: Skipping scan %s - status: %s", scan.Name, scan.Status)
			continue
		}

		if err := r.processScan(ctx, client, scan, scanJobID); err != nil {
			log.Printf("NessusRunner: Failed to process scan %s (ID: %d): %v", scan.Name, scan.ID, err)
			// Continue with other scans instead of failing completely
			continue
		}
	}

	log.Printf("NessusRunner: Completed processing all scans")
	return nil
}

// processScan processes a single Nessus scan
func (r *NessusRunner) processScan(ctx context.Context, client *nessus.Client, scan nessus.Scan, scanJobID int64) error {
	log.Printf("NessusRunner: Processing scan details for scan: %s (ID: %d)", scan.Name, scan.ID)

	// Get detailed scan information
	scanDetails, err := client.GetScanDetails(ctx, scan.ID, true)
	if err != nil {
		log.Printf("NessusRunner: Failed to get scan details for scan %d: %v", scan.ID, err)
		return fmt.Errorf("failed to get scan details for scan %d: %w", scan.ID, err)
	}

	log.Printf("NessusRunner: Got scan details, processing %d hosts", len(scanDetails.Hosts))

	// Store scan information
	nessusScan := r.convertToNessusScan(scan, scanDetails)
	if err := r.storeNessusScan(ctx, nessusScan); err != nil {
		log.Printf("NessusRunner: Failed to store scan information: %v", err)
		// Continue processing even if scan storage fails
	} else {
		log.Printf("NessusRunner: Successfully stored scan information")
	}

	log.Printf("NessusRunner: Processing %d hosts from scan %s", len(scanDetails.Hosts), scan.Name)

	// Process each host in the scan
	for i, host := range scanDetails.Hosts {
		if ctx.Err() == context.Canceled {
			return context.Canceled
		}

		log.Printf("NessusRunner: Processing host %d/%d: %s (ID: %d)", i+1, len(scanDetails.Hosts), host.Hostname, host.HostID)

		if err := r.processHost(ctx, client, scan.ID, host, scanJobID); err != nil {
			log.Printf("NessusRunner: Failed to process host %s (ID: %d) in scan %d: %v",
				host.Hostname, host.HostID, scan.ID, err)
			// Continue with other hosts
			continue
		}
		log.Printf("NessusRunner: Successfully processed host %s", host.Hostname)
	}

	log.Printf("NessusRunner: Completed processing scan %s", scan.Name)
	return nil
}

// processHost processes a single host from a Nessus scan
func (r *NessusRunner) processHost(ctx context.Context, client *nessus.Client, scanID int, host nessus.Host, scanJobID int64) error {
	log.Printf("NessusRunner: Processing host: %s (ID: %d)", host.Hostname, host.HostID)

	// Get detailed host information
	hostDetails, err := client.GetHostDetails(ctx, scanID, host.HostID)
	if err != nil {
		log.Printf("NessusRunner: Failed to get host details for %s: %v", host.Hostname, err)
		return fmt.Errorf("failed to get host details: %w", err)
	}

	log.Printf("NessusRunner: Got host details for %s, has %d vulnerabilities", host.Hostname, len(hostDetails.Vulnerabilities))

	// Create or find asset
	asset, err := r.createOrFindAsset(ctx, hostDetails, scanJobID)
	if err != nil {
		log.Printf("NessusRunner: Failed to create or find asset for %s: %v", host.Hostname, err)
		return fmt.Errorf("failed to create or find asset: %w", err)
	}

	log.Printf("NessusRunner: Created/found asset %s for host %s", asset.ID.String(), host.Hostname)

	log.Printf("NessusRunner: Processing %d vulnerabilities for host %s", len(hostDetails.Vulnerabilities), host.Hostname)

	// Process vulnerabilities
	for i, vuln := range hostDetails.Vulnerabilities {
		if ctx.Err() == context.Canceled {
			return context.Canceled
		}

		log.Printf("NessusRunner: Processing vulnerability %d/%d: Plugin ID %d for host %s",
			i+1, len(hostDetails.Vulnerabilities), vuln.PluginID, host.Hostname)

		if err := r.processVulnerability(ctx, client, scanID, host.HostID, vuln, asset.ID, scanJobID); err != nil {
			log.Printf("NessusRunner: Failed to process vulnerability %d for host %s: %v",
				vuln.PluginID, host.Hostname, err)
			// Continue with other vulnerabilities
			continue
		}
		log.Printf("NessusRunner: Successfully processed vulnerability %d for host %s", vuln.PluginID, host.Hostname)
	}

	log.Printf("NessusRunner: Completed processing host %s", host.Hostname)
	return nil
}

// convertToNessusScan converts Nessus API types to domain types
func (r *NessusRunner) convertToNessusScan(scan nessus.Scan, details *nessus.ScanDetails) *assetDomain.NessusScan {
	nessusScan := &assetDomain.NessusScan{
		ID:          scan.ID,
		UUID:        scan.UUID,
		Name:        scan.Name,
		Status:      scan.Status,
		ScannerName: details.Info.Owner,
		Targets:     details.Info.Targets,
		FolderID:    &scan.FolderID,
	}

	// Convert timestamps
	if scan.StartTime != nil {
		startTime := time.Unix(*scan.StartTime, 0)
		nessusScan.ScanStartTime = &startTime
	}
	if scan.EndTime != nil {
		endTime := time.Unix(*scan.EndTime, 0)
		nessusScan.ScanEndTime = &endTime
	}

	return nessusScan
}

// createOrFindAsset creates a new asset or finds an existing one
func (r *NessusRunner) createOrFindAsset(ctx context.Context, hostDetails *nessus.HostDetails, scanJobID int64) (*assetDomain.AssetDomain, error) {
	// Extract basic asset information from host details
	hostname := hostDetails.Info.Hostname
	if hostname == "" {
		hostname = hostDetails.Info.HostIP
	}

	// Create asset domain object
	assetID := uuid.New()
	asset := assetDomain.AssetDomain{
		ID:           assetID,
		Name:         hostname,
		Hostname:     hostname,
		Type:         "Host", // Standardized asset type
		Description:  fmt.Sprintf("Asset discovered via Nessus scan (Job ID: %d)", scanJobID),
		OSName:       hostDetails.Info.OperatingSystem,
		DiscoveredBy: "Nessus", // Standardized discovery source
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
		AssetIPs:     []assetDomain.AssetIP{},
	}

	// Add IP address
	if hostDetails.Info.HostIP != "" {
		assetIP := assetDomain.AssetIP{
			AssetID: assetID.String(),
			IP:      hostDetails.Info.HostIP,
		}
		if hostDetails.Info.MACAddress != nil {
			assetIP.MACAddress = *hostDetails.Info.MACAddress
		}
		asset.AssetIPs = append(asset.AssetIPs, assetIP)
	}

	// Try to create the asset (this will handle duplicates)
	createdAssetID, err := r.assetRepo.Create(ctx, asset)
	if err != nil {
		// If hostname already exists, try to find the existing asset
		if err == assetDomain.ErrHostnameAlreadyExists {
			existingAssets, findErr := r.assetRepo.Get(ctx, assetDomain.AssetFilters{
				Hostname: hostname,
			})
			if findErr != nil {
				return nil, fmt.Errorf("failed to find existing asset: %w", findErr)
			}
			if len(existingAssets) > 0 {
				asset = existingAssets[0]
				logger.InfoContext(ctx, "Using existing asset: %s", asset.ID.String())

				// Link existing asset to scan job as well
				log.Printf("NessusRunner: Linking existing asset %s to scan job %d", asset.ID.String(), scanJobID)
				if err := r.assetRepo.LinkAssetToScanJob(ctx, asset.ID, scanJobID); err != nil {
					logger.WarnContext(ctx, "Failed to link existing asset to scan job: %v", err)
					// Don't fail the entire process for this, just log the warning
				} else {
					log.Printf("NessusRunner: Successfully linked existing asset %s to scan job %d", asset.ID.String(), scanJobID)
				}
			} else {
				return nil, fmt.Errorf("hostname exists but asset not found")
			}
		} else {
			return nil, fmt.Errorf("failed to create asset: %w", err)
		}
	} else {
		asset.ID = createdAssetID
		logger.InfoContext(ctx, "Created new asset: %s", asset.ID.String())
	}

	// Link asset to scan job
	log.Printf("NessusRunner: Linking asset %s to scan job %d", asset.ID.String(), scanJobID)
	if err := r.assetRepo.LinkAssetToScanJob(ctx, asset.ID, scanJobID); err != nil {
		logger.WarnContext(ctx, "Failed to link asset to scan job: %v", err)
		// Don't fail the entire process for this, just log the warning
	} else {
		log.Printf("NessusRunner: Successfully linked asset %s to scan job %d", asset.ID.String(), scanJobID)
	}

	return &asset, nil
}

func (r *NessusRunner) processVulnerability(ctx context.Context, client *nessus.Client, scanID, hostID int, vuln nessus.HostVulnerability, assetID assetDomain.AssetUUID, scanJobID int64) error {
	logger.DebugContext(ctx, "Processing vulnerability: Plugin ID %d for asset %s", vuln.PluginID, assetID.String())

	// Get detailed plugin information
	pluginDetails, err := client.GetPluginDetails(ctx, vuln.PluginID)
	if err != nil {
		logger.WarnContext(ctx, "Failed to get plugin details for plugin %d: %v", vuln.PluginID, err)
		// Create basic vulnerability info without detailed plugin data
		pluginDetails = &nessus.PluginDetails{
			PluginID:     vuln.PluginID,
			PluginName:   vuln.PluginName,
			PluginFamily: vuln.PluginFamily,
		}
	}

	// Get plugin output for this specific host/vulnerability
	var pluginOutput string
	var pluginOutputDetail *nessus.PluginOutputDetail
	pluginOutputResp, err := client.GetPluginOutput(ctx, scanID, hostID, vuln.PluginID)
	if err != nil {
		logger.WarnContext(ctx, "Failed to get plugin output for plugin %d on host %d: %v", vuln.PluginID, hostID, err)
	} else if len(pluginOutputResp.Outputs) > 0 {
		pluginOutputDetail = &pluginOutputResp.Outputs[0]
		pluginOutput = pluginOutputDetail.PluginOutput
	}

	// Create or find vulnerability
	vulnerability := r.convertToVulnerability(vuln, pluginDetails)
	storedVuln, err := r.storeVulnerability(ctx, vulnerability)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to store vulnerability: %v", err)
		return fmt.Errorf("failed to store vulnerability: %w", err)
	}

	log.Printf("NessusRunner: Successfully stored vulnerability with ID: %s", storedVuln.ID.String())

	// Extract and store port information from plugin output
	ports := r.parsePortsFromPluginOutput(pluginOutputDetail)
	var primaryPort *assetDomain.Port
	if len(ports) > 0 {
		if err := r.storeAssetPorts(ctx, assetID, ports); err != nil {
			logger.WarnContext(ctx, "Failed to store ports for asset %s: %v", assetID.String(), err)
		} else {
			log.Printf("NessusRunner: Successfully stored %d ports for asset %s", len(ports), assetID.String())
			// Use the first port as the primary port for the vulnerability
			primaryPort = &ports[0]
		}
	}

	// Create asset-vulnerability relationship using the stored vulnerability ID
	assetVuln := &assetDomain.AssetVulnerability{
		ID:                  uuid.New(),
		AssetID:             assetID,
		VulnerabilityID:     storedVuln.ID,
		PluginOutput:        pluginOutput,
		FirstDetected:       time.Now(),
		LastDetected:        time.Now(),
		Status:              "Open",
		ScanID:              &scanID,
		HostIDNessus:        &hostID,
		VulnIndexNessus:     &vuln.VulnIndex,
		SeverityIndexNessus: &vuln.SeverityIndex,
		CountNessus:         &vuln.Count,
		CreatedAt:           time.Now(),
		UpdatedAt:           time.Now(),
	}

	if primaryPort != nil {
		assetVuln.PortID = &primaryPort.ID
		assetVuln.Port = &primaryPort.PortNumber
		assetVuln.Protocol = primaryPort.Protocol
	}

	if err := r.storeAssetVulnerability(ctx, assetVuln); err != nil {
		return fmt.Errorf("failed to store asset vulnerability: %w", err)
	}

	return nil
}

func (r *NessusRunner) storeNessusScan(ctx context.Context, scan *assetDomain.NessusScan) error {
	return r.assetRepo.StoreNessusScan(ctx, *scan)
}

func (r *NessusRunner) convertToVulnerability(vuln nessus.HostVulnerability, pluginDetails *nessus.PluginDetails) *assetDomain.Vulnerability {
	vulnID := uuid.New()

	// Map severity index to severity string
	severityMap := map[int]string{
		0: "Info",
		1: "Low",
		2: "Medium",
		3: "High",
		4: "Critical",
	}

	severity := "Info"
	if sev, exists := severityMap[vuln.SeverityIndex]; exists {
		severity = sev
	}

	vulnerability := &assetDomain.Vulnerability{
		ID:            vulnID,
		PluginID:      vuln.PluginID,
		PluginName:    vuln.PluginName,
		PluginFamily:  vuln.PluginFamily,
		Severity:      severity,
		SeverityIndex: vuln.SeverityIndex,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	// Add CVSS scores if available
	if vuln.Score != nil {
		score := vuln.Score.Float64()
		vulnerability.CVSSBaseScore = &score
	}
	if vuln.VPRScore != nil {
		vprScore := vuln.VPRScore.Float64()
		vulnerability.VPRScore = &vprScore
	}
	if vuln.CPE != nil {
		vulnerability.CPE = *vuln.CPE
	}

	// Extract additional information from plugin details
	if pluginDetails != nil {
		for _, attr := range pluginDetails.Attributes {
			switch attr.AttributeName {
			case "description":
				vulnerability.Description = attr.AttributeValue
			case "solution":
				vulnerability.Solution = attr.AttributeValue
			case "synopsis":
				vulnerability.Synopsis = attr.AttributeValue
			case "see_also":
				vulnerability.SeeAlso = attr.AttributeValue
			case "cvss_vector":
				vulnerability.CVSSVector = attr.AttributeValue
			case "cvss3_vector":
				vulnerability.CVSS3Vector = attr.AttributeValue
			case "cvss3_base_score", "cvss3_score", "cvss_v3_base_score":
				// Try different possible CVSS3 attribute names
				if score, err := strconv.ParseFloat(attr.AttributeValue, 64); err == nil {
					vulnerability.CVSS3BaseScore = &score
				}
			case "cve":
				vulnerability.CVE = attr.AttributeValue
			case "bid":
				vulnerability.BID = attr.AttributeValue
			case "xref":
				vulnerability.XRef = attr.AttributeValue
			case "risk_factor":
				vulnerability.RiskFactor = attr.AttributeValue
			case "plugin_type":
				vulnerability.PluginType = attr.AttributeValue
			case "plugin_publication_date":
				if pubDate, err := time.Parse("2006/01/02", attr.AttributeValue); err == nil {
					vulnerability.PluginPublicationDate = &pubDate
				}
			case "plugin_modification_date":
				if modDate, err := time.Parse("2006/01/02", attr.AttributeValue); err == nil {
					vulnerability.PluginModificationDate = &modDate
				}
			}
		}
	}

	return vulnerability
}

func (r *NessusRunner) extractPortFromOutput(output string) *int {
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(strings.ToLower(line), "port") {
			parts := strings.Fields(line)
			for _, part := range parts {
				if strings.Contains(part, "/") {
					portStr := strings.Split(part, "/")[0]
					if port, err := strconv.Atoi(portStr); err == nil && port > 0 && port < 65536 {
						return &port
					}
				}
			}
		}
	}
	return nil
}

// parsePortsFromPluginOutput extracts port and protocol information from Nessus plugin output
func (r *NessusRunner) parsePortsFromPluginOutput(pluginOutput *nessus.PluginOutputDetail) []assetDomain.Port {
	var ports []assetDomain.Port

	// Parse ports from the ports map in plugin output
	if pluginOutput != nil && pluginOutput.Ports != nil {
		for portProto, portData := range pluginOutput.Ports {
			// Port format is typically "80/tcp" or "443/tcp"
			parts := strings.Split(portProto, "/")
			if len(parts) == 2 {
				portNum, err := strconv.Atoi(parts[0])
				if err != nil || portNum <= 0 || portNum > 65535 {
					continue
				}

				protocol := strings.ToUpper(parts[1])
				if protocol != "TCP" && protocol != "UDP" {
					continue
				}

				// Extract service information if available
				var serviceName, serviceVersion string
				if portInfo, ok := portData.(map[string]interface{}); ok {
					if svc, exists := portInfo["service"]; exists {
						if svcStr, ok := svc.(string); ok {
							serviceName = svcStr
						}
					}
					if ver, exists := portInfo["version"]; exists {
						if verStr, ok := ver.(string); ok {
							serviceVersion = verStr
						}
					}
				}

				port := assetDomain.Port{
					ID:             uuid.New().String(),
					PortNumber:     portNum,
					Protocol:       protocol,
					State:          "Up",
					ServiceName:    serviceName,
					ServiceVersion: serviceVersion,
					Description:    "Discovered by Nessus plugin via vulnerability scan",
					DiscoveredAt:   time.Now(),
				}
				ports = append(ports, port)
			}
		}
	}

	// Fallback: try to extract from plugin output text
	if len(ports) == 0 && pluginOutput != nil {
		if port := r.extractPortFromOutput(pluginOutput.PluginOutput); port != nil {
			portDomain := assetDomain.Port{
				ID:           uuid.New().String(),
				PortNumber:   *port,
				Protocol:     "TCP", // Default to TCP
				State:        "Up",
				ServiceName:  "",
				Description:  "Discovered by Nessus plugin via vulnerability scan",
				DiscoveredAt: time.Now(),
			}
			ports = append(ports, portDomain)
		}
	}

	return ports
}

func (r *NessusRunner) storeVulnerability(ctx context.Context, vulnerability *assetDomain.Vulnerability) (*assetDomain.Vulnerability, error) {
	return r.assetRepo.StoreVulnerability(ctx, *vulnerability)
}

func (r *NessusRunner) storeAssetVulnerability(ctx context.Context, assetVuln *assetDomain.AssetVulnerability) error {
	return r.assetRepo.StoreAssetVulnerability(ctx, *assetVuln)
}

func (r *NessusRunner) storeAssetPorts(ctx context.Context, assetID uuid.UUID, ports []assetDomain.Port) error {
	if len(ports) == 0 {
		return nil
	}

	// Convert domain ports to storage types
	storagePorts := make([]types.Port, len(ports))
	for i, port := range ports {
		var serviceName, serviceVersion, description *string
		if port.ServiceName != "" {
			serviceName = &port.ServiceName
		}
		if port.ServiceVersion != "" {
			serviceVersion = &port.ServiceVersion
		}
		if port.Description != "" {
			description = &port.Description
		}

		storagePorts[i] = types.Port{
			ID:             port.ID,
			AssetID:        assetID.String(),
			PortNumber:     port.PortNumber,
			Protocol:       strings.ToUpper(port.Protocol),
			State:          port.State,
			ServiceName:    serviceName,
			ServiceVersion: serviceVersion,
			Description:    description,
			DiscoveredAt:   port.DiscoveredAt,
		}
	}

	// Use the existing UpdateAssetPorts method which handles port storage
	return r.assetRepo.UpdateAssetPorts(ctx, assetID, storagePorts)
}

// extractHostFromURL extracts hostname or IP from Nessus URL
func (r *NessusRunner) extractHostFromURL(nessusURL string) string {
	if nessusURL == "" {
		return ""
	}

	// Parse URL to extract host
	if parsedURL, err := url.Parse(nessusURL); err == nil && parsedURL.Host != "" {
		// Remove port if present (e.g., "localhost:8834" -> "localhost")
		if colonIndex := strings.Index(parsedURL.Host, ":"); colonIndex > 0 {
			return parsedURL.Host[:colonIndex]
		}
		return parsedURL.Host
	}

	// Fallback: try to extract host from URL string directly
	// Handle cases like "https://192.168.1.100:8834" or "192.168.1.100"
	cleanURL := strings.TrimPrefix(nessusURL, "https://")
	cleanURL = strings.TrimPrefix(cleanURL, "http://")

	// Remove port and path
	if colonIndex := strings.Index(cleanURL, ":"); colonIndex > 0 {
		cleanURL = cleanURL[:colonIndex]
	}
	if slashIndex := strings.Index(cleanURL, "/"); slashIndex > 0 {
		cleanURL = cleanURL[:slashIndex]
	}

	return cleanURL
}

// isValidIPFormat validates if a string has proper IPv4 format (simple validation)
func (r *NessusRunner) isValidIPFormat(ip string) bool {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return false
	}

	for _, part := range parts {
		num, err := strconv.Atoi(part)
		if err != nil || num < 0 || num > 255 {
			return false
		}
	}

	return true
}
