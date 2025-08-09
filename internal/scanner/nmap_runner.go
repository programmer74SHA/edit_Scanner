package scanner

import (
	"context"
	"encoding/xml"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"time"

	"github.com/google/uuid"
	assetDomain "gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/domain"
	assetPort "gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/port"
	nmapDomain "gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanner/domain"
	scannerDomain "gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanner/domain"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/adapter/storage/types"
)

// NmapRunner handles executing Nmap scans
type NmapRunner struct {
	assetRepo     assetPort.Repo
	cancelManager *ScanCancelManager
}

// NewNmapRunner creates a new Nmap runner with asset repository
func NewNmapRunner(assetRepo assetPort.Repo) *NmapRunner {
	return &NmapRunner{
		assetRepo:     assetRepo,
		cancelManager: NewScanCancelManager(),
	}
}

// Execute implements the scheduler.Scanner interface
func (r *NmapRunner) Execute(ctx context.Context, scanner scannerDomain.ScannerDomain, scanJobID int64) error {
	return r.ExecuteNmapScan(ctx, scanner, scanJobID)
}

// ExecuteNmapScan runs an Nmap scan based on scanner configuration
func (r *NmapRunner) ExecuteNmapScan(ctx context.Context, scanner scannerDomain.ScannerDomain, scanJobID int64) error {
	log.Printf("Starting Nmap scan for scanner ID: %d, job ID: %d", scanner.ID, scanJobID)

	// Create a cancellable context
	scanCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Register this scan with the cancel manager
	r.cancelManager.RegisterScan(scanJobID, cancel)
	defer r.cancelManager.UnregisterScan(scanJobID)

	// Build Nmap command based on scanner configuration and profile
	args, err := r.buildNmapArgs(scanner)
	if err != nil {
		log.Printf("Error building Nmap args: %v", err)
		return err
	}

	log.Printf("Executing Nmap command: nmap %s", strings.Join(args, " "))

	// Execute the Nmap command with the cancellable context
	cmd := exec.CommandContext(scanCtx, "nmap", args...)
	output, err := cmd.Output()

	// Check if the context was cancelled
	if scanCtx.Err() == context.Canceled {
		log.Printf("Nmap scan was cancelled for job ID: %d", scanJobID)
		return context.Canceled
	}

	if err != nil {
		log.Printf("Error executing Nmap: %v", err)
		return err
	}

	// Parse the XML output
	var nmapRun nmapDomain.NmapRun

	if err := xml.Unmarshal(output, &nmapRun); err != nil {
		log.Printf("Error parsing Nmap XML output: %v", err)
		return err
	}

	// Process and store the results
	return r.processNmapResults(ctx, nmapRun, scanJobID)
}

// buildNmapArgs constructs the Nmap command arguments based on scanner profile and target
func (r *NmapRunner) buildNmapArgs(scanner scannerDomain.ScannerDomain) ([]string, error) {
	log.Printf("Building Nmap args for scanner: %+v", scanner)

	var args []string

	// Determine which switches to use based on scanner type
	switch scanner.Type {
	case "custom":
		// Use custom switches
		if scanner.CustomSwitches == "" {
			return nil, fmt.Errorf("custom switches are required when type is 'custom'")
		}

		log.Printf("Using custom switches: %s", scanner.CustomSwitches)

		// Parse custom switches into individual arguments
		customArgs := strings.Fields(scanner.CustomSwitches)

		// Filter out XML output arguments since we'll add our own
		for _, arg := range customArgs {
			if arg != "-oX" && arg != "-" {
				args = append(args, arg)
			}
		}

	case "profile", "":
		// Use profile arguments (default behavior)
		if scanner.NmapProfile != nil && len(scanner.NmapProfile.Arguments) > 0 {
			log.Printf("Using profile '%s' with arguments: %v", scanner.NmapProfile.Name, scanner.NmapProfile.Arguments)
			// Copy profile arguments (excluding "-oX", "-" if present, as we'll add our own)
			for _, arg := range scanner.NmapProfile.Arguments {
				if arg != "-oX" && arg != "-" {
					args = append(args, arg)
				}
			}
		} else {
			// Fallback to default arguments if no profile is available
			log.Printf("No profile available, using default arguments")
			args = []string{"-sS", "-T4", "--top-ports", "1000"}
		}

	default:
		return nil, fmt.Errorf("unsupported scanner type: %s. Valid types are: 'profile' or 'custom'", scanner.Type)
	}

	// Always add XML output to the end
	args = append(args, "-oX", "-")

	// Add target based on scan configuration
	targetArgs, err := buildNmapTargetArgs(scanner)
	if err != nil {
		log.Printf("Error building target args: %v", err)
		return nil, err
	}
	args = append(args, targetArgs...)

	log.Printf("Built Nmap args: %v", args)
	return args, nil
}

// CancelScan cancels a running scan job
func (r *NmapRunner) CancelScan(jobID int64) bool {
	return r.cancelManager.CancelScan(jobID)
}

// StatusScan checks if a scan job is currently running
func (r *NmapRunner) StatusScan(jobID int64) bool {
	return r.cancelManager.HasActiveScan(jobID)
}

// buildNmapTargetArgs constructs the target arguments for Nmap based on scanner configuration
func buildNmapTargetArgs(scanner scannerDomain.ScannerDomain) ([]string, error) {
	log.Printf("Building Nmap target args for scanner: %+v", scanner)

	var args []string

	switch scanner.Target {
	case "IP":
		if scanner.IP == "" {
			return nil, fmt.Errorf("IP target specified but no IP address provided")
		}
		args = append(args, scanner.IP)
	case "Network":
		if scanner.IP == "" {
			return nil, fmt.Errorf("Network target specified but no IP address provided")
		}
		cidr := fmt.Sprintf("%s/%d", scanner.IP, scanner.Subnet)
		args = append(args, cidr)
	case "Range":
		if scanner.StartIP == "" || scanner.EndIP == "" {
			return nil, fmt.Errorf("Range target specified but start or end IP missing")
		}

		// Extract only the last octet from the end IP if they share the same subnet
		startIPParts := strings.Split(scanner.StartIP, ".")
		endIPParts := strings.Split(scanner.EndIP, ".")

		// Check if the first three octets are the same
		if len(startIPParts) == 4 && len(endIPParts) == 4 &&
			startIPParts[0] == endIPParts[0] &&
			startIPParts[1] == endIPParts[1] &&
			startIPParts[2] == endIPParts[2] {
			// Use the shorthand notation with just the last octet of the end IP
			targetRange := fmt.Sprintf("%s-%s", scanner.StartIP, endIPParts[3])
			args = append(args, targetRange)
		} else {
			// Use full IP range notation
			targetRange := fmt.Sprintf("%s-%s", scanner.StartIP, scanner.EndIP)
			args = append(args, targetRange)
		}
	default:
		return nil, fmt.Errorf("unsupported target type: %s", scanner.Target)
	}

	log.Printf("Built Nmap target args: %v", args)
	return args, nil
}

// processNmapResults parses Nmap results and stores them in the database
func (r *NmapRunner) processNmapResults(ctx context.Context, nmapRun nmapDomain.NmapRun, scanJobID int64) error {
	log.Printf("Processing Nmap results for scan job ID: %d", scanJobID)

	for _, host := range nmapRun.Hosts {
		if host.Status.State != "up" {
			log.Printf("Skipping host with status: %s", host.Status.State)
			continue // Skip hosts that are not up
		}

		// Get the IP address
		var ipAddress string
		for _, addr := range host.Addresses {
			if addr.AddrType == "ipv4" {
				ipAddress = addr.Addr
				break
			}
		}

		if ipAddress == "" {
			log.Printf("No IPv4 address found for host, skipping")
			continue
		}

		// Get hostname if available
		hostname := ipAddress // Default to IP if no hostname
		if len(host.Hostnames.Hostname) > 0 {
			hostname = host.Hostnames.Hostname[0].Name
		}

		// Create new asset with IP in the AssetIPs array
		asset := assetDomain.AssetDomain{
			ID:           uuid.New(),
			Name:         hostname,
			Hostname:     hostname,
			Type:         "Network Device",
			Description:  fmt.Sprintf("Discovered by Nmap scan (Job ID: %d)", scanJobID),
			DiscoveredBy: "NMap", // Standardized discovery source
			CreatedAt:    time.Now(),
			UpdatedAt:    time.Now(),
			AssetIPs:     make([]assetDomain.AssetIP, 0), // Initialize AssetIPs
		}

		// Add the IP address to AssetIPs
		if ipAddress != "" {
			asset.AssetIPs = append(asset.AssetIPs, assetDomain.AssetIP{
				AssetID:    asset.ID.String(),
				IP:         ipAddress,
				MACAddress: "",
			})
		}

		// Detect OS if available
		if len(host.OS.OSMatches) > 0 && len(host.OS.OSMatches[0].OSClasses) > 0 {
			osClass := host.OS.OSMatches[0].OSClasses[0]
			asset.OSName = osClass.OSFamily
			if osClass.OSGen != "" {
				asset.OSVersion = osClass.OSGen
			}
		}

		// Store the asset with scanner type information
		assetID, err := r.assetRepo.Create(ctx, asset, "NMAP")
		if err != nil {
			log.Printf("Error creating asset: %v", err)
			continue
		}

		// Link the asset to the scan job
		err = r.assetRepo.LinkAssetToScanJob(ctx, assetID, scanJobID)
		if err != nil {
			log.Printf("Error linking asset to scan job: %v", err)
		}

		log.Printf("Successfully processed host %s (Asset ID: %s) discovered by NMAP", ipAddress, assetID)

		// Process ports for this host
		if err := r.processPortsForHost(ctx, host, assetID); err != nil {
			log.Printf("Error processing ports for host %s: %v", ipAddress, err)
			// Continue with next host even if port processing fails
		}
	}

	return nil
}

// processPortsForHost extracts port information from Nmap results and stores it
func (r *NmapRunner) processPortsForHost(ctx context.Context, host nmapDomain.Host, assetID assetDomain.AssetUUID) error {
	// Skip if no ports section or no ports
	if len(host.Ports.Ports) == 0 {
		log.Printf("No ports found for asset %s", assetID)
		return nil
	}

	log.Printf("Processing %d ports for asset %s", len(host.Ports.Ports), assetID)

	var ports []types.Port
	now := time.Now()

	// Extract port information
	for _, port := range host.Ports.Ports {
		// Skip if port is not open
		if port.State.State != "open" {
			continue
		}

		// Convert port number to int
		portNum := port.PortID

		// Create port record
		portRecord := types.Port{
			ID:           uuid.New().String(),
			AssetID:      assetID.String(),
			PortNumber:   portNum,
			Protocol:     strings.ToUpper(port.Protocol),
			State:        "Up",
			DiscoveredAt: now,
		}

		// Add service information if available
		if port.Service.Name != "" {
			portRecord.ServiceName = &port.Service.Name
		}

		if port.Service.Product != "" {
			var version string
			if port.Service.Version != "" {
				version = port.Service.Product + " " + port.Service.Version
			} else {
				version = port.Service.Product
			}
			portRecord.ServiceVersion = &version
		}

		ports = append(ports, portRecord)
	}

	// If we found any open ports, store them
	if len(ports) > 0 {
		log.Printf("Storing %d open ports for asset %s", len(ports), assetID)
		if err := r.assetRepo.UpdateAssetPorts(ctx, assetID, ports); err != nil {
			return fmt.Errorf("failed to store ports: %w", err)
		}
	} else {
		log.Printf("No open ports found for asset %s", assetID)
	}

	return nil
}

// NmapRun represents the root element of Nmap XML output
type NmapRun struct {
	XMLName xml.Name `xml:"nmaprun"`
	Hosts   []Host   `xml:"host"`
}

// Host represents a host in Nmap XML output
type Host struct {
	XMLName   xml.Name  `xml:"host"`
	Status    Status    `xml:"status"`
	Addresses []Address `xml:"address"`
	Hostnames struct {
		Hostname []struct {
			Name string `xml:"name,attr"`
			Type string `xml:"type,attr"`
		} `xml:"hostname"`
	} `xml:"hostnames"`
	Ports struct {
		Ports []struct {
			Protocol string `xml:"protocol,attr"`
			PortID   string `xml:"portid,attr"`
			State    struct {
				State string `xml:"state,attr"`
			} `xml:"state"`
			Service struct {
				Name    string `xml:"name,attr"`
				Product string `xml:"product,attr,omitempty"`
				Version string `xml:"version,attr,omitempty"`
			} `xml:"service"`
		} `xml:"port"`
	} `xml:"ports"`
	OS struct {
		OSMatches []struct {
			Name      string `xml:"name,attr"`
			Accuracy  string `xml:"accuracy,attr"`
			OSClasses []struct {
				Type     string `xml:"type,attr"`
				Vendor   string `xml:"vendor,attr"`
				OSFamily string `xml:"osfamily,attr"`
				OSGen    string `xml:"osgen,attr"`
			} `xml:"osclass"`
		} `xml:"osmatch"`
	} `xml:"os"`
}

// Status represents the status of a host
type Status struct {
	State string `xml:"state,attr"`
}

type Address struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
}
