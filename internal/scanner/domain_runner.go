package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/google/uuid"
	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/domain"
	assetDomain "gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/domain"
	assetPort "gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/port"
	scannerDomain "gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanner/domain"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/logger"
)

// ComputerEntry represents an LDAP computer with attributes and resolved IPs
type ComputerEntry struct {
	DN              string              `json:"dn"`
	Attributes      map[string][]string `json:"attributes"`
	IPs             []string            `json:"ips,omitempty"`
	LastLogon       string              `json:"last_logon,omitempty"`
	OperatingSystem string              `json:"os,omitempty"`
	Status          string              `json:"status,omitempty"`
}

// DomainRunner handles executing domain LDAP scans
type DomainRunner struct {
	assetRepo     assetPort.Repo
	cancelManager *ScanCancelManager
}

// NewDomainRunner creates a new Domain runner with asset repository
func NewDomainRunner(assetRepo assetPort.Repo) *DomainRunner {
	return &DomainRunner{
		assetRepo:     assetRepo,
		cancelManager: NewScanCancelManager(),
	}
}

// Execute implements the scheduler.Scanner interface
func (r *DomainRunner) Execute(ctx context.Context, scanner scannerDomain.ScannerDomain, scanJobID int64) error {
	return r.ExecuteDomainScan(ctx, scanner, scanJobID)
}

// ExecuteDomainScan runs a domain LDAP scan based on scanner configuration
func (r *DomainRunner) ExecuteDomainScan(ctx context.Context, scanner scannerDomain.ScannerDomain, scanJobID int64) error {
	logger.InfoContext(ctx, "[DomainScanner] Starting domain LDAP scan for scanner ID: %d, job ID: %d", scanner.ID, scanJobID)
	logger.InfoContext(ctx, "[DomainScanner] Scanner details: IP=%s, Port=%s, Domain=%s, Username=%s, AuthType=%s, Protocol=%s",
		scanner.IP, scanner.Port, scanner.Domain, scanner.Username, scanner.AuthenticationType, scanner.Protocol)

	// Create a cancellable context
	scanCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Register this scan with the cancel manager
	r.cancelManager.RegisterScan(scanJobID, cancel)
	defer r.cancelManager.UnregisterScan(scanJobID)

	// Create LDAP/Domain Controller scanner asset
	logger.InfoContext(ctx, "[DomainScanner] Creating LDAP/Domain Controller scanner asset...")
	scannerAssetID, err := r.createLDAPScannerAsset(scanCtx, scanner, scanJobID)
	if err != nil {
		logger.InfoContext(ctx, "[DomainScanner] Failed to create LDAP scanner asset: %v", err)
		return fmt.Errorf("failed to create LDAP scanner asset: %w", err)
	}
	logger.InfoContext(ctx, "[DomainScanner] Successfully created/updated LDAP scanner asset with ID: %s", scannerAssetID)

	// Parse port number
	port, err := strconv.Atoi(scanner.Port)
	if err != nil {
		logger.InfoContext(ctx, "[DomainScanner] Invalid port number: %v", err)
		return fmt.Errorf("invalid port number: %w", err)
	}

	// Build connection address
	ldapHost := fmt.Sprintf("%s:%d", scanner.IP, port)

	// Normalize authentication type to uppercase for consistent comparison
	authType := strings.ToUpper(strings.TrimSpace(scanner.AuthenticationType))

	// Format username based on domain and authentication type
	bindUsername := r.formatUsername(scanner.Username, scanner.Domain, authType)
	logger.InfoContext(ctx, "[DomainScanner] Using formatted username: %s", bindUsername)

	// Establish connection to LDAP server based on authentication type
	var conn *ldap.Conn

	// Determine if TLS should be used based on port
	useTLS := port == 636 // Default LDAPS port

	switch authType {
	case scannerDomain.AuthTypeSimple:
		logger.InfoContext(ctx, "[DomainScanner] Using Simple authentication")
		conn, err = r.connectWithSimpleAuth(ldapHost, useTLS, bindUsername, scanner.Password)

	case scannerDomain.AuthTypeNTLM:
		logger.InfoContext(ctx, "[DomainScanner] Using NTLM authentication")
		// For NTLM, we often need to handle it differently
		conn, err = r.connectWithNTLMAuth(ldapHost, useTLS, bindUsername, scanner.Password, scanner.Domain)

	case scannerDomain.AuthTypeGSSAPI:
		logger.InfoContext(ctx, "[DomainScanner] Using GSSAPI (Kerberos) authentication")
		conn, err = r.connectWithGSSAPIAuth(ldapHost, useTLS, bindUsername, scanner.Password, scanner.Domain)

	case scannerDomain.AuthTypeDIGESTMD5:
		logger.InfoContext(ctx, "[DomainScanner] Using DIGEST-MD5 authentication")
		conn, err = r.connectWithDigestMD5Auth(ldapHost, useTLS, bindUsername, scanner.Password, scanner.Domain)

	default:
		logger.InfoContext(ctx, "[DomainScanner] Unknown authentication type: %s, defaulting to Simple authentication", authType)
		conn, err = r.connectWithSimpleAuth(ldapHost, useTLS, bindUsername, scanner.Password)
	}

	if err != nil {
		logger.InfoContext(ctx, "[DomainScanner] LDAP connection failed: %v", err)
		return fmt.Errorf("LDAP connection failed: %w", err)
	}

	if conn == nil {
		return fmt.Errorf("failed to establish LDAP connection with %s authentication", authType)
	}

	defer conn.Close()
	logger.InfoContext(ctx, "[DomainScanner] Successfully established LDAP connection")

	// Extract DC components from domain
	domainComponents := r.extractDCFromDomain(scanner.Domain)
	baseDN := domainComponents
	if baseDN == "" {
		baseDN = "DC=" + strings.ReplaceAll(scanner.Domain, ".", ",DC=")
	}

	logger.InfoContext(ctx, "[DomainScanner] Using base DN: %s", baseDN)

	// Define attributes to search for
	attributes := []string{
		"cn", "name", "dNSHostName", "distinguishedName",
		"objectGUID", "objectSid", "operatingSystem",
		"operatingSystemVersion", "lastLogonTimestamp",
		"whenCreated", "whenChanged", "description",
	}

	// Prepare search filter for computers
	filter := "(&(objectClass=computer))"

	// Set up paging control
	pageSize := uint32(100)
	pagingControl := ldap.NewControlPaging(pageSize)

	// Create search request
	searchRequest := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		filter,
		attributes,
		[]ldap.Control{pagingControl},
	)

	var computers []ComputerEntry

	// Perform paged search
	for {
		// Check if the context was cancelled
		if scanCtx.Err() == context.Canceled {
			logger.InfoContext(ctx, "[DomainScanner] Domain scan was cancelled for job ID: %d", scanJobID)
			return context.Canceled
		}

		// Execute search with paging
		searchRequest.Controls = []ldap.Control{pagingControl}
		sr, err := conn.Search(searchRequest)
		if err != nil {
			logger.InfoContext(ctx, "[DomainScanner] Search failed: %v", err)
			return fmt.Errorf("LDAP search failed: %w", err)
		}

		logger.InfoContext(ctx, "[DomainScanner] Found %d computers in current page", len(sr.Entries))

		// Process each entry in the page
		for _, entry := range sr.Entries {
			computer := r.processLdapEntry(entry, scanner.Domain)
			if len(computer.IPs) > 0 {
				logger.InfoContext(ctx, "[DomainScanner] Found computer %s with IPs: %v", computer.Attributes["name"], computer.IPs)
			}
			computers = append(computers, computer)
		}

		// Handle pagination
		var pagingResult *ldap.ControlPaging
		control := ldap.FindControl(sr.Controls, ldap.ControlTypePaging)
		if control == nil {
			logger.InfoContext(ctx, "[DomainScanner] Server did not return paging control")
			break
		}

		var ok bool
		if pagingResult, ok = control.(*ldap.ControlPaging); !ok {
			logger.InfoContext(ctx, "[DomainScanner] Cannot convert control to paging control")
			break
		}

		if len(pagingResult.Cookie) == 0 {
			break // No more pages
		}

		pagingControl.SetCookie(pagingResult.Cookie)
		logger.InfoContext(ctx, "[DomainScanner] Moving to next page of results...")
	}

	// Process the computers and store them as assets
	logger.InfoContext(ctx, "[DomainScanner] Processing %d computers", len(computers))
	return r.processComputersToAssets(scanCtx, computers, scanJobID)
}

// formatUsername formats the username based on domain and authentication type
func (r *DomainRunner) formatUsername(username, domain, authType string) string {
	// If username already contains @ symbol, return as is
	if strings.Contains(username, "@") {
		return username
	}

	// Handle username format based on auth type
	switch authType {
	case scannerDomain.AuthTypeSimple:
		// For Simple auth with AD, typically use username@domain.com
		if domain != "" {
			return fmt.Sprintf("%s@%s", username, domain)
		}

	case scannerDomain.AuthTypeNTLM:
		// For NTLM, often format is DOMAIN\username
		if domain != "" {
			// Convert domain to uppercase for NTLM
			return fmt.Sprintf("%s\\%s", strings.ToUpper(domain), username)
		}

	case scannerDomain.AuthTypeGSSAPI:
		// For GSSAPI (Kerberos), username@REALM.COM (uppercase realm)
		if domain != "" {
			return fmt.Sprintf("%s@%s", username, strings.ToUpper(domain))
		}

	case scannerDomain.AuthTypeDIGESTMD5:
		// For DIGEST-MD5, usually username@domain
		if domain != "" {
			return fmt.Sprintf("%s@%s", username, domain)
		}
	}

	// Default case - return username as is
	return username
}

// connectWithSimpleAuth establishes a connection using simple authentication
func (r *DomainRunner) connectWithSimpleAuth(ldapHost string, useTLS bool, username, password string) (*ldap.Conn, error) {
	var conn *ldap.Conn
	var err error

	// Connect using TLS if specified
	if useTLS {
		logger.Info("[DomainScanner] Using LDAPS (TLS) connection with Simple auth")
		conn, err = ldap.DialTLS("tcp", ldapHost, &tls.Config{InsecureSkipVerify: true})
	} else {
		logger.Info("[DomainScanner] Using standard LDAP connection with Simple auth")
		conn, err = ldap.Dial("tcp", ldapHost)
	}

	if err != nil {
		return nil, err
	}

	// Bind with simple auth
	err = conn.Bind(username, password)
	if err != nil {
		conn.Close()
		return nil, err
	}

	return conn, nil
}

// connectWithNTLMAuth establishes a connection using NTLM authentication
// Note: The standard go-ldap library doesn't support NTLM directly
func (r *DomainRunner) connectWithNTLMAuth(ldapHost string, useTLS bool, username, password, domain string) (*ldap.Conn, error) {
	logger.Info("[DomainScanner] NTLM auth requested. Using NTLM-like approach with Simple auth")

	// For NTLM, we would typically set environment variables for external command
	// or use an NTLM-capable library. Here we're simulating it.

	// Set environment variables that might be used by NTLM-aware applications
	os.Setenv("KRB5CCNAME", "/tmp/krb5cc_"+strconv.Itoa(os.Getuid()))
	os.Setenv("NTLM_USER", username)
	os.Setenv("NTLM_DOMAIN", domain)

	// Extract username without domain part for standard binding
	var simpleUsername string
	if parts := strings.Split(username, "\\"); len(parts) > 1 {
		simpleUsername = parts[1]
	} else {
		simpleUsername = username
	}

	// Since we don't have direct NTLM support, try Simple auth but with NTLM formatting
	return r.connectWithSimpleAuth(ldapHost, useTLS, simpleUsername, password)
}

// connectWithGSSAPIAuth establishes a connection using GSSAPI (Kerberos) authentication
func (r *DomainRunner) connectWithGSSAPIAuth(ldapHost string, useTLS bool, username, password, domain string) (*ldap.Conn, error) {
	logger.Info("[DomainScanner] GSSAPI (Kerberos) auth requested. Setting up with Simple auth fallback")

	// In a real implementation, we would:
	// 1. Initialize Kerberos context
	// 2. Get a Kerberos ticket
	// 3. Use it for SASL GSSAPI authentication

	// Set environment variables that might be used by Kerberos
	os.Setenv("KRB5CCNAME", "/tmp/krb5cc_"+strconv.Itoa(os.Getuid()))
	os.Setenv("KRB5_KTNAME", "/etc/krb5.keytab")

	// Since we don't have direct GSSAPI support, use Simple auth as fallback
	logger.Info("[DomainScanner] Falling back to Simple auth (GSSAPI not directly supported)")
	return r.connectWithSimpleAuth(ldapHost, useTLS, username, password)
}

// connectWithDigestMD5Auth establishes a connection using DIGEST-MD5 authentication
func (r *DomainRunner) connectWithDigestMD5Auth(ldapHost string, useTLS bool, username, password, domain string) (*ldap.Conn, error) {
	logger.Info("[DomainScanner] DIGEST-MD5 auth requested. Setting up with Simple auth fallback")

	// In a real implementation, we would:
	// 1. Connect to LDAP server
	// 2. Start SASL DIGEST-MD5 negotiation
	// 3. Complete the DIGEST-MD5 handshake

	// Since we don't have direct DIGEST-MD5 support, use Simple auth as fallback
	logger.Info("[DomainScanner] Falling back to Simple auth (DIGEST-MD5 not directly supported)")
	return r.connectWithSimpleAuth(ldapHost, useTLS, username, password)
}

// extractDCFromDomain tries to extract proper DC components from domain name
func (r *DomainRunner) extractDCFromDomain(domain string) string {
	if domain == "" {
		return ""
	}

	// If already in DC format, return as is
	if strings.HasPrefix(strings.ToUpper(domain), "DC=") {
		return domain
	}

	// Convert domain.local to DC=domain,DC=local
	parts := strings.Split(domain, ".")
	var dcParts []string
	for _, part := range parts {
		if part != "" {
			dcParts = append(dcParts, fmt.Sprintf("DC=%s", part))
		}
	}

	return strings.Join(dcParts, ",")
}

// processLdapEntry converts an LDAP entry to a ComputerEntry
func (r *DomainRunner) processLdapEntry(entry *ldap.Entry, domainName string) ComputerEntry {
	data := ComputerEntry{
		DN:         entry.DN,
		Attributes: map[string][]string{},
	}

	// Store all attributes
	for _, attr := range entry.Attributes {
		data.Attributes[attr.Name] = attr.Values
	}

	// Extract hostname
	var hostname string
	if v, ok := data.Attributes["dNSHostName"]; ok && len(v) > 0 {
		hostname = v[0]
	} else if v, ok := data.Attributes["name"]; ok && len(v) > 0 {
		// If no DNS hostname, use the name and assume it's in the domain
		hostname = v[0]
		// Append domain if not already present and domain is provided
		if domainName != "" && !strings.Contains(hostname, ".") {
			hostname = hostname + "." + domainName
		}
	}

	// Extract operating system information
	if v, ok := data.Attributes["operatingSystem"]; ok && len(v) > 0 {
		data.OperatingSystem = v[0]
		if osv, ok := data.Attributes["operatingSystemVersion"]; ok && len(osv) > 0 {
			data.OperatingSystem += " " + osv[0]
		}
	}

	// Extract and format lastLogonTimestamp
	if v, ok := data.Attributes["lastLogonTimestamp"]; ok && len(v) > 0 {
		// Windows stores time as number of 100-nanosecond intervals since January 1, 1601 UTC
		if timestamp, err := formatADTimestamp(v[0]); err == nil {
			data.LastLogon = timestamp
		}
	}

	// Resolve hostname to IP addresses using DNS
	if hostname != "" {
		ips := r.resolveHostname(hostname)
		if len(ips) > 0 {
			data.IPs = ips
			data.Status = "Active"
		} else {
			data.Status = "Inactive"
			logger.Info("[DomainScanner] Could not resolve IP for %s", hostname)
		}
	}

	return data
}

// resolveHostname resolves a hostname to IP addresses using DNS
func (r *DomainRunner) resolveHostname(hostname string) []string {
	logger.Info("[DomainScanner] Resolving hostname: %s", hostname)

	// Try with DNS lookups with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	var ips []string

	// Try standard DNS lookup first
	addrs, err := net.DefaultResolver.LookupHost(ctx, hostname)
	if err != nil {
		logger.Info("[DomainScanner] Standard DNS lookup failed for %s: %v", hostname, err)

		// Try variants of the hostname
		variants := []string{
			strings.ToLower(hostname),                // lowercase
			strings.ToUpper(hostname),                // UPPERCASE
			strings.Title(strings.ToLower(hostname)), // Title Case
		}

		for _, variant := range variants {
			addrs, err := net.DefaultResolver.LookupHost(ctx, variant)
			if err == nil && len(addrs) > 0 {
				logger.Info("[DomainScanner] Resolved variant %s to %v", variant, addrs)
				return addrs
			}
		}
	} else {
		// Filter to only include IPv4 addresses
		for _, addr := range addrs {
			ip := net.ParseIP(addr)
			if ip != nil && ip.To4() != nil {
				ips = append(ips, addr)
			}
		}

		if len(ips) > 0 {
			logger.Info("[DomainScanner] Resolved %s to %v", hostname, ips)
			return ips
		}
	}

	// If no resolution worked, return empty slice
	return []string{}
}

// isValidIPFormat validates if a string has proper IPv4 format
func (r *DomainRunner) isValidIPFormat(ip string) bool {
	// Very basic IPv4 validation - checks if string has 1-3 digits separated by dots
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return false
	}

	for _, part := range parts {
		// Each part should be a number between 0-255
		num, err := strconv.Atoi(part)
		if err != nil || num < 0 || num > 255 {
			return false
		}
	}

	return true
}

// Get MAC address for IP by checking ARP tables
func (r *DomainRunner) getMACAddress(ip string) string {
	logger.Info("[DomainScanner] Attempting to get MAC address for IP: %s", ip)

	// Try using ARP table first
	mac, err := r.getMACFromARP(ip)
	if err == nil && mac != "" {
		logger.Info("[DomainScanner] Found MAC address from ARP: %s", mac)
		return mac
	}

	// If ARP didn't work, try to ping the host to populate ARP cache
	// This is a common technique to ensure the ARP entry exists
	logger.Info("[DomainScanner] No MAC in ARP cache, pinging IP to populate ARP table")
	r.pingHost(ip)

	// Try ARP again after ping
	mac, err = r.getMACFromARP(ip)
	if err == nil && mac != "" {
		logger.Info("[DomainScanner] Found MAC address after ping: %s", mac)
		return mac
	}

	logger.Info("[DomainScanner] Could not determine MAC address for IP: %s", ip)
	return ""
}

// Get MAC address from ARP table based on OS
func (r *DomainRunner) getMACFromARP(ip string) (string, error) {
	var cmd *exec.Cmd
	var macRegex *regexp.Regexp

	switch runtime.GOOS {
	case "windows":
		// Windows command to get ARP table
		cmd = exec.Command("arp", "-a", ip)
		macRegex = regexp.MustCompile(`([0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2})`)
	case "darwin", "linux", "freebsd":
		// Unix/Linux/macOS command
		cmd = exec.Command("arp", "-n", ip)
		macRegex = regexp.MustCompile(`([0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2})`)
	default:
		return "", fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	}

	// Execute the command
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", err
	}

	// Parse the output to find MAC address
	matches := macRegex.FindStringSubmatch(string(output))
	if len(matches) > 1 {
		return strings.ToUpper(matches[1]), nil
	}

	return "", fmt.Errorf("MAC address not found in ARP table for IP: %s", ip)
}

// Ping host to populate ARP cache
func (r *DomainRunner) pingHost(ip string) {
	var cmd *exec.Cmd

	// Different ping commands based on OS
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("ping", "-n", "1", "-w", "500", ip)
	default:
		cmd = exec.Command("ping", "-c", "1", "-W", "1", ip)
	}

	// Execute ping but don't care about the result
	// We just want to populate the ARP cache
	_ = cmd.Run()
}

// processComputersToAssets converts ComputerEntry objects to Assets and stores them
func (r *DomainRunner) processComputersToAssets(ctx context.Context, computers []ComputerEntry, scanJobID int64) error {
	logger.InfoContext(ctx, "[DomainScanner] Processing %d computers", len(computers))

	totalAssets := 0
	assetsWithIPs := 0

	for i, computer := range computers {
		// Check for cancellation periodically
		if i%10 == 0 && ctx.Err() == context.Canceled {
			logger.InfoContext(ctx, "[DomainScanner] Domain scan was cancelled during computer processing for job ID: %d", scanJobID)
			return context.Canceled
		}

		// Default asset values
		hostname := "Unknown"
		if v, ok := computer.Attributes["dNSHostName"]; ok && len(v) > 0 {
			hostname = v[0]
		} else if v, ok := computer.Attributes["name"]; ok && len(v) > 0 {
			hostname = v[0]
		}

		// Get asset name
		name := hostname
		if v, ok := computer.Attributes["name"]; ok && len(v) > 0 {
			name = v[0]
		}

		// Computer description
		description := ""
		if v, ok := computer.Attributes["description"]; ok && len(v) > 0 {
			description = v[0]
		}

		// Create asset domain object
		asset := assetDomain.AssetDomain{
			ID:           uuid.New(),
			Name:         name,
			Hostname:     hostname,
			Type:         "Domain device",
			Description:  fmt.Sprintf("Domain device discovered by LDAP scan (Job ID: %d). %s", scanJobID, description),
			DiscoveredBy: "LDAP",
			CreatedAt:    time.Now(),
			UpdatedAt:    time.Now(),
		}

		// Set OS name and version
		if computer.OperatingSystem != "" {
			osInfo := strings.Split(computer.OperatingSystem, " ")
			if len(osInfo) > 1 {
				asset.OSName = strings.Join(osInfo[:len(osInfo)-1], " ")
				asset.OSVersion = osInfo[len(osInfo)-1]
			} else {
				asset.OSName = computer.OperatingSystem
			}
		}

		// Set IP addresses from DNS resolution results
		if len(computer.IPs) > 0 {
			// Filter validated IPs
			var validIPs []string
			for _, ip := range computer.IPs {
				if r.isValidIPFormat(ip) {
					validIPs = append(validIPs, ip)
				} else {
					logger.InfoContext(ctx, "[DomainScanner] Skipping invalid IP format: %s for computer %s", ip, name)
				}
			}

			// Create AssetIP objects for each valid IP
			var assetIPList []domain.AssetIP
			for _, ip := range validIPs {
				// Get MAC address for this IP
				macAddress := r.getMACAddress(ip)

				assetIPList = append(assetIPList, domain.AssetIP{
					AssetID:    asset.ID.String(),
					IP:         ip,
					MACAddress: macAddress, // Store the MAC address
				})

				if macAddress != "" {
					logger.InfoContext(ctx, "[DomainScanner] Asset %s IP %s has MAC: %s", name, ip, macAddress)
				}
			}
			asset.AssetIPs = assetIPList

			if len(validIPs) > 0 {
				assetsWithIPs++
				logger.InfoContext(ctx, "[DomainScanner] Asset %s has %d valid IPs", name, len(validIPs))
			} else {
				logger.InfoContext(ctx, "[DomainScanner] Asset %s has no valid IPs after filtering", name)
			}
		} else {
			// Empty slice - no IP addresses will be created in asset_ips
			asset.AssetIPs = []domain.AssetIP{}
			logger.InfoContext(ctx, "[DomainScanner] Asset %s has no IPs from DNS resolution", name)
		}

		// Store the asset
		logger.InfoContext(ctx, "[DomainScanner] Creating asset for computer: %s", name)
		assetID, err := r.assetRepo.Create(ctx, asset, "DOMAIN")
		if err != nil {
			logger.InfoContext(ctx, "[DomainScanner] Error creating asset: %v", err)
			continue
		}

		// Link the asset to the scan job
		err = r.assetRepo.LinkAssetToScanJob(ctx, assetID, scanJobID)
		if err != nil {
			logger.InfoContext(ctx, "[DomainScanner] Error linking asset to scan job: %v", err)
			continue
		}

		logger.InfoContext(ctx, "[DomainScanner] Successfully processed computer %s (Asset ID: %s) discovered by DOMAIN", name, assetID)
		totalAssets++
	}

	logger.InfoContext(ctx, "[DomainScanner] Completed processing %d computers. Created %d assets, %d with IP addresses",
		len(computers), totalAssets, assetsWithIPs)
	return nil
}

// CancelScan cancels a running scan job
func (r *DomainRunner) CancelScan(jobID int64) bool {
	return r.cancelManager.CancelScan(jobID)
}

// StatusScan checks if a scan job is currently running
func (r *DomainRunner) StatusScan(jobID int64) bool {
	return r.cancelManager.HasActiveScan(jobID)
}

// createLDAPScannerAsset creates an asset representing the LDAP/Domain Controller server itself
func (r *DomainRunner) createLDAPScannerAsset(ctx context.Context, scanner scannerDomain.ScannerDomain, scanJobID int64) (string, error) {
	logger.InfoContext(ctx, "[DomainScanner] Creating/updating LDAP scanner asset for IP: %s, Domain: %s", scanner.IP, scanner.Domain)

	// First, check if an asset already exists with this IP
	filter := domain.AssetFilters{IP: scanner.IP}
	assets, err := r.assetRepo.Get(ctx, filter)
	if err == nil && len(assets) > 0 {
		// Found existing asset - use it directly
		existingAsset := assets[0]
		logger.InfoContext(ctx, "[DomainScanner] Found existing asset: ID=%s, Type=%s - reusing for LDAP scan",
			existingAsset.ID, existingAsset.Type)

		// Ensure it's marked as a LDAP/Domain Scanner (update if needed)
		if existingAsset.Type != "Domain Scanner" {
			existingAsset.Type = "Domain Scanner"
			existingAsset.Name = fmt.Sprintf("DS-%s", scanner.IP)
			existingAsset.UpdatedAt = time.Now()
			r.assetRepo.Update(ctx, existingAsset) // Ignore errors - asset exists and that's what matters
		}

		// Link to scan job (ignore errors - not critical)
		r.assetRepo.LinkAssetToScanJob(ctx, existingAsset.ID, scanJobID)

		logger.InfoContext(ctx, "[DomainScanner] Successfully reusing existing asset: %s", existingAsset.ID)
		return existingAsset.ID.String(), nil
	}

	// No existing asset found, create new one
	assetID := uuid.New()
	timestamp := time.Now().Unix()
	hostname := fmt.Sprintf("ldap-server-%s-job%d-%d", strings.ReplaceAll(scanner.IP, ".", "-"), scanJobID, timestamp)

	// Determine asset type and name based on whether domain is provided
	assetType := "Domain Scanner"
	assetName := fmt.Sprintf("DS-%s-%s", scanner.Domain, scanner.IP)
	assetDesc := fmt.Sprintf("Domain Scanner for %s (Job ID: %d, IP: %s)", scanner.Domain, scanJobID, scanner.IP)

	asset := domain.AssetDomain{
		ID:          assetID,
		Name:        assetName,
		Domain:      scanner.Domain,
		Hostname:    hostname,
		Type:        assetType,
		Description: assetDesc,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		AssetIPs:    make([]domain.AssetIP, 0),
	}

	if r.isValidIPFormat(scanner.IP) {
		asset.AssetIPs = append(asset.AssetIPs, domain.AssetIP{
			ID:          uuid.New().String(),
			AssetID:     assetID.String(),
			InterfaceID: "",
			IP:          scanner.IP,
			MACAddress:  "",
		})
	}

	// Create the asset
	createdAssetID, err := r.assetRepo.Create(ctx, asset, "DOMAIN")
	if err != nil {
		return "", fmt.Errorf("failed to create LDAP scanner asset: %w", err)
	}

	// Link to scan job (ignore errors - not critical)
	r.assetRepo.LinkAssetToScanJob(ctx, createdAssetID, scanJobID)

	logger.InfoContext(ctx, "[DomainScanner] Successfully created new LDAP scanner asset: %s", createdAssetID)
	return createdAssetID.String(), nil
}

// formatADTimestamp converts Active Directory timestamp to human readable format
func formatADTimestamp(adTimestamp string) (string, error) {
	// Convert string to int64
	timestamp, err := strconv.ParseInt(adTimestamp, 10, 64)
	if err != nil {
		return "", err
	}

	// Windows timestamps are 100-nanosecond intervals since January 1, 1601 UTC
	// Convert to Unix timestamp (seconds since January 1, 1970 UTC)
	// 116444736000000000 is the number of 100-nanosecond intervals between 1601 and 1970
	unixTime := (timestamp - 116444736000000000) / 10000000

	// Convert to time.Time
	t := time.Unix(unixTime, 0)

	// Format as human-readable
	return t.Format("2006-01-02 15:04:05"), nil
}
