package scanner

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	scannerDomain "gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanner/domain"
	scannerPort "gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanner/port"

	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/logger"
)

// SwitchRunner orchestrates the switch device scanning process using unified repository
type SwitchRunner struct {
	repo          scannerPort.Repo // Use unified repository interface
	deviceFactory scannerDomain.SwitchDeviceClientFactory
	cancelManager *ScanCancelManager
}

// NewSwitchRunner creates a new switch runner with unified repository approach
func NewSwitchRunner(
	repo scannerPort.Repo, // Now accepts unified repository
	deviceFactory scannerDomain.SwitchDeviceClientFactory,
	cancelManager *ScanCancelManager,
) *SwitchRunner {
	return &SwitchRunner{
		repo:          repo,
		deviceFactory: deviceFactory,
		cancelManager: cancelManager,
	}
}

// Execute implements the scheduler.Scanner interface
func (r *SwitchRunner) Execute(ctx context.Context, scanner scannerDomain.ScannerDomain, scanJobID int64) error {
	return r.ExecuteSwitchScan(ctx, scanner, scanJobID)
}

// ExecuteSwitchScan runs a switch device scan based on scanner configuration
func (r *SwitchRunner) ExecuteSwitchScan(ctx context.Context, scanner scannerDomain.ScannerDomain, scanJobID int64) error {
	logger.InfoContext(ctx, "[SwitchRunner] Starting switch scan for scanner ID: %d, job ID: %d", scanner.ID, scanJobID)

	// Create cancellable context and register scan
	scanCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	r.cancelManager.RegisterScan(scanJobID, cancel)
	defer r.cancelManager.UnregisterScan(scanJobID)

	startTime := time.Now()

	// Get or create the asset ID for this scanner
	assetID, err := r.getOrCreateAssetForScanner(ctx, scanner)
	if err != nil {
		logger.InfoContext(ctx, "[SwitchRunner] Error getting/creating asset ID for scanner: %v", err)
		return fmt.Errorf("failed to get/create asset for scanner: %w", err)
	}

	logger.InfoContext(ctx, "[SwitchRunner] Using asset ID: %s for scanner ID: %d", assetID.String(), scanner.ID)

	// Execute the scan
	result, err := r.performScan(scanCtx, scanner, scanJobID)
	if err != nil {
		if scanCtx.Err() == context.Canceled {
			logger.InfoContext(ctx, "[SwitchRunner] Switch scan was cancelled for job ID: %d", scanJobID)
			return context.Canceled
		}
		logger.InfoContext(ctx, "[SwitchRunner] Error executing switch scan: %v", err)
		return fmt.Errorf("scan execution failed: %w", err)
	}

	result.ScanDuration = time.Since(startTime)
	result.ScanJobID = scanJobID
	result.AssetID = assetID.String()

	// Process and store results using unified repository
	if err := r.processResults(ctx, result, assetID); err != nil {
		logger.InfoContext(ctx, "[SwitchRunner] Error processing scan results: %v", err)
		return fmt.Errorf("failed to process scan results: %w", err)
	}

	logger.InfoContext(ctx, "[SwitchRunner] Successfully completed switch scan for scanner ID: %d", scanner.ID)
	return nil
}

// performScan executes the actual device scan using the device client factory
func (r *SwitchRunner) performScan(ctx context.Context, scanner scannerDomain.ScannerDomain, scanJobID int64) (*scannerDomain.SwitchScanResult, error) {
	logger.InfoContext(ctx, "[SwitchRunner] Performing switch scan on device: %s:%s", scanner.IP, r.getDefaultPort(scanner))

	// Validate scanner configuration
	if err := r.validateScannerConfig(scanner); err != nil {
		return nil, fmt.Errorf("invalid scanner configuration: %w", err)
	}

	// Create device connection configuration
	config := scannerDomain.SwitchConnectionConfig{
		Host:              scanner.IP,
		Port:              r.getDefaultPortInt(scanner),
		Protocol:          scanner.Protocol,
		Username:          scanner.Username,
		Password:          scanner.Password,
		ConnectionTimeout: 30 * time.Second,
		CommandTimeout:    30 * time.Second,
		MaxRetries:        3,
	}

	// Create appropriate device client based on device type
	client, err := r.deviceFactory.CreateClient(scanner.Type, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create device client for type %s: %w", scanner.Type, err)
	}
	defer func() {
		if closeErr := client.Close(); closeErr != nil {
			logger.InfoContext(ctx, "[SwitchRunner] Warning: Error closing client connection: %v", closeErr)
		}
	}()

	// Connect to the device
	logger.InfoContext(ctx, "[SwitchRunner] Attempting to connect to %s:%d", config.Host, config.Port)
	if err := client.Connect(ctx, config); err != nil {
		return nil, fmt.Errorf("connection failed to %s:%d: %w", config.Host, config.Port, err)
	}

	// Execute commands and get output
	commands := client.GetDefaultCommands()
	logger.InfoContext(ctx, "[SwitchRunner] Executing %d commands on device", len(commands))

	output, err := client.ExecuteCommands(ctx, commands)
	if err != nil {
		return nil, fmt.Errorf("command execution failed: %w", err)
	}

	if output == "" {
		return nil, fmt.Errorf("no output received from device commands")
	}

	logger.InfoContext(ctx, "[SwitchRunner] Received %d bytes of output, parsing...", len(output))

	// Parse output using the client
	result, err := client.ParseOutput(output)
	if err != nil {
		return nil, fmt.Errorf("output parsing failed: %w", err)
	}

	if result == nil {
		return nil, fmt.Errorf("parsing returned nil result")
	}

	// Set scan metadata
	result.DeviceIP = scanner.IP
	result.ConnectionMethod = scanner.Protocol
	result.ScanJobID = scanJobID

	logger.InfoContext(ctx, "[SwitchRunner] Successfully parsed scan results: %d interfaces, %d VLANs, %d neighbors",
		len(result.Interfaces), len(result.VLANs), len(result.Neighbors))

	return result, nil
}

// processResults processes scan results using the unified repository
func (r *SwitchRunner) processResults(ctx context.Context, result *scannerDomain.SwitchScanResult, assetID uuid.UUID) error {
	logger.InfoContext(ctx, "[SwitchRunner] Processing switch scan results for device: %s using asset: %s", result.DeviceIP, assetID.String())

	// Validate result data
	if result == nil {
		return fmt.Errorf("scan result is nil")
	}

	// Update asset with scan results - don't fail if this fails
	if err := r.repo.UpdateAssetWithScanResults(ctx, assetID, result); err != nil {
		logger.InfoContext(ctx, "[SwitchRunner] Warning: Failed to update asset, but continuing with switch data storage: %v", err)
		// Don't return error - continue with storing switch data
	}

	// Link asset to scan job - don't fail if this fails
	if err := r.repo.LinkAssetToScanJob(ctx, assetID, result.ScanJobID); err != nil {
		logger.InfoContext(ctx, "[SwitchRunner] Warning: Error linking asset to scan job: %v", err)
		// Don't fail the entire operation for this
	}

	// Store comprehensive switch scan results using unified repository
	// This is the most important part - prioritize storing switch data
	if err := r.repo.StoreSwitchScanResult(ctx, result); err != nil {
		logger.InfoContext(ctx, "[SwitchRunner] Error storing switch data: %v", err)
		return fmt.Errorf("failed to store switch data: %w", err)
	}

	logger.InfoContext(ctx, "[SwitchRunner] Successfully processed switch device %s (Asset ID: %s)", result.DeviceIP, assetID.String())
	return nil
}

// getOrCreateAssetForScanner gets the existing asset or creates a new one if needed
func (r *SwitchRunner) getOrCreateAssetForScanner(ctx context.Context, scanner scannerDomain.ScannerDomain) (uuid.UUID, error) {
	// Try to get existing asset ID
	assetID, err := r.repo.GetAssetIDForScanner(ctx, scanner.ID)
	if err == nil {
		logger.InfoContext(ctx, "[SwitchRunner] Found existing asset ID: %s for scanner: %d", assetID.String(), scanner.ID)
		return assetID, nil
	}

	logger.InfoContext(ctx, "[SwitchRunner] No existing asset found for scanner %d, creating new asset", scanner.ID)

	// Create new asset using unified repository
	switchConfig := scannerDomain.SwitchConfig{
		Name:     scanner.Name,
		IP:       scanner.IP,
		Username: scanner.Username,
		Password: scanner.Password,
		Port:     r.getDefaultPortInt(scanner),
		Brand:    r.getBrandFromType(scanner.Type),
	}

	assetID, err = r.repo.CreateSwitchAsset(ctx, scanner.ID, switchConfig)
	if err != nil {
		return uuid.Nil, fmt.Errorf("failed to create switch asset: %w", err)
	}

	logger.InfoContext(ctx, "[SwitchRunner] Created new asset ID: %s for scanner: %d", assetID.String(), scanner.ID)
	return assetID, nil
}

func (r *SwitchRunner) getDefaultPort(scanner scannerDomain.ScannerDomain) string {
	if scanner.Port != "" {
		return scanner.Port
	}
	return "22"
}

func (r *SwitchRunner) getDefaultPortInt(scanner scannerDomain.ScannerDomain) int {
	if scanner.Port != "" {
		if port, err := strconv.Atoi(scanner.Port); err == nil && port > 0 && port <= 65535 {
			return port
		}
	}
	return 22
}

func (r *SwitchRunner) getBrandFromType(deviceType string) string {
	switch strings.ToLower(deviceType) {
	case "cisco":
		return "Cisco"
	case "juniper":
		return "Juniper"
	case "huawei":
		return "Huawei"
	case "hp":
		return "HP"
	case "arista":
		return "Arista"
	default:
		return "Cisco" // Default
	}
}

// Cancel and status methods
func (r *SwitchRunner) CancelScan(jobID int64) bool {
	return r.cancelManager.CancelScan(jobID)
}

func (r *SwitchRunner) StatusScan(jobID int64) bool {
	return r.cancelManager.HasActiveScan(jobID)
}

// validateScannerConfig validates the scanner configuration before attempting scan
func (r *SwitchRunner) validateScannerConfig(scanner scannerDomain.ScannerDomain) error {
	if scanner.IP == "" {
		return fmt.Errorf("IP address is required")
	}

	if scanner.Username == "" {
		return fmt.Errorf("username is required")
	}

	if scanner.Password == "" {
		return fmt.Errorf("password is required")
	}

	if scanner.Type == "" {
		return fmt.Errorf("device type is required")
	}

	// Validate IP format
	if !r.isValidIP(scanner.IP) {
		return fmt.Errorf("invalid IP address format: %s", scanner.IP)
	}

	// Validate port if specified
	if scanner.Port != "" {
		if port, err := strconv.Atoi(scanner.Port); err != nil || port < 1 || port > 65535 {
			return fmt.Errorf("invalid port number: %s", scanner.Port)
		}
	}

	return nil
}

// isValidIP validates IP address format
func (r *SwitchRunner) isValidIP(ip string) bool {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return false
	}

	for _, part := range parts {
		if num, err := strconv.Atoi(part); err != nil || num < 0 || num > 255 {
			return false
		}
	}

	return true
}
