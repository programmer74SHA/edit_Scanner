package scanner

import (
	"context"
	"fmt"
	"net"
	"strings"

	scannerDomain "gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanner/domain"
)

// FirewallValidator handles validation logic for firewall scanning
type FirewallValidator struct{}

// NewFirewallValidator creates a new validator instance
func NewFirewallValidator() *FirewallValidator {
	return &FirewallValidator{}
}

// ValidateAPIKey checks if the API key is valid
func (v *FirewallValidator) ValidateAPIKey(apiKey string) error {
	if apiKey == "" {
		return fmt.Errorf("API key is required for firewall scanner")
	}
	return nil
}

// ValidateConnection tests connection to FortiGate with different auth methods
func (v *FirewallValidator) ValidateConnection(ctx context.Context, client *FortigateClient, apiKey string) error {
	var lastErr error

	for _, auth := range scannerDomain.FortigateAuthMethods {
		client.authMethod = auth.Method

		err := v.testConnection(ctx, client)
		if err == nil {
			return nil
		}
		lastErr = err
	}

	return fmt.Errorf("all authentication methods failed, last error: %w", lastErr)
}

// testConnection tests the connection to FortiGate
func (v *FirewallValidator) testConnection(ctx context.Context, client *FortigateClient) error {
	_, err := client.fetchData(ctx, "system/interface")
	if err != nil {
		return fmt.Errorf("FortiGate API test failed: %w", err)
	}
	return nil
}

// ValidateIPFormat checks if a string is a valid IPv4 address format
func (v *FirewallValidator) ValidateIPFormat(ip string) bool {
	if ip == "" {
		return false
	}

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	return parsedIP.To4() != nil
}

// ValidateMACFormat checks if the string is a valid MAC address format
func (v *FirewallValidator) ValidateMACFormat(mac string) bool {
	if mac == "" {
		return false
	}

	// Check for standard MAC address patterns
	// xx:xx:xx:xx:xx:xx or xx-xx-xx-xx-xx-xx or xxxxxxxxxxxx
	if len(mac) == 17 && (strings.Count(mac, ":") == 5 || strings.Count(mac, "-") == 5) {
		return true
	}
	if len(mac) == 12 && strings.Count(mac, ":") == 0 && strings.Count(mac, "-") == 0 {
		return true
	}

	return false
}

// ValidatePortConfiguration validates the port configuration
func (v *FirewallValidator) ValidatePortConfiguration(scanner scannerDomain.ScannerDomain) (string, error) {
	// Determine port to use (default to 443 for HTTPS)
	port := "443"
	if scanner.Port != "" {
		port = scanner.Port
	}
	return port, nil
}

// ValidateInterfaceData validates interface data before processing
func (v *FirewallValidator) ValidateInterfaceData(intf scannerDomain.FortigateInterface) bool {
	// Basic validation for interface data
	if intf.Name == "" {
		return false
	}
	return true
}

// ValidateZoneData validates zone data before processing
func (v *FirewallValidator) ValidateZoneData(zone scannerDomain.FortigateZone) bool {
	// Basic validation for zone data
	if zone.Name == "" {
		return false
	}
	return true
}

// ValidatePolicyData validates policy data before processing
func (v *FirewallValidator) ValidatePolicyData(policy scannerDomain.FortigatePolicy) bool {
	// Basic validation for policy data
	if policy.PolicyID == 0 {
		return false
	}
	return true
}
