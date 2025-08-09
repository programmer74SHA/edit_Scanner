package scanner

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanner/domain"
)

// NmapProfileValidator provides validation for Nmap profiles and related data
type NmapProfileValidator struct{}

// NewNmapProfileValidator creates a new validator instance
func NewNmapProfileValidator() *NmapProfileValidator {
	return &NmapProfileValidator{}
}

// ValidateProfile validates an Nmap profile configuration
func (v *NmapProfileValidator) ValidateProfile(profile domain.NmapProfile) error {
	if profile.Name == "" {
		return fmt.Errorf("profile name is required")
	}

	if len(profile.Name) > 100 {
		return fmt.Errorf("profile name cannot exceed 100 characters")
	}

	if len(profile.Arguments) == 0 {
		return fmt.Errorf("profile must have at least one argument")
	}

	// Validate that profile doesn't contain dangerous arguments
	if err := v.validateNmapArguments(profile.Arguments); err != nil {
		return fmt.Errorf("invalid nmap arguments: %v", err)
	}

	if profile.Description != nil && len(*profile.Description) > 500 {
		return fmt.Errorf("profile description cannot exceed 500 characters")
	}

	return nil
}

// validateNmapArguments checks for potentially dangerous or problematic Nmap arguments
func (v *NmapProfileValidator) validateNmapArguments(args []string) error {
	// List of prohibited arguments for security reasons
	prohibitedArgs := []string{
		"--script-unsafe",
		"--script-args=unsafe",
		"--script=*exploit*",
		"--script=*vuln*",
		"--script=*dos*",
		"--script=*flood*",
		"--script=*auth-spoof*",
		"--max-rate=0", // Unlimited rate can be dangerous
	}

	// List of arguments that should not be set by profiles (handled by system)
	systemArgs := []string{
		"-oX", // XML output format - handled by system
		"-oN", // Normal output format
		"-oG", // Grepable output format
		"-oA", // All output formats
	}

	argString := strings.Join(args, " ")

	// Check for prohibited arguments
	for _, prohibited := range prohibitedArgs {
		if strings.Contains(strings.ToLower(argString), strings.ToLower(prohibited)) {
			return fmt.Errorf("prohibited argument: %s", prohibited)
		}
	}

	// Check for system-managed arguments
	for _, systemArg := range systemArgs {
		if strings.Contains(argString, systemArg) {
			return fmt.Errorf("system-managed argument not allowed in profile: %s", systemArg)
		}
	}

	// Validate specific argument patterns
	for i, arg := range args {
		if strings.HasPrefix(arg, "--max-rate=") {
			rateStr := strings.TrimPrefix(arg, "--max-rate=")
			rate, err := strconv.Atoi(rateStr)
			if err != nil {
				return fmt.Errorf("invalid max-rate value: %s", rateStr)
			}
			if rate > 10000 {
				return fmt.Errorf("max-rate too high: %d (maximum allowed: 10000)", rate)
			}
		}

		if strings.HasPrefix(arg, "-T") && len(arg) == 3 {
			timing := arg[2:]
			if timing < "0" || timing > "5" {
				return fmt.Errorf("invalid timing template: %s (valid range: 0-5)", timing)
			}
		}

		if arg == "-p" && i+1 < len(args) {
			if err := v.validatePortRange(args[i+1]); err != nil {
				return fmt.Errorf("invalid port range: %v", err)
			}
		}
	}

	return nil
}

// validatePortRange validates port range specifications
func (v *NmapProfileValidator) validatePortRange(portSpec string) error {
	// Handle common port specifications
	if portSpec == "-" {
		return fmt.Errorf("scanning all ports (-) is not allowed in profiles")
	}

	// Split by commas for multiple ranges
	ranges := strings.Split(portSpec, ",")
	for _, r := range ranges {
		r = strings.TrimSpace(r)

		if strings.Contains(r, "-") {
			// Range specification (e.g., "1-1000")
			parts := strings.Split(r, "-")
			if len(parts) != 2 {
				return fmt.Errorf("invalid port range format: %s", r)
			}

			start, err := strconv.Atoi(parts[0])
			if err != nil {
				return fmt.Errorf("invalid start port: %s", parts[0])
			}

			end, err := strconv.Atoi(parts[1])
			if err != nil {
				return fmt.Errorf("invalid end port: %s", parts[1])
			}

			if start < 1 || start > 65535 || end < 1 || end > 65535 {
				return fmt.Errorf("port numbers must be between 1 and 65535")
			}

			if start > end {
				return fmt.Errorf("start port cannot be greater than end port")
			}

			if end-start > 10000 {
				return fmt.Errorf("port range too large: %d ports (maximum allowed: 10000)", end-start+1)
			}
		} else {
			// Single port
			port, err := strconv.Atoi(r)
			if err != nil {
				return fmt.Errorf("invalid port number: %s", r)
			}

			if port < 1 || port > 65535 {
				return fmt.Errorf("port number must be between 1 and 65535: %d", port)
			}
		}
	}

	return nil
}

// ValidateIPAddress validates an IP address format
func (v *NmapProfileValidator) ValidateIPAddress(ip string) error {
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("invalid IP address format: %s", ip)
	}
	return nil
}

// ValidateIPRange validates an IP range for Nmap scanning
func (v *NmapProfileValidator) ValidateIPRange(startIP, endIP string) error {
	if err := v.ValidateIPAddress(startIP); err != nil {
		return fmt.Errorf("invalid start IP: %v", err)
	}

	if err := v.ValidateIPAddress(endIP); err != nil {
		return fmt.Errorf("invalid end IP: %v", err)
	}

	// Convert to compare
	start := net.ParseIP(startIP)
	end := net.ParseIP(endIP)

	// Ensure both are same IP version
	if (start.To4() == nil) != (end.To4() == nil) {
		return fmt.Errorf("start and end IP must be the same version (IPv4 or IPv6)")
	}

	// For IPv4, ensure start <= end
	if start.To4() != nil && end.To4() != nil {
		startInt := ipv4ToInt(start.To4())
		endInt := ipv4ToInt(end.To4())

		if startInt > endInt {
			return fmt.Errorf("start IP cannot be greater than end IP")
		}

		// Limit range size for security
		if endInt-startInt > 65536 {
			return fmt.Errorf("IP range too large: %d addresses (maximum allowed: 65536)", endInt-startInt+1)
		}
	}

	return nil
}

// ValidateNetworkCIDR validates a network CIDR notation
func (v *NmapProfileValidator) ValidateNetworkCIDR(ip string, subnet int64) error {
	if err := v.ValidateIPAddress(ip); err != nil {
		return fmt.Errorf("invalid network IP: %v", err)
	}

	// Check subnet range
	parsedIP := net.ParseIP(ip)
	if parsedIP.To4() != nil {
		// IPv4
		if subnet < 1 || subnet > 32 {
			return fmt.Errorf("IPv4 subnet mask must be between 1 and 32")
		}

		// Calculate network size and limit for security
		hostBits := 32 - subnet
		if hostBits > 16 { // More than /16 (65536 hosts)
			return fmt.Errorf("network too large: /%d (minimum allowed: /16)", subnet)
		}
	} else {
		// IPv6
		if subnet < 1 || subnet > 128 {
			return fmt.Errorf("IPv6 subnet mask must be between 1 and 128")
		}

		// For IPv6, be more restrictive
		if subnet < 64 {
			return fmt.Errorf("IPv6 network too large: /%d (minimum allowed: /64)", subnet)
		}
	}

	return nil
}

// Helper function to convert IPv4 to integer for comparison
func ipv4ToInt(ip net.IP) uint32 {
	if len(ip) == 16 {
		ip = ip[12:16]
	}
	return uint32(ip[0])<<24 + uint32(ip[1])<<16 + uint32(ip[2])<<8 + uint32(ip[3])
}

// ValidateScannerTarget validates scanner target configuration
func (v *NmapProfileValidator) ValidateScannerTarget(target, ip string, subnet int64, startIP, endIP string) error {
	switch target {
	case "IP":
		return v.ValidateIPAddress(ip)
	case "Network":
		return v.ValidateNetworkCIDR(ip, subnet)
	case "Range":
		return v.ValidateIPRange(startIP, endIP)
	default:
		return fmt.Errorf("invalid target type: %s (valid types: IP, Network, Range)", target)
	}
}

// SanitizeProfileName sanitizes a profile name for safe storage
func (v *NmapProfileValidator) SanitizeProfileName(name string) string {
	// Remove leading/trailing whitespace
	name = strings.TrimSpace(name)

	// Replace multiple consecutive spaces with single space
	re := regexp.MustCompile(`\s+`)
	name = re.ReplaceAllString(name, " ")

	// Remove any control characters
	re = regexp.MustCompile(`[\x00-\x1f\x7f]`)
	name = re.ReplaceAllString(name, "")

	return name
}

// NmapArgumentBuilder helps build safe Nmap argument lists
type NmapArgumentBuilder struct {
	args []string
}

// NewNmapArgumentBuilder creates a new argument builder
func NewNmapArgumentBuilder() *NmapArgumentBuilder {
	return &NmapArgumentBuilder{
		args: make([]string, 0),
	}
}

// AddScanType adds a scan type argument (-sS, -sT, etc.)
func (b *NmapArgumentBuilder) AddScanType(scanType string) *NmapArgumentBuilder {
	validScanTypes := []string{"-sS", "-sT", "-sA", "-sW", "-sM", "-sU", "-sN", "-sF", "-sX"}
	for _, valid := range validScanTypes {
		if scanType == valid {
			b.args = append(b.args, scanType)
			break
		}
	}
	return b
}

// AddTiming adds a timing template (-T0 to -T5)
func (b *NmapArgumentBuilder) AddTiming(level int) *NmapArgumentBuilder {
	if level >= 0 && level <= 5 {
		b.args = append(b.args, fmt.Sprintf("-T%d", level))
	}
	return b
}

// AddTopPorts adds top ports scanning
func (b *NmapArgumentBuilder) AddTopPorts(count int) *NmapArgumentBuilder {
	if count > 0 && count <= 65535 {
		b.args = append(b.args, "--top-ports", strconv.Itoa(count))
	}
	return b
}

// AddServiceDetection adds service version detection
func (b *NmapArgumentBuilder) AddServiceDetection() *NmapArgumentBuilder {
	b.args = append(b.args, "-sV")
	return b
}

// AddOSDetection adds OS detection
func (b *NmapArgumentBuilder) AddOSDetection() *NmapArgumentBuilder {
	b.args = append(b.args, "-O")
	return b
}

// AddScriptScan adds default script scanning
func (b *NmapArgumentBuilder) AddScriptScan() *NmapArgumentBuilder {
	b.args = append(b.args, "-sC")
	return b
}

// Build returns the constructed argument list
func (b *NmapArgumentBuilder) Build() []string {
	// Always add XML output
	result := make([]string, len(b.args))
	copy(result, b.args)
	result = append(result, "-oX", "-")
	return result
}
