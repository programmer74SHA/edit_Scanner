package domain

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// Switch Error Codes - Generic, not brand-specific
const (
	ErrCodeSwitchConnectionFailed    = "CONNECTION_FAILED"
	ErrCodeSwitchAuthFailed          = "AUTHENTICATION_FAILED"
	ErrCodeSwitchCommandFailed       = "COMMAND_FAILED"
	ErrCodeSwitchDataExtraction      = "DATA_EXTRACTION_FAILED"
	ErrCodeSwitchDataValidation      = "DATA_VALIDATION_FAILED"
	ErrCodeSwitchAssetCreation       = "ASSET_CREATION_FAILED"
	ErrCodeSwitchUnsupportedProtocol = "UNSUPPORTED_PROTOCOL"
	ErrCodeSwitchTimeoutError        = "TIMEOUT_ERROR"
	ErrCodeSwitchPrivilegeError      = "PRIVILEGE_ERROR"
	ErrCodeSwitchVendorNotSupported  = "VENDOR_NOT_SUPPORTED"
)

// SwitchError represents generic switch operation errors
type SwitchError struct {
	Code    string
	Message string
	Cause   error
	Vendor  string // Optional: track which vendor implementation failed
}

func (e SwitchError) Error() string {
	if e.Cause != nil {
		if e.Vendor != "" {
			return fmt.Sprintf("switch error [%s/%s]: %s - %v", e.Vendor, e.Code, e.Message, e.Cause)
		}
		return fmt.Sprintf("switch error [%s]: %s - %v", e.Code, e.Message, e.Cause)
	}
	if e.Vendor != "" {
		return fmt.Sprintf("switch error [%s/%s]: %s", e.Vendor, e.Code, e.Message)
	}
	return fmt.Sprintf("switch error [%s]: %s", e.Code, e.Message)
}

// NewSwitchError creates a new switch error
func NewSwitchError(code, message string, cause error) *SwitchError {
	return &SwitchError{
		Code:    code,
		Message: message,
		Cause:   cause,
	}
}

// NewSwitchErrorWithVendor creates a new switch error with vendor information
func NewSwitchErrorWithVendor(vendor, code, message string, cause error) *SwitchError {
	return &SwitchError{
		Vendor:  vendor,
		Code:    code,
		Message: message,
		Cause:   cause,
	}
}

// SwitchConfig represents configuration for creating a switch asset
type SwitchConfig struct {
	Name     string
	IP       string
	Username string
	Password string
	Port     int
	Brand    string
}

// SwitchData represents comprehensive switch data
type SwitchData struct {
	Metadata   *SwitchMetadata
	Interfaces []SwitchInterface
	VLANs      []SwitchVLAN
	Neighbors  []SwitchNeighbor
}

// SwitchMetadata represents switch configuration metadata
type SwitchMetadata struct {
	ID        string
	AssetID   string
	ScannerID int64
	Username  string
	Password  string
	Port      int
	Brand     string
}

// SwitchScanResult represents the result of a network switch scan
type SwitchScanResult struct {
	AssetID           string               `json:"asset_id"`
	SystemInfo        SwitchSystemInfo     `json:"system_info"`
	Interfaces        []SwitchInterface    `json:"interfaces"`
	VLANs             []SwitchVLAN         `json:"vlans"`
	VLANPorts         []SwitchVLANPort     `json:"vlan_ports"`
	RoutingTable      []SwitchRoutingEntry `json:"routing_table"`
	Neighbors         []SwitchNeighbor     `json:"neighbors"`
	AssetsCreated     int                  `json:"assets_created"`
	ScanJobID         int64                `json:"scan_job_id"`
	DeviceIP          string               `json:"device_ip"`
	ConnectionMethod  string               `json:"connection_method"`
	ScanDuration      time.Duration        `json:"scan_duration"`
	ErrorsEncountered []string             `json:"errors_encountered"`
	VendorInfo        SwitchVendorInfo     `json:"vendor_info"`
}

// SwitchVendorInfo contains vendor-specific information
type SwitchVendorInfo struct {
	Vendor       string            `json:"vendor"`       // e.g., "cisco", "juniper", "huawei"
	Model        string            `json:"model"`        // Device model
	OSVersion    string            `json:"os_version"`   // Operating system version
	Capabilities []string          `json:"capabilities"` // Supported features
	Extensions   map[string]string `json:"extensions"`   // Vendor-specific extensions
}

// SwitchInterface represents a network interface on a switch device
type SwitchInterface struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	IPAddress   string   `json:"ip_address"`
	SubnetMask  string   `json:"subnet_mask"`
	Status      string   `json:"status"`   // up/down/administratively down
	Protocol    string   `json:"protocol"` // up/down
	MacAddress  string   `json:"mac_address"`
	VLANs       []string `json:"vlans"` // VLANs associated with this interface
	AssetID     *string  `json:"asset_id,omitempty"`
	Type        string   `json:"type"`   // physical/virtual/loopback/etc
	Speed       string   `json:"speed"`  // interface speed
	Duplex      string   `json:"duplex"` // full/half/auto
	MTU         int      `json:"mtu"`    // Maximum Transmission Unit
	Mode        string   `json:"mode"`   // access/trunk/hybrid
}

// Interface behavior methods
func (s *SwitchInterface) SetAssetID(assetID string) {
	s.AssetID = &assetID
}

func (s *SwitchInterface) HasAsset() bool {
	return s.AssetID != nil && *s.AssetID != ""
}

func (s *SwitchInterface) GetAssetID() string {
	if s.AssetID != nil {
		return *s.AssetID
	}
	return ""
}

func (s *SwitchInterface) IsPhysical() bool {
	return s.Type == "physical" || s.Type == ""
}

func (s *SwitchInterface) IsVirtual() bool {
	return s.Type == "virtual" || s.Type == "vlan" || s.Type == "loopback"
}

// SwitchVLAN represents a VLAN configuration on a switch device
type SwitchVLAN struct {
	ID          int      `json:"id"`
	Name        string   `json:"name"`
	Status      string   `json:"status"` // active/suspend/inactive
	Ports       []string `json:"ports"`  // Ports assigned to this VLAN
	Type        string   `json:"type"`   // ethernet/management/voice/etc
	Parent      int      `json:"parent"` // Parent VLAN for private VLANs
	Description string   `json:"description"`
}

// VLAN behavior methods
func (v *SwitchVLAN) IsActive() bool {
	return strings.ToLower(v.Status) == "active"
}

func (v *SwitchVLAN) IsManagement() bool {
	return v.ID == 1 || strings.ToLower(v.Type) == "management"
}

func (v *SwitchVLAN) AddPort(portName string) {
	for _, port := range v.Ports {
		if port == portName {
			return // Already exists
		}
	}
	v.Ports = append(v.Ports, portName)
}

// SwitchVLANPort represents individual port assignments to VLANs
type SwitchVLANPort struct {
	ID         string `json:"id"`
	VlanID     int    `json:"vlan_id"`     // VLAN number
	VlanName   string `json:"vlan_name"`   // VLAN name for reference
	PortName   string `json:"port_name"`   // Port identifier
	PortType   string `json:"port_type"`   // access/trunk/hybrid
	PortStatus string `json:"port_status"` // active/inactive/blocked
	IsNative   bool   `json:"is_native"`   // Is this the native VLAN for trunk port
}

// SwitchRoutingEntry represents a routing table entry
type SwitchRoutingEntry struct {
	Network         string `json:"network"`
	Mask            string `json:"mask"`
	NextHop         string `json:"next_hop"`
	Interface       string `json:"interface"`
	Metric          int    `json:"metric"`
	AdminDistance   int    `json:"admin_distance"`
	Protocol        string `json:"protocol"` // connected/static/rip/ospf/eigrp/bgp
	Age             string `json:"age"`
	Tag             string `json:"tag"`
	VRF             string `json:"vrf"`              // Virtual Routing and Forwarding
	RoutePreference int    `json:"route_preference"` // Route preference/priority
}

// Routing entry behavior methods
func (r *SwitchRoutingEntry) IsConnected() bool {
	return strings.ToLower(r.Protocol) == "connected"
}

func (r *SwitchRoutingEntry) IsStatic() bool {
	return strings.ToLower(r.Protocol) == "static"
}

func (r *SwitchRoutingEntry) IsDefault() bool {
	return r.Network == "0.0.0.0" || r.Network == "0.0.0.0/0"
}

// SwitchNeighbor represents a discovery protocol neighbor (CDP/LLDP/etc)
type SwitchNeighbor struct {
	DeviceID     string                 `json:"device_id"`
	LocalPort    string                 `json:"local_port"`
	RemotePort   string                 `json:"remote_port"`
	Platform     string                 `json:"platform"`
	IPAddress    string                 `json:"ip_address"`
	Capabilities []string               `json:"capabilities"`
	Software     string                 `json:"software"`
	Duplex       string                 `json:"duplex"`
	Protocol     string                 `json:"protocol"` // CDP/LLDP/etc
	VendorData   map[string]interface{} `json:"vendor_data,omitempty"`
}

// Neighbor behavior methods
func (n *SwitchNeighbor) HasCapability(capability string) bool {
	for _, cap := range n.Capabilities {
		if strings.EqualFold(cap, capability) {
			return true
		}
	}
	return false
}

func (n *SwitchNeighbor) IsRouter() bool {
	return n.HasCapability("Router") || n.HasCapability("R")
}

func (n *SwitchNeighbor) IsSwitch() bool {
	return n.HasCapability("Switch") || n.HasCapability("S")
}

// SwitchSystemInfo represents system information from the switch device
type SwitchSystemInfo struct {
	Hostname         string                 `json:"hostname"`
	Model            string                 `json:"model"`
	SystemUptime     string                 `json:"system_uptime"`
	EthernetMAC      string                 `json:"ethernet_mac"`
	ManagementIP     string                 `json:"management_ip"`
	DomainName       string                 `json:"domain_name"`
	Location         string                 `json:"location"`
	LastConfigTime   time.Time              `json:"last_config_time"`
	SerialNumber     string                 `json:"serial_number"`
	SoftwareVersion  string                 `json:"software_version"`
	HardwareRevision string                 `json:"hardware_revision"`
	VendorExtensions map[string]interface{} `json:"vendor_extensions,omitempty"`
}

// System info behavior methods
func (s *SwitchSystemInfo) GetVendor() string {
	// Try to determine vendor from model or other info
	model := strings.ToLower(s.Model)
	switch {
	case strings.Contains(model, "cisco"):
		return "cisco"
	case strings.Contains(model, "juniper"):
		return "juniper"
	case strings.Contains(model, "huawei"):
		return "huawei"
	case strings.Contains(model, "hp") || strings.Contains(model, "aruba"):
		return "hp"
	case strings.Contains(model, "arista"):
		return "arista"
	default:
		return "unknown"
	}
}

func (s *SwitchSystemInfo) HasValidMAC() bool {
	return s.EthernetMAC != "" && len(s.EthernetMAC) >= 12
}

// SwitchScanService defines the domain service for switch operations
type SwitchScanService interface {
	ValidateScanCapabilities(vendor string, capabilities []string) error
	DetermineScanStrategy(vendor, model string) ScanStrategy
	ProcessScanResults(result *SwitchScanResult) error
	ValidateInterfaceConfiguration(interfaces []SwitchInterface) error
	ValidateVLANConfiguration(vlans []SwitchVLAN) error
}

// ScanStrategy defines the scanning approach for different vendors
type ScanStrategy struct {
	Commands            []string          `json:"commands"`
	ConnectionTimeout   time.Duration     `json:"connection_timeout"`
	CommandTimeout      time.Duration     `json:"command_timeout"`
	RequiredPrivileges  []string          `json:"required_privileges"`
	VendorSpecificFlags map[string]string `json:"vendor_specific_flags"`
}

// SwitchConnectionConfig represents connection configuration
type SwitchConnectionConfig struct {
	Host              string        `json:"host"`
	Port              int           `json:"port"`
	Protocol          string        `json:"protocol"` // SSH/Telnet/SNMP
	Username          string        `json:"username"`
	Password          string        `json:"password"`
	PrivateKey        string        `json:"private_key,omitempty"`
	ConnectionTimeout time.Duration `json:"connection_timeout"`
	CommandTimeout    time.Duration `json:"command_timeout"`
	MaxRetries        int           `json:"max_retries"`
	EnableMode        bool          `json:"enable_mode"`
	EnablePassword    string        `json:"enable_password,omitempty"`
}

// SwitchCredentials represents authentication credentials
type SwitchCredentials struct {
	Username       string            `json:"username"`
	Password       string            `json:"password"`
	PrivateKey     string            `json:"private_key,omitempty"`
	EnablePassword string            `json:"enable_password,omitempty"`
	APIKey         string            `json:"api_key,omitempty"`
	Certificates   map[string]string `json:"certificates,omitempty"`
}

// Validate credentials
func (c *SwitchCredentials) Validate() error {
	if c.Username == "" {
		return NewSwitchError(ErrCodeSwitchAuthFailed, "username is required", nil)
	}
	if c.Password == "" && c.PrivateKey == "" && c.APIKey == "" {
		return NewSwitchError(ErrCodeSwitchAuthFailed, "password, private key, or API key is required", nil)
	}
	return nil
}

// SwitchScanStarted event
type SwitchScanStarted struct {
	ScanJobID  int64     `json:"scan_job_id"`
	ScannerID  int64     `json:"scanner_id"`
	DeviceIP   string    `json:"device_ip"`
	StartedAt  time.Time `json:"started_at"`
	VendorInfo string    `json:"vendor_info"`
}

// SwitchScanCompleted event
type SwitchScanCompleted struct {
	ScanJobID        int64         `json:"scan_job_id"`
	ScannerID        int64         `json:"scanner_id"`
	DeviceIP         string        `json:"device_ip"`
	CompletedAt      time.Time     `json:"completed_at"`
	Duration         time.Duration `json:"duration"`
	AssetsDiscovered int           `json:"assets_discovered"`
	InterfacesFound  int           `json:"interfaces_found"`
	VLANsFound       int           `json:"vlans_found"`
	NeighborsFound   int           `json:"neighbors_found"`
	Success          bool          `json:"success"`
	ErrorMessage     string        `json:"error_message,omitempty"`
}

// SwitchScanFailed event
type SwitchScanFailed struct {
	ScanJobID    int64     `json:"scan_job_id"`
	ScannerID    int64     `json:"scanner_id"`
	DeviceIP     string    `json:"device_ip"`
	FailedAt     time.Time `json:"failed_at"`
	ErrorCode    string    `json:"error_code"`
	ErrorMessage string    `json:"error_message"`
	Retryable    bool      `json:"retryable"`
}

// SwitchDeviceClient defines operations for connecting to and scanning switch devices
type SwitchDeviceClient interface {
	Connect(ctx context.Context, config SwitchConnectionConfig) error
	ExecuteCommands(ctx context.Context, commands []string) (string, error)
	ParseOutput(output string) (*SwitchScanResult, error)
	GetDefaultCommands() []string
	Close() error
}

// SwitchDeviceClientFactory creates appropriate client for device type
type SwitchDeviceClientFactory interface {
	CreateClient(deviceType string, config SwitchConnectionConfig) (SwitchDeviceClient, error)
}
