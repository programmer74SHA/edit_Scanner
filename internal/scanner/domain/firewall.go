package domain

import (
	"encoding/json"
	"fmt"
)

// FlexibleStringArray handles both string and []string from JSON
type FlexibleStringArray []string

// ToStringSlice converts FlexibleStringArray to []string
func (f FlexibleStringArray) ToStringSlice() []string {
	return []string(f)
}

// FortiGate API response structures
type FortigateResponse struct {
	Results []json.RawMessage `json:"results"`
	Status  string            `json:"status"`
}

// FortigateZone represents a security zone in FortiGate
type FortigateZone struct {
	Name        string                   `json:"name"`
	Description string                   `json:"description"`
	Interface   []FortigateZoneInterface `json:"interface"`
}

// FortigateZoneInterface represents an interface within a zone
type FortigateZoneInterface struct {
	InterfaceName string `json:"interface-name"`
	Name          string `json:"name"`
}

// FortigateInterface represents a network interface in FortiGate
type FortigateInterface struct {
	Name        string                 `json:"name"`
	IP          string                 `json:"ip"`
	Status      string                 `json:"status"`
	Description string                 `json:"description"`
	MTU         int                    `json:"mtu"`
	Speed       string                 `json:"speed"`
	Duplex      string                 `json:"duplex"`
	Type        string                 `json:"type"`
	VDOM        string                 `json:"vdom"`
	Mode        string                 `json:"mode"`
	Role        string                 `json:"role"`
	MacAddr     string                 `json:"macaddr"`
	Allowaccess FlexibleStringArray    `json:"allowaccess"`
	SecondaryIP []FortigateSecondaryIP `json:"secondaryip"`
}

// FortigateSecondaryIP represents a secondary IP address on an interface
type FortigateSecondaryIP struct {
	ID          int                 `json:"id"`
	IP          string              `json:"ip"`
	Allowaccess FlexibleStringArray `json:"allowaccess"`
}

// FortigatePolicy represents a firewall policy in FortiGate
type FortigatePolicy struct {
	PolicyID int                        `json:"policyid"`
	Name     string                     `json:"name"`
	SrcIntf  []FortigatePolicyInterface `json:"srcintf"`
	DstIntf  []FortigatePolicyInterface `json:"dstintf"`
	SrcAddr  []FortigateAddress         `json:"srcaddr"`
	DstAddr  []FortigateAddress         `json:"dstaddr"`
	Service  []FortigateService         `json:"service"`
	Action   string                     `json:"action"`
	Status   string                     `json:"status"`
	Schedule string                     `json:"schedule"`
}

// FortigatePolicyInterface represents an interface reference in a policy
type FortigatePolicyInterface struct {
	Name string `json:"name"`
}

// FortigateService represents a service object in FortiGate
type FortigateService struct {
	Name string `json:"name"`
}

// FortigateAddress represents an address object in FortiGate
type FortigateAddress struct {
	Name   string `json:"name"`
	Subnet string `json:"subnet"`
	Type   string `json:"type"`
}

// FortigateAuthMethod represents different authentication methods for FortiGate
type FortigateAuthMethod struct {
	Name   string
	Method string
}

// Constants for authentication methods
var (
	FortigateAuthMethods = []FortigateAuthMethod{
		{"Bearer Token", "bearer"},
		{"API Key Header", "apikey"},
		{"Query Parameter", "query"},
	}
)

// FirewallScanResult represents the result of a firewall scan
type FirewallScanResult struct {
	AssetID          string
	Zones            []FortigateZone
	Interfaces       []FortigateInterface
	Policies         []FortigatePolicy
	Addresses        []FortigateAddress
	AssetsCreated    int
	ScanJobID        int64
	FirewallIP       string
	ConnectionMethod string
}

// FirewallScanConfiguration represents the configuration for a firewall scan
type FirewallScanConfiguration struct {
	Scanner         ScannerDomain
	ScanJobID       int64
	DefaultPort     string
	TimeoutSeconds  int
	RetryAttempts   int
	ValidationRules FirewallValidationRules
}

// FirewallValidationRules represents validation rules for firewall scanning
type FirewallValidationRules struct {
	RequireAPIKey      bool
	ValidateConnection bool
	ValidateIPFormat   bool
	ValidateMACFormat  bool
	MinZoneCount       int
	MinInterfaceCount  int
	MinPolicyCount     int
}

// DefaultFirewallValidationRules returns default validation rules
func DefaultFirewallValidationRules() FirewallValidationRules {
	return FirewallValidationRules{
		RequireAPIKey:      true,
		ValidateConnection: true,
		ValidateIPFormat:   true,
		ValidateMACFormat:  true,
		MinZoneCount:       0,
		MinInterfaceCount:  0,
		MinPolicyCount:     0,
	}
}

// FirewallError represents firewall-specific errors
type FirewallError struct {
	Code    string
	Message string
	Cause   error
}

func (e FirewallError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("firewall error [%s]: %s - %v", e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("firewall error [%s]: %s", e.Code, e.Message)
}

// Firewall error codes
const (
	ErrCodeAPIKeyInvalid    = "API_KEY_INVALID"
	ErrCodeConnectionFailed = "CONNECTION_FAILED"
	ErrCodeAuthFailed       = "AUTHENTICATION_FAILED"
	ErrCodeDataExtraction   = "DATA_EXTRACTION_FAILED"
	ErrCodeDataValidation   = "DATA_VALIDATION_FAILED"
	ErrCodeAssetCreation    = "ASSET_CREATION_FAILED"
	ErrCodeStorageFailed    = "STORAGE_FAILED"
)

// NewFirewallError creates a new firewall error
func NewFirewallError(code, message string, cause error) *FirewallError {
	return &FirewallError{
		Code:    code,
		Message: message,
		Cause:   cause,
	}
}

// FirewallData represents the complete firewall configuration data
type FirewallData struct {
	AssetID    string
	Zones      []ZoneData
	Interfaces []InterfaceData
	Policies   []PolicyData
	VLANs      []VLANData
}

type ZoneData struct {
	Name        string
	Description string
	Interfaces  []string
}

type InterfaceData struct {
	Name         string
	IP           string
	Status       string
	Description  string
	MTU          int
	Speed        string
	Duplex       string
	Type         string
	VDOM         string
	Mode         string
	Role         string
	MacAddr      string
	Allowaccess  []string
	SecondaryIPs []SecondaryIPData
	Zone         string
	AssetID      *string 
}

func (i *InterfaceData) SetAssetID(assetID string) {
	i.AssetID = &assetID
}

func (i *InterfaceData) HasAsset() bool {
	return i.AssetID != nil && *i.AssetID != ""
}

func (i *InterfaceData) GetAssetID() string {
	if i.AssetID != nil {
		return *i.AssetID
	}
	return ""
}

type SecondaryIPData struct {
	ID          int
	IP          string
	Allowaccess []string
}

type PolicyData struct {
	PolicyID int
	Name     string
	SrcIntf  []string
	DstIntf  []string
	SrcAddr  []string
	DstAddr  []string
	Service  []string
	Action   string
	Status   string
	Schedule string
}

type VLANData struct {
	VLANID          int
	VLANName        string
	ParentInterface string
	Description     string
}
