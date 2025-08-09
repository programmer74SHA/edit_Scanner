package domain

import (
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
)

var (
	ErrFirewallNotFound           = errors.New("firewall not found")
	ErrFirewallCreateFailed       = errors.New("failed to create firewall")
	ErrFirewallUpdateFailed       = errors.New("failed to update firewall")
	ErrFirewallDeleteFailed       = errors.New("failed to delete firewall")
	ErrInvalidFirewallData        = errors.New("invalid firewall data")
	ErrInvalidZoneData            = errors.New("invalid zone data")
	ErrInvalidInterfaceData       = errors.New("invalid interface data")
	ErrInvalidVLANData            = errors.New("invalid VLAN data")
	ErrFirewallManagementIPExists = errors.New("firewall with this management IP already exists")
	ErrVendorNotFound             = errors.New("vendor not found")
)

// ValidateHARole validates the HA role enum value
func ValidateHARole(haRole string) error {
	haRole = strings.ToLower(haRole)
	validRoles := []string{"active", "passive", "standalone"}
	for _, role := range validRoles {
		if haRole == role {
			return nil
		}
	}
	return errors.New("ha_role must be one of: active, passive, standalone")
}

// ValidateStatus validates the status enum value
func ValidateStatus(status string) error {
	status = strings.ToLower(status)
	validStatuses := []string{"active", "inactive"}
	for _, s := range validStatuses {
		if status == s {
			return nil
		}
	}
	return errors.New("status must be one of: active, inactive")
}

// ValidateZoneType validates the zone type enum value
func ValidateZoneType(zoneType string) error {
	zoneType = strings.ToLower(zoneType)
	validTypes := []string{"security", "management", "dmz"}
	for _, t := range validTypes {
		if zoneType == t {
			return nil
		}
	}
	return errors.New("zone_type must be one of: security, management, DMZ")
}

// ValidateVendorZoneType validates the vendor zone type enum value
func ValidateVendorZoneType(vendorZoneType string) error {
	vendorZoneType = strings.ToLower(vendorZoneType)
	validTypes := []string{"lan", "wan", "dmz", "vpn"}
	for _, t := range validTypes {
		if vendorZoneType == t {
			return nil
		}
	}
	return errors.New("vendor_zone_type must be one of: LAN, WAN, DMZ, VPN")
}

// ValidateInterfaceType validates the interface type enum value
func ValidateInterfaceType(interfaceType string) error {
	interfaceType = strings.ToLower(interfaceType)
	validTypes := []string{"logical", "physical"}
	for _, t := range validTypes {
		if interfaceType == t {
			return nil
		}
	}
	return errors.New("interface_type must be one of: logical, physical")
}

// ValidateOperationalStatus validates the operational status enum value
func ValidateOperationalStatus(operationalStatus string) error {
	operationalStatus = strings.ToLower(operationalStatus)
	validStatuses := []string{"up", "down"}
	for _, s := range validStatuses {
		if operationalStatus == s {
			return nil
		}
	}
	return errors.New("operational_status must be one of: Up, Down")
}

// ValidateRisk validates the risk value (should be a number between 0-5)
func ValidateRisk(risk int) error {
	if risk < 0 || risk > 5 {
		return errors.New("risk must be between 0 and 5")
	}
	return nil
}

type FirewallUUID = uuid.UUID

// SecondaryIP represents secondary IP addresses on interfaces
type SecondaryIP struct {
	ID          int      `json:"id"`
	IP          string   `json:"ip"`
	CIDRPrefix  *int     `json:"cidr_prefix"`
	Allowaccess []string `json:"allowaccess"`
}

// ZoneInterfaces represents interfaces assigned to zones
type ZoneInterfaces struct {
	InterfaceName []string `json:"interface_name"`
	VLANName      []string `json:"vlan_name"`
}

// FirewallZone represents security zones in the firewall
type FirewallZone struct {
	ID                    string         `json:"id"`
	ZoneName              string         `json:"zone_name"`
	ZoneType              string         `json:"zone_type"`
	VendorZoneType        string         `json:"vendor_zone_type"`
	Description           string         `json:"description"`
	ZoneMode              string         `json:"zone_mode"`
	IntrazoneAction       string         `json:"intrazone_action"`
	ZoneProtectionProfile string         `json:"zone_protection_profile"`
	LogSetting            string         `json:"log_setting"`
	Interfaces            ZoneInterfaces `json:"interfaces"`
}

// FirewallInterface represents network interfaces
type FirewallInterface struct {
	ID                     string        `json:"id"`
	InterfaceName          string        `json:"interface_name"`
	InterfaceType          string        `json:"interface_type"`
	VirtualRouter          string        `json:"virtual_router"`
	VirtualSystem          string        `json:"virtual_system"`
	Description            string        `json:"description"`
	OperationalStatus      string        `json:"operational_status"`
	AdminStatus            string        `json:"admin_status"`
	ParentInterfaceName    *string       `json:"parent_interface_name"`
	VLANId                 *int          `json:"vlan_id"`
	MacAddress             string        `json:"mac_address"`
	VendorSpecificConfig   string        `json:"vendor_specific_config"`
	SecondaryIPs           []SecondaryIP `json:"secondary_ips"`
	PrimaryIP              string        `json:"primary_ip"`
	CIDRPrefix             *int          `json:"cidr_prefix"`
}

// FirewallVLAN represents VLANs configured on the firewall
type FirewallVLAN struct {
	ID                   string   `json:"id"`
	VLANNumber           int      `json:"vlan_number"`
	VLANName             string   `json:"vlan_name"`
	Description          string   `json:"description"`
	IsNative             bool     `json:"is_native"`
	VendorSpecificConfig string   `json:"vendor_specific_config"`
	Interfaces           []string `json:"interfaces"`
}

// FirewallPolicy represents firewall security policies
type FirewallPolicy struct {
	ID                   string   `json:"id"`
	PolicyName           string   `json:"policy_name"`
	PolicyID             *int     `json:"policy_id"`
	SrcAddresses         []string `json:"src_addresses"`
	DstAddresses         []string `json:"dst_addresses"`
	Services             []string `json:"services"`
	Action               string   `json:"action"`
	PolicyType           string   `json:"policy_type"`
	Status               string   `json:"status"`
	RuleOrder            *int     `json:"rule_order"`
	VendorSpecificConfig string   `json:"vendor_specific_config"`
	Schedule             string   `json:"schedule"`
}

// FirewallAsset represents the main firewall asset
type FirewallAsset struct {
	ID               string    `json:"id"`
	VendorCode       string    `json:"vendor_code"`
	Name             string    `json:"name"`
	Domain           string    `json:"domain"`
	Hostname         string    `json:"hostname"`
	OSName           string    `json:"os_name"`
	OSVersion        string    `json:"os_version"`
	Description      string    `json:"description"`
	AssetType        string    `json:"asset_type"`
	DiscoveredBy     *string   `json:"discovered_by"`
	Risk             int       `json:"risk"`
	LoggingCompleted bool      `json:"logging_completed"`
	AssetValue       float64   `json:"asset_value"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

// FirewallDetails represents specific firewall configuration details
type FirewallDetails struct {
	ID              string     `json:"id"`
	AssetID         string     `json:"asset_id"`
	Model           string     `json:"model"`
	FirmwareVersion string     `json:"firmware_version"`
	SerialNumber    string     `json:"serial_number"`
	IsHAEnabled     bool       `json:"is_ha_enabled"`
	HARole          string     `json:"ha_role"`
	ManagementIP    string     `json:"management_ip"`
	SiteName        string     `json:"site_name"`
	Location        string     `json:"location"`
	Status          string     `json:"status"`
	LastSync        *time.Time `json:"last_sync"`
	SyncStatus      string     `json:"sync_status"`
}

// FirewallDomain represents the complete firewall configuration
type FirewallDomain struct {
	Asset      FirewallAsset       `json:"asset"`
	Details    FirewallDetails     `json:"details"`
	Zones      []FirewallZone      `json:"zones"`
	Interfaces []FirewallInterface `json:"interfaces"`
	VLANs      []FirewallVLAN      `json:"vlans"`
	Policies   []FirewallPolicy    `json:"policies"`
}

// ListFirewallsResult represents the result of listing firewalls with pagination
type ListFirewalls struct {
	Firewalls  []FirewallDomain `json:"firewalls"`
	TotalCount int              `json:"total_count"`
}

// ValidateFirewallAsset validates the firewall asset data
func (f *FirewallAsset) Validate() error {
	if f.Name == "" {
		return errors.New("firewall name is required")
	}
	if f.Hostname == "" {
		return errors.New("firewall hostname is required")
	}
	if f.VendorCode == "" {
		return errors.New("vendor code is required")
	}
	if err := ValidateRisk(f.Risk); err != nil {
		return err
	}
	return nil
}

// ValidateFirewallDetails validates the firewall details
func (f *FirewallDetails) Validate() error {
	if f.ManagementIP == "" {
		return errors.New("management IP is required")
	}
	if err := ValidateHARole(f.HARole); err != nil {
		return err
	}
	if err := ValidateStatus(f.Status); err != nil {
		return err
	}
	return nil
}

// ValidateForCreation validates the firewall details for creation
func (f *FirewallDetails) ValidateForCreation() error {
	return f.Validate()
}

// ValidateForUpdate validates the firewall details for updates
func (f *FirewallDetails) ValidateForUpdate() error {
	if f.AssetID == "" {
		return errors.New("asset ID is required")
	}
	return f.Validate()
}

// ValidateFirewallZone validates the zone data
func (z *FirewallZone) Validate() error {
	if z.ZoneName == "" {
		return errors.New("zone name is required")
	}
	if err := ValidateZoneType(z.ZoneType); err != nil {
		return err
	}
	if err := ValidateVendorZoneType(z.VendorZoneType); err != nil {
		return err
	}
	return nil
}

// ValidateFirewallInterface validates the interface data
func (i *FirewallInterface) Validate() error {
	if i.InterfaceName == "" {
		return errors.New("interface name is required")
	}
	if err := ValidateInterfaceType(i.InterfaceType); err != nil {
		return err
	}
	if err := ValidateOperationalStatus(i.OperationalStatus); err != nil {
		return err
	}
	return nil
}

// ValidateFirewallVLAN validates the VLAN data
func (v *FirewallVLAN) Validate() error {
	if v.VLANNumber <= 0 || v.VLANNumber > 4094 {
		return errors.New("VLAN number must be between 1 and 4094")
	}
	return nil
}

// ValidateFirewallPolicy validates the policy data
func (p *FirewallPolicy) Validate() error {
	// All policy fields are now optional
	return nil
}

// Validate validates the complete firewall domain for creation
func (f *FirewallDomain) Validate() error {
	if err := f.Asset.Validate(); err != nil {
		return err
	}

	if err := f.Details.ValidateForCreation(); err != nil {
		return err
	}

	for _, zone := range f.Zones {
		if err := zone.Validate(); err != nil {
			return err
		}
	}

	for _, iface := range f.Interfaces {
		if err := iface.Validate(); err != nil {
			return err
		}
	}

	for _, vlan := range f.VLANs {
		if err := vlan.Validate(); err != nil {
			return err
		}
	}

	for _, policy := range f.Policies {
		if err := policy.Validate(); err != nil {
			return err
		}
	}

	return nil
}

// ValidateForUpdate validates the complete firewall domain for updates
func (f *FirewallDomain) ValidateForUpdate() error {
	if err := f.Asset.Validate(); err != nil {
		return err
	}
	if err := f.Details.ValidateForUpdate(); err != nil {
		return err
	}

	for _, zone := range f.Zones {
		if err := zone.Validate(); err != nil {
			return err
		}
	}

	for _, iface := range f.Interfaces {
		if err := iface.Validate(); err != nil {
			return err
		}
	}

	for _, vlan := range f.VLANs {
		if err := vlan.Validate(); err != nil {
			return err
		}
	}

	for _, policy := range f.Policies {
		if err := policy.Validate(); err != nil {
			return err
		}
	}

	return nil
}

// FirewallUUIDFromString parses a string to FirewallUUID
func FirewallUUIDFromString(s string) (uuid.UUID, error) {
	return uuid.Parse(s)
}
