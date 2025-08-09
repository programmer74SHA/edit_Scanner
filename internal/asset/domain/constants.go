package domain

import "strings"

// Asset field standardized values

// OSType represents standardized OS types
type OSType string

const (
	OSTypeLinux    OSType = "Linux"
	OSTypeWindows  OSType = "Windows"
	OSTypeMacOS    OSType = "MacOS"
	OSTypeCiscoIOS OSType = "Cisco IOS"
	OSTypeFortiOS  OSType = "FortiOS"
	OSTypeUnknown  OSType = "Unknown"
)

// DiscoveredBy represents standardized discovery sources
type DiscoveredBy string

const (
	DiscoveredByNmap            DiscoveredBy = "NMap"
	DiscoveredByNessus          DiscoveredBy = "Nessus"
	DiscoveredByLDAP            DiscoveredBy = "LDAP"
	DiscoveredByVcenter         DiscoveredBy = "Vcenter"
	DiscoveredBySwitchScanner   DiscoveredBy = "Switch Scanner"
	DiscoveredByFirewallScanner DiscoveredBy = "Firewall Scanner"
	DiscoveredBySystemUser      DiscoveredBy = "System User"
	DiscoveredByUnknown         DiscoveredBy = "Unknown"
)

// AssetType represents standardized asset types
type AssetType string

const (
	AssetTypeVM                   AssetType = "VM"
	AssetTypeSwitch               AssetType = "Switch"
	AssetTypeFirewall             AssetType = "Firewall"
	AssetTypeVcenter              AssetType = "Vcenter"
	AssetTypeDomainDevice         AssetType = "Domain device"
	AssetTypeHost                 AssetType = "Host"
	AssetTypeClient               AssetType = "Client"
	AssetTypeNessusScanner        AssetType = "Nessus Scanner"
	AssetTypeDomainScanner        AssetType = "Domain scanner"
	AssetFireWallDevice           AssetType = "Firewall Device"
	AssetFireWallNetworkInterface AssetType = "Firewall Network Interface"
	AssetNetworkDevice            AssetType = "Network Device"

	AssetTypeUnknown AssetType = "Unknown"
)

// GetValidOSTypes returns all valid OS types
func GetValidOSTypes() []string {
	return []string{
		string(OSTypeLinux),
		string(OSTypeWindows),
		string(OSTypeMacOS),
		string(OSTypeCiscoIOS),
		string(OSTypeFortiOS),
		string(OSTypeUnknown),
	}
}

// GetValidDiscoveredBy returns all valid discovery sources
func GetValidDiscoveredBy() []string {
	return []string{
		string(DiscoveredByNmap),
		string(DiscoveredByNessus),
		string(DiscoveredByLDAP),
		string(DiscoveredByVcenter),
		string(DiscoveredBySwitchScanner),
		string(DiscoveredByFirewallScanner),
		string(DiscoveredBySystemUser),
		string(DiscoveredByUnknown),
	}
}

// GetValidAssetTypes returns all valid asset types
func GetValidAssetTypes() []string {
	return []string{
		string(AssetTypeVM),
		string(AssetTypeSwitch),
		string(AssetTypeFirewall),
		string(AssetTypeVcenter),
		string(AssetTypeDomainDevice),
		string(AssetTypeHost),
		string(AssetTypeClient),
		string(AssetTypeNessusScanner),
		string(AssetTypeDomainScanner),
		string(AssetFireWallDevice),
		string(AssetFireWallNetworkInterface),
		string(AssetNetworkDevice),
		string(AssetTypeUnknown),
	}
}

// IsValidOSType checks if the provided OS type is valid
func IsValidOSType(osType string) bool {
	validTypes := GetValidOSTypes()
	for _, valid := range validTypes {
		if osType == valid {
			return true
		}
	}
	return false
}

// IsValidDiscoveredBy checks if the provided discovery source is valid
func IsValidDiscoveredBy(discoveredBy string) bool {
	validSources := GetValidDiscoveredBy()
	for _, valid := range validSources {
		if discoveredBy == valid {
			return true
		}
	}
	return false
}

// IsValidAssetType checks if the provided asset type is valid
func IsValidAssetType(assetType string) bool {
	validTypes := GetValidAssetTypes()
	for _, valid := range validTypes {
		if assetType == valid {
			return true
		}
	}
	return false
}

// NormalizeOSType maps common OS strings to standardized types
func NormalizeOSType(osName string) string {
	osNameLower := strings.ToLower(osName)

	switch {
	case strings.Contains(osNameLower, "fortios") || strings.Contains(osNameLower, "fortigate"):
		return string(OSTypeFortiOS)
	case strings.Contains(osNameLower, "cisco"):
		return string(OSTypeCiscoIOS)
	case strings.Contains(osNameLower, "linux") || strings.Contains(osNameLower, "ubuntu") || strings.Contains(osNameLower, "centos") || strings.Contains(osNameLower, "redhat") || strings.Contains(osNameLower, "debian"):
		return string(OSTypeLinux)
	case strings.Contains(osNameLower, "windows"):
		return string(OSTypeWindows)
	case strings.Contains(osNameLower, "macos") || strings.Contains(osNameLower, "mac os") || strings.Contains(osNameLower, "osx"):
		return string(OSTypeMacOS)
	default:
		return string(OSTypeUnknown)
	}
}

// NormalizeAssetType maps common asset type strings to standardized types
func NormalizeAssetType(assetType string) string {
	assetTypeLower := strings.ToLower(assetType)

	switch {
	case strings.Contains(assetTypeLower, "vcenter"):
		return string(AssetTypeVcenter)
	case strings.Contains(assetTypeLower, "vm") || strings.Contains(assetTypeLower, "virtual machine"):
		return string(AssetTypeVM)
	case strings.Contains(assetTypeLower, "switch"):
		return string(AssetTypeSwitch)
	case strings.Contains(assetTypeLower, "firewall"):
		return string(AssetTypeFirewall)
	case strings.Contains(assetTypeLower, "firewall device"):
		return string(AssetFireWallDevice)
	case strings.Contains(assetTypeLower, "firewall network interface"):
		return string(AssetFireWallNetworkInterface)
	case strings.Contains(assetTypeLower, "domain") && strings.Contains(assetTypeLower, "device"):
		return string(AssetTypeDomainDevice)
	case strings.Contains(assetTypeLower, "host"):
		return string(AssetTypeHost)
	case strings.Contains(assetTypeLower, "client"):
		return string(AssetTypeClient)
	case strings.Contains(assetTypeLower, "nessus") && strings.Contains(assetTypeLower, "scanner"):
		return string(AssetTypeNessusScanner)
	case strings.Contains(assetTypeLower, "domain") && strings.Contains(assetTypeLower, "scanner"):
		return string(AssetTypeDomainScanner)
	case strings.Contains(assetTypeLower, "network") && strings.Contains(assetTypeLower, "device"):
		return string(AssetNetworkDevice)
	default:
		return string(AssetTypeUnknown)
	}
}

// NormalizeDiscoveredBy maps common discovery source strings to standardized types
func NormalizeDiscoveredBy(source string) string {
	sourceLower := strings.ToLower(source)

	switch {
	case strings.Contains(sourceLower, "nmap"):
		return string(DiscoveredByNmap)
	case strings.Contains(sourceLower, "nessus"):
		return string(DiscoveredByNessus)
	case strings.Contains(sourceLower, "ldap"):
		return string(DiscoveredByLDAP)
	case strings.Contains(sourceLower, "vcenter"):
		return string(DiscoveredByVcenter)
	case strings.Contains(sourceLower, "switch scanner"):
		return string(DiscoveredBySwitchScanner)
	case strings.Contains(sourceLower, "firewall scanner"):
		return string(DiscoveredByFirewallScanner)
	case strings.Contains(sourceLower, "system user"):
		return string(DiscoveredBySystemUser)
	default:
		return string(DiscoveredByUnknown)
	}
}
