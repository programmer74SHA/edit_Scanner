package domain

import (
	"fmt"
	"time"

	"github.com/google/uuid"
	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/domain"
)

// NewTestAssetDomain creates a basic test asset domain with sensible defaults
func NewTestAssetDomain() domain.AssetDomain {
	return domain.AssetDomain{
		ID:               uuid.New(),
		Name:             "Test Asset",
		Domain:           "test.local",
		Hostname:         "test-host",
		OSName:           "Ubuntu",
		OSVersion:        "20.04",
		Type:             "Server",
		Description:      "Test asset for unit tests",
		Risk:             1,
		LoggingCompleted: false,
		AssetValue:       100,
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
		Ports:            []domain.Port{},
		VMwareVMs:        []domain.VMwareVM{},
		AssetIPs:         []domain.AssetIP{},
		Scanner:          nil,
	}
}

// NewTestAssetDomainWithPorts creates a test asset with specified number of ports
func NewTestAssetDomainWithPorts(portCount int) domain.AssetDomain {
	asset := NewTestAssetDomain()
	for i := 0; i < portCount; i++ {
		asset.Ports = append(asset.Ports, NewTestPort(asset.ID.String(), 80+i))
	}
	return asset
}

// NewTestAssetDomainWithIPs creates a test asset with specified IPs
func NewTestAssetDomainWithIPs(ips []string) domain.AssetDomain {
	asset := NewTestAssetDomain()
	for i, ip := range ips {
		asset.AssetIPs = append(asset.AssetIPs, domain.AssetIP{
			AssetID:    asset.ID.String(),
			IP:         ip,
			MACAddress: NewTestMACAddress(i),
		})
	}
	return asset
}

// NewTestPort creates a test port
func NewTestPort(assetID string, portNumber int) domain.Port {
	return domain.Port{
		ID:             uuid.New().String(),
		AssetID:        assetID,
		PortNumber:     portNumber,
		Protocol:       "tcp",
		State:          "open",
		ServiceName:    "http",
		ServiceVersion: "1.0",
		Description:    "Test port",
		DiscoveredAt:   time.Now(),
	}
}

// NewTestMACAddress generates a test MAC address
func NewTestMACAddress(index int) string {
	return "00:11:22:33:44:" + fmt.Sprintf("%02d", index%100)
}

// NewTestAssetDomainMinimal creates a minimal valid asset for testing
func NewTestAssetDomainMinimal() domain.AssetDomain {
	return domain.AssetDomain{
		ID:        uuid.New(),
		Hostname:  "minimal-host",
		Type:      "Server",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}

// NewTestAssetDomainWithValidation creates asset for validation testing
func NewTestAssetDomainWithValidation(hostname string, assetType string) domain.AssetDomain {
	asset := NewTestAssetDomain()
	asset.Hostname = hostname
	asset.Type = assetType
	return asset
}

// NewTestAssetDomainWithDuplicateHostname creates asset with hostname for duplicate testing
func NewTestAssetDomainWithDuplicateHostname(hostname string) domain.AssetDomain {
	asset := NewTestAssetDomain()
	asset.Hostname = hostname
	return asset
}

// NewTestAssetDomainWithDuplicateIP creates asset with specific IP for duplicate testing
func NewTestAssetDomainWithDuplicateIP(ip string) domain.AssetDomain {
	asset := NewTestAssetDomain()
	asset.AssetIPs = []domain.AssetIP{
		{
			AssetID:    asset.ID.String(),
			IP:         ip,
			MACAddress: "00:11:22:33:44:55",
		},
	}
	return asset
}

// NewTestVMwareVM creates a test VMware VM
func NewTestVMwareVM(assetID string) domain.VMwareVM {
	return domain.VMwareVM{
		VMID:         "vm-" + uuid.New().String(),
		AssetID:      assetID,
		VMName:       "Test VM",
		Hypervisor:   "ESXi 7.0",
		CPUCount:     4,
		MemoryMB:     8192,
		DiskSizeGB:   100,
		PowerState:   "On",
		LastSyncedAt: time.Now(),
	}
}

// NewTestAssetDomainWithVMwareVMs creates an asset with VMware VMs
func NewTestAssetDomainWithVMwareVMs(vmCount int) domain.AssetDomain {
	asset := NewTestAssetDomain()
	for i := 0; i < vmCount; i++ {
		asset.VMwareVMs = append(asset.VMwareVMs, NewTestVMwareVM(asset.ID.String()))
	}
	return asset
}

// NewTestAssetDomainComplete creates a complete asset with all related data
func NewTestAssetDomainComplete() domain.AssetDomain {
	asset := NewTestAssetDomain()

	// Add IPs
	asset.AssetIPs = []domain.AssetIP{
		{
			AssetID:    asset.ID.String(),
			IP:         "192.168.1.100",
			MACAddress: "00:11:22:33:44:55",
		},
		{
			AssetID:    asset.ID.String(),
			IP:         "10.0.0.50",
			MACAddress: "00:11:22:33:44:56",
		},
	}

	// Add ports
	asset.Ports = []domain.Port{
		NewTestPort(asset.ID.String(), 80),
		NewTestPort(asset.ID.String(), 443),
		NewTestPort(asset.ID.String(), 22),
	}

	// Add VMware VMs
	asset.VMwareVMs = []domain.VMwareVM{
		NewTestVMwareVM(asset.ID.String()),
	}

	return asset
}

// NewTestAssetFilters creates test asset filters
func NewTestAssetFilters() domain.AssetFilters {
	return domain.AssetFilters{
		Name:        "Test",
		Domain:      "test.local",
		Hostname:    "test-host",
		OSName:      "Ubuntu",
		OSVersion:   "20.04",
		Type:        "Server",
		IP:          "192.168.1.100",
		ScannerType: "nmap",
		Network:     "192.168.1.0/24",
	}
}

// NewTestExportData creates test export data
func NewTestExportData() *domain.ExportData {
	assetMap := map[string]interface{}{
		"id":          uuid.New().String(),
		"name":        "Test Asset",
		"hostname":    "test-host",
		"os_name":     "Ubuntu",
		"os_version":  "20.04",
		"asset_type":  "Server",
		"description": "Test asset for export",
	}

	portMap := map[string]interface{}{
		"id":           uuid.New().String(),
		"asset_id":     assetMap["id"],
		"port_number":  80,
		"protocol":     "TCP",
		"state":        "Up",
		"service_name": "http",
	}

	vmMap := map[string]interface{}{
		"vm_id":       "vm-123",
		"asset_id":    assetMap["id"],
		"vm_name":     "Test VM",
		"hypervisor":  "ESXi 7.0",
		"cpu_count":   4,
		"memory_mb":   8192,
		"power_state": "On",
	}

	ipMap := map[string]interface{}{
		"id":          uuid.New().String(),
		"asset_id":    assetMap["id"],
		"ip_address":  "192.168.1.100",
		"mac_address": "00:11:22:33:44:55",
	}

	return &domain.ExportData{
		Assets:    []map[string]interface{}{assetMap},
		Ports:     []map[string]interface{}{portMap},
		VMwareVMs: []map[string]interface{}{vmMap},
		AssetIPs:  []map[string]interface{}{ipMap},
	}
}

// NewTestSortOptions creates test sort options
func NewTestSortOptions() []domain.SortOption {
	return []domain.SortOption{
		{Field: "name", Order: "ASC"},
		{Field: "created_at", Order: "DESC"},
	}
}

// NewTestVulnerability creates a test vulnerability
func NewTestVulnerability() domain.Vulnerability {
	now := time.Now()
	cvssScore := 7.5
	cvss3Score := 7.5
	vprScore := 8.2
	
	return domain.Vulnerability{
		ID:                     uuid.New(),
		PluginID:               12345,
		PluginName:             "Test Vulnerability",
		PluginFamily:           "Test Family",
		Severity:               "High",
		SeverityIndex:          3,
		CVSSBaseScore:          &cvssScore,
		CVSSVector:             "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
		CVSS3BaseScore:         &cvss3Score,
		CVSS3Vector:            "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
		VPRScore:               &vprScore,
		CPE:                    "cpe:/a:vendor:product:1.0",
		Description:            "Test vulnerability description",
		Solution:               "Update to latest version",
		Synopsis:               "Test vulnerability synopsis",
		SeeAlso:                "https://example.com/advisory",
		PluginPublicationDate:  &now,
		PluginModificationDate: &now,
		PluginType:             "remote",
		CVE:                    "CVE-2023-1234",
		BID:                    "12345",
		XRef:                   "test-ref",
		RiskFactor:             "High",
		CreatedAt:              now,
		UpdatedAt:              now,
	}
}

// NewTestAssetVulnerability creates a test asset vulnerability relationship
func NewTestAssetVulnerability() domain.AssetVulnerability {
	now := time.Now()
	port := 80
	
	return domain.AssetVulnerability{
		ID:              uuid.New(),
		AssetID:         uuid.New(),
		VulnerabilityID: uuid.New(),
		Port:            &port,
		Protocol:        "tcp",
		PluginOutput:    "Test plugin output",
		FirstDetected:   now,
		LastDetected:    now,
		Status:          "active",
		CreatedAt:       now,
		UpdatedAt:       now,
	}
}

// NewTestNessusScan creates a test Nessus scan
func NewTestNessusScan() domain.NessusScan {
	now := time.Now()
	startTime := now.Add(-1 * time.Hour)
	
	return domain.NessusScan{
		ID:            1,
		UUID:          "12345-67890-abcdef",
		Name:          "Test Scan",
		Status:        "completed",
		ScannerName:   "Test Scanner",
		Targets:       "192.168.1.0/24",
		ScanStartTime: &startTime,
		ScanEndTime:   &now,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
}
