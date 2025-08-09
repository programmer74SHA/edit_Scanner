package domain

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"

	scannerDomain "gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanner/domain"
)

var (
	ErrIPAlreadyExists       = errors.New("IP address already exists")
	ErrHostnameAlreadyExists = errors.New("Hostname already exists")
)

type AssetUUID = uuid.UUID

type Port struct {
	ID             string    `json:"id"`
	AssetID        string    `json:"asset_id"`
	PortNumber     int       `json:"port_number"`
	Protocol       string    `json:"protocol"`
	State          string    `json:"state"`
	ServiceName    string    `json:"service_name"`
	ServiceVersion string    `json:"service_version"`
	Description    string    `json:"description"`
	DiscoveredAt   time.Time `json:"discovered_at"`
}

type VMwareVM struct {
	VMID         string    `json:"vm_id"`
	AssetID      string    `json:"asset_id"`
	VMName       string    `json:"vm_name"`
	HostID       *string   `json:"host_id,omitempty"`
	ClusterID    *string   `json:"cluster_id,omitempty"`
	Hypervisor   string    `json:"hypervisor"`
	CPUCount     int32     `json:"cpu_count"`
	MemoryMB     int32     `json:"memory_mb"`
	DiskSizeGB   int       `json:"disk_size_gb"`
	PowerState   string    `json:"power_state"`
	LastSyncedAt time.Time `json:"last_synced_at"`
}

type VCenterDatacenter struct {
	ID            string    `json:"id"`
	VsphereID     string    `json:"vsphere_id"`
	Name          string    `json:"name"`
	Moref         string    `json:"moref"`
	VCenterServer string    `json:"vcenter_server"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
	LastSyncedAt  time.Time `json:"last_synced_at"`
}

type VCenterHost struct {
	ID                 string    `json:"id"`
	DatacenterID       string    `json:"datacenter_id"`
	ClusterID          *string   `json:"cluster_id,omitempty"`
	VsphereID          string    `json:"vsphere_id"`
	Name               string    `json:"name"`
	Moref              string    `json:"moref"`
	ConnectionState    string    `json:"connection_state"`
	PowerState         string    `json:"power_state"`
	CPUUsageMhz        *int32    `json:"cpu_usage_mhz,omitempty"`
	MemoryUsageMB      *int64    `json:"memory_usage_mb,omitempty"`
	TotalMemoryMB      *int64    `json:"total_memory_mb,omitempty"`
	CPUCores           *int32    `json:"cpu_cores,omitempty"`
	CPUThreads         *int32    `json:"cpu_threads,omitempty"`
	CPUModel           string    `json:"cpu_model"`
	CPUMhz             *int32    `json:"cpu_mhz,omitempty"`
	NumNICs            *int32    `json:"num_nics,omitempty"`
	NumVMs             *int32    `json:"num_vms,omitempty"`
	UptimeSeconds      *int64    `json:"uptime_seconds,omitempty"`
	Vendor             string    `json:"vendor"`
	Model              string    `json:"model"`
	BiosVersion        string    `json:"bios_version"`
	HypervisorType     string    `json:"hypervisor_type"`
	HypervisorVersion  string    `json:"hypervisor_version"`
	VCenterServer      string    `json:"vcenter_server"`
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
	LastSyncedAt       time.Time `json:"last_synced_at"`
}

type VCenterDatastore struct {
	ID                  string    `json:"id"`
	DatacenterID        string    `json:"datacenter_id"`
	VsphereID           string    `json:"vsphere_id"`
	Name                string    `json:"name"`
	Moref               string    `json:"moref"`
	Type                string    `json:"type"`
	CapacityGB          *int64    `json:"capacity_gb,omitempty"`
	FreeSpaceGB         *int64    `json:"free_space_gb,omitempty"`
	ProvisionedSpaceGB  *int64    `json:"provisioned_space_gb,omitempty"`
	Accessible          *bool     `json:"accessible,omitempty"`
	MultipleHostAccess  *bool     `json:"multiple_host_access,omitempty"`
	VCenterServer       string    `json:"vcenter_server"`
	CreatedAt           time.Time `json:"created_at"`
	UpdatedAt           time.Time `json:"updated_at"`
	LastSyncedAt        time.Time `json:"last_synced_at"`
}

type VCenterNetwork struct {
	ID            string    `json:"id"`
	DatacenterID  string    `json:"datacenter_id"`
	VsphereID     string    `json:"vsphere_id"`
	Name          string    `json:"name"`
	Moref         string    `json:"moref"`
	NetworkType   string    `json:"network_type"`
	VLanID        *int      `json:"vlan_id,omitempty"`
	SwitchName    string    `json:"switch_name"`
	Accessible    *bool     `json:"accessible,omitempty"`
	VCenterServer string    `json:"vcenter_server"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
	LastSyncedAt  time.Time `json:"last_synced_at"`
}

type VCenterCluster struct {
	ID                string    `json:"id"`
	DatacenterID      string    `json:"datacenter_id"`
	VsphereID         string    `json:"vsphere_id"`
	Name              string    `json:"name"`
	Moref             string    `json:"moref"`
	TotalCPUMhz       *int32    `json:"total_cpu_mhz,omitempty"`
	UsedCPUMhz        *int32    `json:"used_cpu_mhz,omitempty"`
	TotalMemoryMB     *int64    `json:"total_memory_mb,omitempty"`
	UsedMemoryMB      *int64    `json:"used_memory_mb,omitempty"`
	NumHosts          *int32    `json:"num_hosts,omitempty"`
	NumVMs            *int32    `json:"num_vms,omitempty"`
	DRSEnabled        *bool     `json:"drs_enabled,omitempty"`
	HAEnabled         *bool     `json:"ha_enabled,omitempty"`
	VCenterServer     string    `json:"vcenter_server"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
	LastSyncedAt      time.Time `json:"last_synced_at"`
}

type VCenterHostIP struct {
	ID         string `json:"id"`
	HostID     string `json:"host_id"`
	IPAddress  string `json:"ip_address"`
	IPType     string `json:"ip_type"` // management, vmotion, etc.
	SubnetMask string `json:"subnet_mask"`
	Gateway    string `json:"gateway"`
	DHCP       *bool  `json:"dhcp,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

type VCenterHostNIC struct {
	ID         string    `json:"id"`
	HostID     string    `json:"host_id"`
	Device     string    `json:"device"`
	Driver     string    `json:"driver"`
	LinkSpeed  *int32    `json:"link_speed,omitempty"` // Mbps
	Duplex     string    `json:"duplex"`
	MacAddress string    `json:"mac_address"`
	PCI        string    `json:"pci"`
	WakeOnLAN  *bool     `json:"wake_on_lan,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

type VCenterVirtualSwitch struct {
	ID           string    `json:"id"`
	HostID       string    `json:"host_id"`
	VsphereID    string    `json:"vsphere_id"`
	Name         string    `json:"name"`
	SwitchType   string    `json:"switch_type"` // standard, distributed
	NumPorts     *int32    `json:"num_ports,omitempty"`
	UsedPorts    *int32    `json:"used_ports,omitempty"`
	MTU          *int32    `json:"mtu,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	LastSyncedAt time.Time `json:"last_synced_at"`
}

type VMDatastoreRelation struct {
	ID            string    `json:"id"`
	VMID          string    `json:"vm_id"`
	DatastoreID   string    `json:"datastore_id"`
	UsedSpaceGB   *int64    `json:"used_space_gb,omitempty"`
	CommittedGB   *int64    `json:"committed_gb,omitempty"`
	UncommittedGB *int64    `json:"uncommitted_gb,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type VMNetworkRelation struct {
	ID             string    `json:"id"`
	VMID           string    `json:"vm_id"`
	NetworkID      string    `json:"network_id"`
	MacAddress     string    `json:"mac_address"`
	IPAddresses    string    `json:"ip_addresses"` // JSON array of IPs
	Connected      *bool     `json:"connected,omitempty"`
	StartConnected *bool     `json:"start_connected,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

type HostDatastoreRelation struct {
	ID          string    `json:"id"`
	HostID      string    `json:"host_id"`
	DatastoreID string    `json:"datastore_id"`
	Accessible  *bool     `json:"accessible,omitempty"`
	Mounted     *bool     `json:"mounted,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Composite types for enhanced API responses
type VCenterHostDetails struct {
	Host            VCenterHost           `json:"host"`
	IPs             []VCenterHostIP       `json:"ips"`
	NICs            []VCenterHostNIC      `json:"nics"`
	VirtualSwitches []VCenterVirtualSwitch `json:"virtual_switches"`
	DatastoreRelations []HostDatastoreRelation `json:"datastore_relations"`
}

type VMRelations struct {
	DatastoreRelations []VMDatastoreRelation `json:"datastore_relations"`
	NetworkRelations   []VMNetworkRelation   `json:"network_relations"`
}

type AssetIP struct {
	ID          string `json:"id"`
	AssetID     string `json:"asset_id"`
	InterfaceID string `json:"interface_id"`
	IP          string `json:"ip"`
	MACAddress  string `json:"mac_address"`
	CIDRPrefix  *int   `json:"cidr_prefix"`
}

type AssetDomain struct {
	ID               AssetUUID                    `json:"id"`
	Name             string                       `json:"name"`
	Domain           string                       `json:"domain"`
	Hostname         string                       `json:"hostname"`
	OSName           string                       `json:"os_name"`
	OSVersion        string                       `json:"os_version"`
	Type             string                       `json:"type"`
	Description      string                       `json:"description"`
	DiscoveredBy     string                       `json:"discovered_by"`
	Risk             int                          `json:"risk"`
	LoggingCompleted bool                         `json:"logging_completed"`
	AssetValue       int                          `json:"asset_value"`
	CreatedAt        time.Time                    `json:"created_at"`
	UpdatedAt        time.Time                    `json:"updated_at"`
	Ports            []Port                       `json:"-"`
	VMwareVMs        []VMwareVM                   `json:"-"`
	AssetIPs         []AssetIP                    `json:"-"`
	Scanner          *scannerDomain.ScannerDomain `json:"-"`
}

type SortOption struct {
	Field string
	Order string
}

type AssetFilters struct {
	Name        string
	Domain      string
	Hostname    string
	OSName      string
	OSVersion   string
	Type        string
	IP          string
	ScannerType string
	Network     string
}

func AssetUUIDFromString(s string) (uuid.UUID, error) {
	return uuid.Parse(s)
}

// NormalizeOSName normalizes the OS name using the standardized types
func (a *AssetDomain) NormalizeOSName() {
	if a.OSName != "" {
		a.OSName = NormalizeMultiValueField(a.OSName, NormalizeOSType)
	}
}

// NormalizeAssetType normalizes the asset type using the standardized types
func (a *AssetDomain) NormalizeAssetType() {
	if a.Type != "" {
		a.Type = NormalizeMultiValueField(a.Type, NormalizeAssetType)
	}
}

// AddOSType adds an OS type to the asset (multi-value support)
func (a *AssetDomain) AddOSType(osType string) {
	normalized := NormalizeOSType(osType)
	a.OSName = UpdateMultiValueField(a.OSName, normalized)
}

// AddDiscoveredBy adds a discovery source to the asset (multi-value support)
func (a *AssetDomain) AddDiscoveredBy(source string) {
	// Validate source against allowed values
	if IsValidDiscoveredBy(source) {
		a.DiscoveredBy = UpdateMultiValueField(a.DiscoveredBy, source)
	}
}

// AddAssetType adds an asset type to the asset (multi-value support)
func (a *AssetDomain) AddAssetType(assetType string) {
	normalized := NormalizeAssetType(assetType)
	a.Type = UpdateMultiValueField(a.Type, normalized)
}

// ValidateFieldValues validates that all multi-value fields contain only valid values
func (a *AssetDomain) ValidateFieldValues() error {
	// Validate OS types
	if a.OSName != "" && !ValidateMultiValueField(a.OSName, GetValidOSTypes()) {
		return errors.New("invalid OS type(s) in OSName field")
	}

	// Validate discovery sources
	if a.DiscoveredBy != "" && !ValidateMultiValueField(a.DiscoveredBy, GetValidDiscoveredBy()) {
		return errors.New("invalid discovery source(s) in DiscoveredBy field")
	}

	// Validate asset types
	if a.Type != "" && !ValidateMultiValueField(a.Type, GetValidAssetTypes()) {
		return errors.New("invalid asset type(s) in Type field")
	}

	return nil
}

// ToMap converts any struct to map[string]interface{} using JSON marshaling/unmarshaling
func ToMap(obj interface{}) (map[string]interface{}, error) {
	// Marshal to JSON
	jsonData, err := json.Marshal(obj)
	if err != nil {
		return nil, err
	}

	// Unmarshal to map
	var result map[string]interface{}
	err = json.Unmarshal(jsonData, &result)
	if err != nil {
		return nil, err
	}

	return result, nil
}
