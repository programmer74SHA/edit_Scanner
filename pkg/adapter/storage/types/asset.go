package types

import (
	"strings"
	"time"

	"gorm.io/gorm"
)

// Base tables (no dependencies)
type Vendors struct {
	ID         uint      `gorm:"primaryKey;autoIncrement"`
	VendorName string    `gorm:"size:100;uniqueIndex;not null"`
	VendorCode string    `gorm:"size:20;uniqueIndex;not null"`
	CreatedAt  time.Time `gorm:"autoCreateTime"`

	// Relationships
	Assets []Assets `gorm:"foreignKey:VendorID"`
}

func (Vendors) TableName() string {
	return "vendors"
}

type InterfaceTypes struct {
	ID          uint   `gorm:"primaryKey;autoIncrement"`
	TypeName    string `gorm:"size:50;uniqueIndex;not null"`
	Description string `gorm:"size:255"`

	// Relationships
	Interfaces []Interfaces `gorm:"foreignKey:InterfaceTypeID"`
}

func (InterfaceTypes) TableName() string {
	return "interface_types"
}

// Assets table (depends on vendors)
type Assets struct {
	ID               string     `gorm:"column:id;size:50;primaryKey"`
	VendorID         uint       `gorm:"not null;index"`
	Name             string     `gorm:"size:255"`
	Domain           string     `gorm:"size:255"`
	Hostname         string     `gorm:"size:255"`
	OSName           string     `gorm:"size:100;column:os_name"`
	OSVersion        string     `gorm:"size:100;column:os_version"`
	Description      string     `gorm:"type:text"`
	AssetType        string     `gorm:"size:50;default:'firewall';column:asset_type"`
	DiscoveredBy     *string    `gorm:"column:discovered_by;size:255"`
	Risk             int        `gorm:"type:int;default:2;check:risk >= 0 AND risk <= 5"`
	LoggingCompleted bool       `gorm:"default:false;column:logging_completed"`
	AssetValue       float64    `gorm:"type:decimal(15,2);default:0.00;column:asset_value"`
	CreatedAt        time.Time  `gorm:"autoCreateTime;column:created_at"`
	UpdatedAt        time.Time  `gorm:"autoUpdateTime;column:updated_at"`
	DeletedAt        *time.Time `gorm:"index;column:deleted_at"`

	// Relationships
	Vendor          Vendors           `gorm:"foreignKey:VendorID"`
	FirewallDetails []FirewallDetails `gorm:"foreignKey:AssetID"`
	IPs             []IPs             `gorm:"foreignKey:AssetID"`
	AssetScanJobs   []AssetScanJob    `gorm:"foreignKey:AssetID"`
	Ports           []Port            `gorm:"foreignKey:AssetID"`
	VMwareVMs       []VMwareVM        `gorm:"foreignKey:AssetID"`
	Interfaces      []Interfaces      `gorm:"foreignKey:AssetID"`
	VLANs           []VLANs           `gorm:"foreignKey:AssetID"`
}

func (Assets) TableName() string {
	return "assets"
}

// Firewall details (depends on assets)
type FirewallDetails struct {
	ID              string `gorm:"column:id;size:50;primaryKey"`
	AssetID         string `gorm:"not null;uniqueIndex"`
	Model           string `gorm:"size:100"`
	FirmwareVersion string `gorm:"size:100"`
	SerialNumber    string `gorm:"size:100"`
	IsHAEnabled     bool   `gorm:"default:false"`
	HARole          string `gorm:"type:enum('active','passive','standalone');default:'standalone'"`
	ManagementIP    string `gorm:"size:45;not null"`
	SiteName        string `gorm:"size:255"`
	Location        string `gorm:"size:255"`
	Status          string `gorm:"type:enum('active','inactive','maintenance');default:'active'"`
	LastSync        *time.Time
	SyncStatus      string     `gorm:"type:enum('success','failed','pending');default:'pending'"`
	CreatedAt       time.Time  `gorm:"autoCreateTime"`
	UpdatedAt       time.Time  `gorm:"autoUpdateTime"`
	DeletedAt       *time.Time `gorm:"index;column:deleted_at"`

	// Relationships
	Asset    Assets           `gorm:"foreignKey:AssetID"`
	Policies []FirewallPolicy `gorm:"foreignKey:FirewallDetailsID"`
}

func (FirewallDetails) TableName() string {
	return "firewall_details"
}

// Zones table (depends on firewall_details)
type Zones struct {
	ID                    string     `gorm:"column:id;size:50;primaryKey"`
	ZoneName              string     `gorm:"size:100;not null;uniqueIndex"`
	ZoneType              string     `gorm:"type:enum('security','virtual_router','context','vdom','vsys');default:'security'"`
	VendorZoneType        string     `gorm:"size:50"`
	Description           string     `gorm:"type:text"`
	ZoneMode              string     `gorm:"type:enum('layer3','layer2','virtual-wire','tap');default:'layer3'"`
	IntrazoneAction       string     `gorm:"type:enum('allow','deny');default:'allow'"`
	ZoneProtectionProfile string     `gorm:"size:100"`
	LogSetting            string     `gorm:"size:100"`
	CreatedAt             time.Time  `gorm:"autoCreateTime"`
	UpdatedAt             time.Time  `gorm:"autoUpdateTime"`
	DeletedAt             *time.Time `gorm:"index;column:deleted_at"`
	FirewallID            string     `gorm:"size:255;not null"`

	// Relationships
	FirewallDetails FirewallDetails `gorm:"foreignKey:FirewallID"`
	ZoneDetails     []ZoneDetails   `gorm:"foreignKey:ZoneID"`
}

func (Zones) TableName() string {
	return "zones"
}

// Interfaces table (depends on interface_types and assets, has self-reference)
type Interfaces struct {
	ID                   string     `gorm:"column:id;size:50;primaryKey"`
	InterfaceName        string     `gorm:"size:100;not null;uniqueIndex"`
	InterfaceTypeID      uint       `gorm:"not null;index"`
	AssetID              *string    `gorm:"size:50;index"`
	VirtualRouter        string     `gorm:"size:100"`
	VirtualSystem        string     `gorm:"size:100"`
	Description          string     `gorm:"type:text"`
	OperationalStatus    string     `gorm:"type:enum('up','down','unknown');default:'unknown'"`
	AdminStatus          string     `gorm:"type:enum('up','down');default:'up'"`
	ParentInterfaceID    *string    `gorm:"size:50;index"` // Self-reference for sub-interfaces
	VLANId               *int       `gorm:"column:vlan_id"`
	MacAddress           string     `gorm:"size:17"`
	VendorSpecificConfig string     `gorm:"type:json"`
	CreatedAt            time.Time  `gorm:"autoCreateTime"`
	UpdatedAt            time.Time  `gorm:"autoUpdateTime"`
	DeletedAt            *time.Time `gorm:"index;column:deleted_at"`

	// Relationships
	Asset           *Assets         `gorm:"foreignKey:AssetID"`
	InterfaceType   InterfaceTypes  `gorm:"foreignKey:InterfaceTypeID"`
	ParentInterface *Interfaces     `gorm:"foreignKey:ParentInterfaceID"` // Self-reference
	SubInterfaces   []Interfaces    `gorm:"foreignKey:ParentInterfaceID"`
	IPs             []IPs           `gorm:"foreignKey:InterfaceID"`
	ZoneDetails     []ZoneDetails   `gorm:"foreignKey:FirewallInterfaceID"`
	VLANInterfaces  []VLANInterface `gorm:"foreignKey:InterfaceID"`
}

func (Interfaces) TableName() string {
	return "interfaces"
}

// VLANs table (depends on assets)
type VLANs struct {
	ID                   string     `gorm:"column:id;size:50;primaryKey"`
	VLANNumber           int        `gorm:"not null;column:vlan_id"`
	VLANName             string     `gorm:"size:100"`
	Description          string     `gorm:"type:text"`
	IsNative             bool       `gorm:"default:false"`
	VendorSpecificConfig string     `gorm:"type:json"`
	DeviceType           string     `gorm:"size:255;not null"`
	AssetID              string     `gorm:"size:50;not null"`
	CreatedAt            time.Time  `gorm:"autoCreateTime"`
	UpdatedAt            time.Time  `gorm:"autoUpdateTime"`
	DeletedAt            *time.Time `gorm:"index;column:deleted_at"`

	// Relationships
	Asset       Assets        `gorm:"foreignKey:AssetID"`
	ZoneDetails []ZoneDetails `gorm:"foreignKey:VLANTableID"`
}

func (VLANs) TableName() string {
	return "vlans"
}

// IPs table (depends on assets and interfaces)
type IPs struct {
	ID          string     `gorm:"column:id;size:50;primaryKey"`
	AssetID     string     `gorm:"not null;index"`
	InterfaceID *string    `gorm:"index"` // Made optional for management IPs
	IPAddress   string     `gorm:"size:45;not null;column:ip_address"`
	MacAddress  string     `gorm:"size:17;column:mac_address"`
	CIDRPrefix  *int       `gorm:"column:cidr_prefix"`
	CreatedAt   time.Time  `gorm:"autoCreateTime"`
	UpdatedAt   *time.Time `gorm:"autoUpdateTime"`
	DeletedAt   *time.Time `gorm:"index"`

	// Relationships
	Asset     Assets      `gorm:"foreignKey:AssetID"`
	Interface *Interfaces `gorm:"foreignKey:InterfaceID"`
}

func (IPs) TableName() string {
	return "ips"
}

// VLANInterface junction table
type VLANInterface struct {
	ID          uint       `gorm:"primaryKey;autoIncrement"`
	VLANTableID string     `gorm:"size:50;not null;index;column:vlan_table_id"` // References vlans.id (primary key)
	InterfaceID string     `gorm:"size:50;not null;index"`                      // References interfaces.id
	IsNative    *bool      `gorm:""`
	CreatedAt   *time.Time `gorm:""`
	DeletedAt   *time.Time `gorm:"index;column:deleted_at"`

	// Relationships - VLANTableID references vlans.id (primary key)
	VLAN      VLANs      `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE;foreignKey:VLANTableID;references:ID"`
	Interface Interfaces `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE;foreignKey:InterfaceID;references:ID"`
}

func (VLANInterface) TableName() string {
	return "vlan_interface"
}

// Zone details (junction table - depends on zones, interfaces, and vlans)
type ZoneDetails struct {
	ID                  string     `gorm:"column:id;size:50;primaryKey"`
	ZoneID              string     `gorm:"not null;index"`
	FirewallInterfaceID string     `gorm:"not null;index;column:firewall_interface_id"`
	VLANTableID         string     `gorm:"not null;index;column:vlan_table_id"` // References vlans.id
	CreatedAt           time.Time  `gorm:"autoCreateTime"`
	UpdatedAt           time.Time  `gorm:"autoUpdateTime"`
	DeletedAt           *time.Time `gorm:"index;column:deleted_at"`

	// Relationships
	Zone      Zones      `gorm:"foreignKey:ZoneID"`
	Interface Interfaces `gorm:"foreignKey:FirewallInterfaceID"`
	VLAN      VLANs      `gorm:"foreignKey:VLANTableID;references:ID"` // References vlans.id
}

func (ZoneDetails) TableName() string {
	return "zone_details"
}

// Firewall policies (depends on firewall_details and zones)
type FirewallPolicy struct {
	ID                   string     `gorm:"column:id;size:50;primaryKey"`
	FirewallDetailsID    string     `gorm:"not null;index"`
	PolicyName           string     `gorm:"size:255"`
	PolicyID             *int       `gorm:"index"`
	Source               *string    `gorm:"index"`
	Destination          *string    `gorm:"index"`
	Action               string     `gorm:"type:enum('allow','deny','drop','reject','tunnel');default:'deny'"`
	PolicyType           string     `gorm:"type:enum('security','nat','qos','decryption');default:'security'"`
	Status               string     `gorm:"type:enum('enabled','disabled');default:'enabled'"`
	RuleOrder            *int       `gorm:"index"`
	VendorSpecificConfig string     `gorm:"type:json"`
	CreatedAt            time.Time  `gorm:"autoCreateTime"`
	UpdatedAt            time.Time  `gorm:"autoUpdateTime"`
	DeletedAt            *time.Time `gorm:"index;column:deleted_at"`

	// Relationships
	FirewallDetails FirewallDetails `gorm:"foreignKey:FirewallDetailsID"`
}

func (FirewallPolicy) TableName() string {
	return "firewall_policy"
}

// Keep your existing Port and VMwareVM types...
type Port struct {
	ID             string     `gorm:"column:id;size:50;primaryKey"`
	AssetID        string     `gorm:"column:asset_id;not null"`
	PortNumber     int        `gorm:"column:port_number;not null"`
	Protocol       string     `gorm:"column:protocol;type:enum('TCP','UDP');not null"`
	State          string     `gorm:"column:state;type:enum('Up','Down','Unknown');not null"`
	ServiceName    *string    `gorm:"column:service_name;size:100"`
	ServiceVersion *string    `gorm:"column:service_version;size:100"`
	Description    *string    `gorm:"column:description;size:500"`
	DiscoveredAt   time.Time  `gorm:"column:discovered_at;type:datetime;default:CURRENT_TIMESTAMP"`
	DeletedAt      *time.Time `gorm:"column:deleted_at;type:datetime"`

	Asset Assets `gorm:"foreignKey:AssetID"`
}

func (Port) TableName() string {
	return "ports"
}

type VMwareVM struct {
	VMID         string    `gorm:"column:vm_id;size:50;primaryKey"`
	AssetID      string    `gorm:"column:asset_id;not null"`
	VMName       string    `gorm:"column:vm_name;size:255;not null"`
	HostID       *string   `gorm:"column:host_id;size:50;index"` // Reference to vcenter_hosts
	ClusterID    *string   `gorm:"column:cluster_id;size:50;index"` // Reference to vcenter_clusters
	Hypervisor   string    `gorm:"column:hypervisor;size:100;not null"`
	CPUCount     int32     `gorm:"column:cpu_count;not null"`
	MemoryMB     int32     `gorm:"column:memory_mb;not null"`
	DiskSizeGB   int       `gorm:"column:disk_size_gb;not null"`
	PowerState   string    `gorm:"column:power_state;type:enum('On','Off','Suspended');not null"`
	LastSyncedAt time.Time `gorm:"column:last_synced_at;type:datetime;default:CURRENT_TIMESTAMP"`

	Asset              Assets                 `gorm:"foreignKey:AssetID"`
	Host               *VCenterHost           `gorm:"foreignKey:HostID;references:ID"`
	Cluster            *VCenterCluster        `gorm:"foreignKey:ClusterID;references:ID"`
}

func (VMwareVM) TableName() string {
	return "vmware_vms"
}

// VCenter infrastructure entities
type VCenterDatacenter struct {
	ID            string     `gorm:"column:id;size:50;primaryKey"`
	VsphereID     string     `gorm:"column:vsphere_id;size:100;not null;index"`
	Name          string     `gorm:"column:name;size:255;not null"`
	Moref         string     `gorm:"column:moref;size:100;not null;index"`
	VCenterServer string     `gorm:"column:vcenter_server;size:255;not null"`
	CreatedAt     time.Time  `gorm:"column:created_at;autoCreateTime"`
	UpdatedAt     time.Time  `gorm:"column:updated_at;autoUpdateTime"`
	LastSyncedAt  time.Time  `gorm:"column:last_synced_at;type:datetime;default:CURRENT_TIMESTAMP"`
	DeletedAt     *time.Time `gorm:"column:deleted_at;index"`

	// Relationships
	Hosts      []VCenterHost      `gorm:"foreignKey:DatacenterID;references:ID"`
	Datastores []VCenterDatastore `gorm:"foreignKey:DatacenterID;references:ID"`
	Networks   []VCenterNetwork   `gorm:"foreignKey:DatacenterID;references:ID"`
}

func (VCenterDatacenter) TableName() string {
	return "vcenter_datacenters"
}

type VCenterHost struct {
	ID                 string     `gorm:"column:id;size:50;primaryKey"`
	DatacenterID       string     `gorm:"column:datacenter_id;size:50;not null;index"`
	ClusterID          *string    `gorm:"column:cluster_id;size:50;index"`
	VsphereID          string     `gorm:"column:vsphere_id;size:100;not null;index"`
	Name               string     `gorm:"column:name;size:255;not null"`
	Moref              string     `gorm:"column:moref;size:100;not null;index"`
	ConnectionState    string     `gorm:"column:connection_state;size:50"`
	PowerState         string     `gorm:"column:power_state;size:50"`
	CPUUsageMhz        *int32     `gorm:"column:cpu_usage_mhz"`
	MemoryUsageMB      *int64     `gorm:"column:memory_usage_mb"`
	TotalMemoryMB      *int64     `gorm:"column:total_memory_mb"`
	CPUCores           *int32     `gorm:"column:cpu_cores"`
	CPUThreads         *int32     `gorm:"column:cpu_threads"`
	CPUModel           string     `gorm:"column:cpu_model;size:255"`
	CPUMhz             *int32     `gorm:"column:cpu_mhz"`
	NumNICs            *int32     `gorm:"column:num_nics"`
	NumVMs             *int32     `gorm:"column:num_vms"`
	UptimeSeconds      *int64     `gorm:"column:uptime_seconds"`
	Vendor             string     `gorm:"column:vendor;size:100"`
	Model              string     `gorm:"column:model;size:255"`
	BiosVersion        string     `gorm:"column:bios_version;size:100"`
	HypervisorType     string     `gorm:"column:hypervisor_type;size:100"`
	HypervisorVersion  string     `gorm:"column:hypervisor_version;size:100"`
	VCenterServer      string     `gorm:"column:vcenter_server;size:255;not null"`
	CreatedAt          time.Time  `gorm:"column:created_at;autoCreateTime"`
	UpdatedAt          time.Time  `gorm:"column:updated_at;autoUpdateTime"`
	LastSyncedAt       time.Time  `gorm:"column:last_synced_at;type:datetime;default:CURRENT_TIMESTAMP"`
	DeletedAt          *time.Time `gorm:"column:deleted_at;index"`

	// Relationships
	Datacenter       VCenterDatacenter        `gorm:"foreignKey:DatacenterID;references:ID"`
	Cluster          *VCenterCluster          `gorm:"foreignKey:ClusterID;references:ID"`
	VMwareVMs        []VMwareVM               `gorm:"foreignKey:HostID;references:ID"`
	HostIPs          []VCenterHostIP          `gorm:"foreignKey:HostID;references:ID"`
	HostNICs         []VCenterHostNIC         `gorm:"foreignKey:HostID;references:ID"`
	VirtualSwitches  []VCenterVirtualSwitch   `gorm:"foreignKey:HostID;references:ID"`
	DatastoreRelations []HostDatastoreRelation `gorm:"foreignKey:HostID;references:ID"`
}

func (VCenterHost) TableName() string {
	return "vcenter_hosts"
}

type VCenterDatastore struct {
	ID                  string     `gorm:"column:id;size:50;primaryKey"`
	DatacenterID        string     `gorm:"column:datacenter_id;size:50;not null;index"`
	VsphereID           string     `gorm:"column:vsphere_id;size:100;not null;index"`
	Name                string     `gorm:"column:name;size:255;not null"`
	Moref               string     `gorm:"column:moref;size:100;not null;index"`
	Type                string     `gorm:"column:type;size:50"`
	CapacityGB          *int64     `gorm:"column:capacity_gb"`
	FreeSpaceGB         *int64     `gorm:"column:free_space_gb"`
	ProvisionedSpaceGB  *int64     `gorm:"column:provisioned_space_gb"`
	Accessible          *bool      `gorm:"column:accessible"`
	MultipleHostAccess  *bool      `gorm:"column:multiple_host_access"`
	VCenterServer       string     `gorm:"column:vcenter_server;size:255;not null"`
	CreatedAt           time.Time  `gorm:"column:created_at;autoCreateTime"`
	UpdatedAt           time.Time  `gorm:"column:updated_at;autoUpdateTime"`
	LastSyncedAt        time.Time  `gorm:"column:last_synced_at;type:datetime;default:CURRENT_TIMESTAMP"`
	DeletedAt           *time.Time `gorm:"column:deleted_at;index"`

	// Relationships
	Datacenter VCenterDatacenter `gorm:"foreignKey:DatacenterID;references:ID"`
}

func (VCenterDatastore) TableName() string {
	return "vcenter_datastores"
}

type VCenterNetwork struct {
	ID            string     `gorm:"column:id;size:50;primaryKey"`
	DatacenterID  string     `gorm:"column:datacenter_id;size:50;not null;index"`
	VsphereID     string     `gorm:"column:vsphere_id;size:100;not null;index"`
	Name          string     `gorm:"column:name;size:255;not null"`
	Moref         string     `gorm:"column:moref;size:100;not null;index"`
	NetworkType   string     `gorm:"column:network_type;size:100"`
	VLanID        *int       `gorm:"column:vlan_id"`
	SwitchName    string     `gorm:"column:switch_name;size:255"`
	Accessible    *bool      `gorm:"column:accessible"`
	VCenterServer string     `gorm:"column:vcenter_server;size:255;not null"`
	CreatedAt     time.Time  `gorm:"column:created_at;autoCreateTime"`
	UpdatedAt     time.Time  `gorm:"column:updated_at;autoUpdateTime"`
	LastSyncedAt  time.Time  `gorm:"column:last_synced_at;type:datetime;default:CURRENT_TIMESTAMP"`
	DeletedAt     *time.Time `gorm:"column:deleted_at;index"`

	// Relationships
	Datacenter VCenterDatacenter `gorm:"foreignKey:DatacenterID;references:ID"`
}

func (VCenterNetwork) TableName() string {
	return "vcenter_networks"
}

// VCenter Clusters
type VCenterCluster struct {
	ID                string     `gorm:"column:id;size:50;primaryKey"`
	DatacenterID      string     `gorm:"column:datacenter_id;size:50;not null;index"`
	VsphereID         string     `gorm:"column:vsphere_id;size:100;not null;index"`
	Name              string     `gorm:"column:name;size:255;not null"`
	Moref             string     `gorm:"column:moref;size:100;not null;index"`
	TotalCPUMhz       *int32     `gorm:"column:total_cpu_mhz"`
	UsedCPUMhz        *int32     `gorm:"column:used_cpu_mhz"`
	TotalMemoryMB     *int64     `gorm:"column:total_memory_mb"`
	UsedMemoryMB      *int64     `gorm:"column:used_memory_mb"`
	NumHosts          *int32     `gorm:"column:num_hosts"`
	NumVMs            *int32     `gorm:"column:num_vms"`
	DRSEnabled        *bool      `gorm:"column:drs_enabled"`
	HAEnabled         *bool      `gorm:"column:ha_enabled"`
	VCenterServer     string     `gorm:"column:vcenter_server;size:255;not null"`
	CreatedAt         time.Time  `gorm:"column:created_at;autoCreateTime"`
	UpdatedAt         time.Time  `gorm:"column:updated_at;autoUpdateTime"`
	LastSyncedAt      time.Time  `gorm:"column:last_synced_at;type:datetime;default:CURRENT_TIMESTAMP"`
	DeletedAt         *time.Time `gorm:"column:deleted_at;index"`

	// Relationships
	Datacenter VCenterDatacenter `gorm:"foreignKey:DatacenterID;references:ID"`
	Hosts      []VCenterHost      `gorm:"foreignKey:ClusterID;references:ID"`
}

func (VCenterCluster) TableName() string {
	return "vcenter_clusters"
}

// Host IPs - for storing host management and other IP addresses
type VCenterHostIP struct {
	ID            string     `gorm:"column:id;size:50;primaryKey"`
	HostID        string     `gorm:"column:host_id;size:50;not null;index"`
	IPAddress     string     `gorm:"column:ip_address;size:45;not null"`
	IPType        string     `gorm:"column:ip_type;size:50;not null"` // management, vmotion, etc.
	SubnetMask    string     `gorm:"column:subnet_mask;size:45"`
	Gateway       string     `gorm:"column:gateway;size:45"`
	DHCP          *bool      `gorm:"column:dhcp"`
	CreatedAt     time.Time  `gorm:"column:created_at;autoCreateTime"`
	UpdatedAt     time.Time  `gorm:"column:updated_at;autoUpdateTime"`
	DeletedAt     *time.Time `gorm:"column:deleted_at;index"`

	// Relationships
	Host VCenterHost `gorm:"foreignKey:HostID;references:ID"`
}

func (VCenterHostIP) TableName() string {
	return "vcenter_host_ips"
}

// Host NICs - for storing physical network interface details
type VCenterHostNIC struct {
	ID            string     `gorm:"column:id;size:50;primaryKey"`
	HostID        string     `gorm:"column:host_id;size:50;not null;index"`
	Device        string     `gorm:"column:device;size:100;not null"`
	Driver        string     `gorm:"column:driver;size:100"`
	LinkSpeed     *int32     `gorm:"column:link_speed"` // Mbps
	Duplex        string     `gorm:"column:duplex;size:20"`
	MacAddress    string     `gorm:"column:mac_address;size:17"`
	PCI           string     `gorm:"column:pci;size:50"`
	WakeOnLAN     *bool      `gorm:"column:wake_on_lan"`
	CreatedAt     time.Time  `gorm:"column:created_at;autoCreateTime"`
	UpdatedAt     time.Time  `gorm:"column:updated_at;autoUpdateTime"`
	DeletedAt     *time.Time `gorm:"column:deleted_at;index"`

	// Relationships
	Host VCenterHost `gorm:"foreignKey:HostID;references:ID"`
}

func (VCenterHostNIC) TableName() string {
	return "vcenter_host_nics"
}

// Virtual Switches - for storing virtual switch information
type VCenterVirtualSwitch struct {
	ID               string     `gorm:"column:id;size:50;primaryKey"`
	HostID           string     `gorm:"column:host_id;size:50;not null;index"`
	VsphereID        string     `gorm:"column:vsphere_id;size:100;not null;index"`
	Name             string     `gorm:"column:name;size:255;not null"`
	SwitchType       string     `gorm:"column:switch_type;size:50"` // standard, distributed
	NumPorts         *int32     `gorm:"column:num_ports"`
	UsedPorts        *int32     `gorm:"column:used_ports"`
	MTU              *int32     `gorm:"column:mtu"`
	CreatedAt        time.Time  `gorm:"column:created_at;autoCreateTime"`
	UpdatedAt        time.Time  `gorm:"column:updated_at;autoUpdateTime"`
	LastSyncedAt     time.Time  `gorm:"column:last_synced_at;type:datetime;default:CURRENT_TIMESTAMP"`
	DeletedAt        *time.Time `gorm:"column:deleted_at;index"`

	// Relationships
	Host VCenterHost `gorm:"foreignKey:HostID;references:ID"`
}

func (VCenterVirtualSwitch) TableName() string {
	return "vcenter_virtual_switches"
}

// VM-Datastore relationships
type VMDatastoreRelation struct {
	ID           string     `gorm:"column:id;size:50;primaryKey"`
	VMID         string     `gorm:"column:vm_id;size:50;not null;index"`
	DatastoreID  string     `gorm:"column:datastore_id;size:50;not null;index"`
	UsedSpaceGB  *int64     `gorm:"column:used_space_gb"`
	CommittedGB  *int64     `gorm:"column:committed_gb"`
	UncommittedGB *int64    `gorm:"column:uncommitted_gb"`
	CreatedAt    time.Time  `gorm:"column:created_at;autoCreateTime"`
	UpdatedAt    time.Time  `gorm:"column:updated_at;autoUpdateTime"`
	DeletedAt    *time.Time `gorm:"column:deleted_at;index"`

	// Relationships
	Datastore VCenterDatastore  `gorm:"foreignKey:DatastoreID;references:ID"`
}

func (VMDatastoreRelation) TableName() string {
	return "vm_datastore_relations"
}

// VM-Network relationships  
type VMNetworkRelation struct {
	ID           string     `gorm:"column:id;size:50;primaryKey"`
	VMID         string     `gorm:"column:vm_id;size:50;not null;index"`
	NetworkID    string     `gorm:"column:network_id;size:50;not null;index"`
	MacAddress   string     `gorm:"column:mac_address;size:17"`
	IPAddresses  string     `gorm:"column:ip_addresses;type:text"` // JSON array of IPs
	Connected    *bool      `gorm:"column:connected"`
	StartConnected *bool    `gorm:"column:start_connected"`
	CreatedAt    time.Time  `gorm:"column:created_at;autoCreateTime"`
	UpdatedAt    time.Time  `gorm:"column:updated_at;autoUpdateTime"`
	DeletedAt    *time.Time `gorm:"column:deleted_at;index"`

	// Relationships  
	Network VCenterNetwork `gorm:"foreignKey:NetworkID;references:ID"`
}

func (VMNetworkRelation) TableName() string {
	return "vm_network_relations"
}

// Host-Datastore relationships
type HostDatastoreRelation struct {
	ID          string     `gorm:"column:id;size:50;primaryKey"`
	HostID      string     `gorm:"column:host_id;size:50;not null;index"`
	DatastoreID string     `gorm:"column:datastore_id;size:50;not null;index"`
	Accessible  *bool      `gorm:"column:accessible"`
	Mounted     *bool      `gorm:"column:mounted"`
	CreatedAt   time.Time  `gorm:"column:created_at;autoCreateTime"`
	UpdatedAt   time.Time  `gorm:"column:updated_at;autoUpdateTime"`
	DeletedAt   *time.Time `gorm:"column:deleted_at;index"`

	// Relationships
	Host      VCenterHost      `gorm:"foreignKey:HostID;references:ID"`
	Datastore VCenterDatastore `gorm:"foreignKey:DatastoreID;references:ID"`
}

func (HostDatastoreRelation) TableName() string {
	return "host_datastore_relations"
}

// Add unique constraints
type UniqueConstraints struct{}

func (u UniqueConstraints) ApplyConstraints(db *gorm.DB) error {
	// Add unique constraint for asset name and hostname combination
	if err := db.Exec("ALTER TABLE assets ADD CONSTRAINT assets_name_hostname_unique UNIQUE (name, hostname)").Error; err != nil {
		if !strings.Contains(err.Error(), "Duplicate key name") {
			return err
		}
	}

	// Add unique constraint for interface and IP combination (using new table name)
	if err := db.Exec("ALTER TABLE ips ADD CONSTRAINT ips_interface_id_ip_address_unique UNIQUE (interface_id, ip_address)").Error; err != nil {
		if !strings.Contains(err.Error(), "Duplicate key name") {
			return err
		}
	}

	// Add unique constraint for zone, interface, and VLAN combination (matching new schema)
	if err := db.Exec("ALTER TABLE zone_details ADD CONSTRAINT zone_details_zone_id_firewall_interface_id_vlan_table_id_unique UNIQUE (zone_id, firewall_interface_id, vlan_table_id)").Error; err != nil {
		if !strings.Contains(err.Error(), "Duplicate key name") {
			return err
		}
	}

	return nil
}
