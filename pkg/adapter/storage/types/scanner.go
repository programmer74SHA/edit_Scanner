package types

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"time"
)

// NmapProfile represents an Nmap scan profile with predefined arguments
type NmapProfile struct {
	ID          int64         `gorm:"column:id;primaryKey;autoIncrement"`
	Name        string        `gorm:"column:name;size:100;not null;uniqueIndex"`
	Description *string       `gorm:"column:description;size:500"`
	Arguments   NmapArguments `gorm:"column:arguments;type:json;not null"`
	IsDefault   bool          `gorm:"column:is_default;default:false"`
	IsSystem    bool          `gorm:"column:is_system;default:false"`
	CreatedBy   *string       `gorm:"column:created_by;size:100"`
	CreatedAt   time.Time     `gorm:"column:created_at;type:datetime;default:CURRENT_TIMESTAMP"`
	UpdatedAt   *time.Time    `gorm:"column:updated_at;type:datetime"`
}

func (NmapProfile) TableName() string {
	return "nmap_profiles"
}

// NmapArguments represents the command line arguments for nmap
type NmapArguments []string

// Value implements the driver.Valuer interface for database storage
func (args NmapArguments) Value() (driver.Value, error) {
	if len(args) == 0 {
		return "[]", nil
	}
	return json.Marshal(args)
}

// Scan implements the sql.Scanner interface for database retrieval
func (args *NmapArguments) Scan(value interface{}) error {
	if value == nil {
		*args = NmapArguments{}
		return nil
	}

	var bytes []byte
	switch v := value.(type) {
	case []byte:
		bytes = v
	case string:
		bytes = []byte(v)
	default:
		return fmt.Errorf("cannot scan %T into NmapArguments", value)
	}

	return json.Unmarshal(bytes, args)
}

// Scanner represents a scanner in the database
type Scanner struct {
	ID        int64      `gorm:"column:id;primaryKey;autoIncrement"`
	ScanType  string     `gorm:"column:scan_type"`
	Name      string     `gorm:"column:name;size:255;not null"`
	Status    bool       `gorm:"column:status;default:1"`
	CreatedAt time.Time  `gorm:"column:created_at;type:datetime;default:CURRENT_TIMESTAMP"`
	UpdatedAt *time.Time `gorm:"column:updated_at;type:datetime"`
	UserID    *string    `gorm:"column:user_id;size:100"`
	DeletedAt *time.Time `gorm:"column:deleted_at;type:datetime"`

	NmapMetadatas     []NmapMetadata          `gorm:"foreignKey:ScannerID"`
	DomainMetadatas   []DomainMetadata        `gorm:"foreignKey:ScannerID"`
	VCenterMetadatas  []VcenterMetadata       `gorm:"foreignKey:ScannerID"`
	FirewallMetadatas []FirewallMetadata      `gorm:"foreignKey:ScannerID"`
	NessusMetadatas   []NessusMetadata        `gorm:"foreignKey:ScannerID"`
	SwitchMetadatas   []SwitchScannerMetadata `gorm:"foreignKey:ScannerID"`
	Schedules         []Schedule              `gorm:"foreignKey:ScannerID"`
	ScanJob           ScanJob                 `gorm:"foreignKey:ScannerID"`
}

func (Scanner) TableName() string {
	return "scanners"
}

// ScannerFilter struct for filtering scanners
type ScannerFilter struct {
	Name     string `json:"name"`
	ScanType string `json:"type"`
	Status   *bool  `json:"status"`
}

type NmapMetadata struct {
	ID             int64   `gorm:"column:id;primaryKey;autoIncrement"`
	ScannerID      int64   `gorm:"column:scanner_id;not null;uniqueIndex:nmap_metadatas_unique"`
	ProfileID      *int64  `gorm:"column:profile_id"`
	Target         string  `gorm:"column:target;type:enum('IP','Network','Range');not null"`
	CustomSwitches *string `gorm:"column:custom_switches;type:text"`

	Scanner     Scanner          `gorm:"foreignKey:ScannerID"`
	Profile     *NmapProfile     `gorm:"foreignKey:ProfileID"`
	IPScan      *NmapIPScan      `gorm:"foreignKey:NmapMetadatasID"`
	NetworkScan *NmapNetworkScan `gorm:"foreignKey:NmapMetadatasID"`
	RangeScan   *NmapRangeScan   `gorm:"foreignKey:NmapMetadatasID"`
}

type NmapIPScan struct {
	ID              int64  `gorm:"column:id;primaryKey;autoIncrement"`
	NmapMetadatasID int64  `gorm:"column:nmap_metadatas_id;not null;uniqueIndex:nmap_ip_scan_unique"`
	IP              string `gorm:"column:ip;size:50;not null"`

	NmapMetadata NmapMetadata `gorm:"foreignKey:NmapMetadatasID"`
}

type NmapNetworkScan struct {
	ID              int64  `gorm:"column:id;primaryKey;autoIncrement"`
	NmapMetadatasID int64  `gorm:"column:nmap_metadatas_id;not null;uniqueIndex:nmap_network_scan_unique"`
	IP              string `gorm:"column:ip;size:50;not null"`
	Subnet          int64  `gorm:"column:subnet;not null"`

	NmapMetadata NmapMetadata `gorm:"foreignKey:NmapMetadatasID"`
}

type NmapRangeScan struct {
	ID              int64  `gorm:"column:id;primaryKey;autoIncrement"`
	NmapMetadatasID int64  `gorm:"column:nmap_metadatas_id;not null;uniqueIndex:nmap_range_scan_unique"`
	StartIP         string `gorm:"column:start_ip;size:50;not null"`
	EndIP           string `gorm:"column:end_ip;size:50;not null"`

	NmapMetadata NmapMetadata `gorm:"foreignKey:NmapMetadatasID"`
}

type DomainMetadata struct {
	ID                 int64  `gorm:"column:id;primaryKey"`
	ScannerID          int64  `gorm:"column:scanner_id;not null"`
	IP                 string `gorm:"column:ip;size:50;not null"`
	Port               string `gorm:"column:port;size:50;not null"`
	Domain             string `gorm:"column:domain;size:50;not null"`
	Username           string `gorm:"column:username;size:50;not null"`
	Password           string `gorm:"column:password;size:200;not null"`
	AuthenticationType string `gorm:"column:authentication_type;size:50;not null"`
	Protocol           string `gorm:"column:protocol;size:50;not null"`

	Scanner Scanner `gorm:"foreignKey:ScannerID"`
}

type VcenterMetadata struct {
	ID        int64  `gorm:"column:id;primaryKey"`
	ScannerID int64  `gorm:"column:scanner_id;not null"`
	IP        string `gorm:"column:ip;size:50;not null"`
	Port      string `gorm:"column:port;size:50;not null"`
	Username  string `gorm:"column:username;size:50;not null"`
	Password  string `gorm:"column:password;size:200;not null"`
}

type NessusMetadata struct {
	ID        int64  `gorm:"column:id;primaryKey;autoIncrement"`
	ScannerID int64  `gorm:"column:scanner_id;not null;uniqueIndex:nessus_metadata_unique"`
	URL       string `gorm:"column:url;size:255;not null"`
	Username  string `gorm:"column:username;size:100"`
	Password  string `gorm:"column:password;size:200"`
	APIKey    string `gorm:"column:api_key;size:500"`

	Scanner Scanner `gorm:"foreignKey:ScannerID"`
}

type FirewallMetadata struct {
	ID        int64  `gorm:"column:id;primaryKey;autoIncrement"`
	ScannerID int64  `gorm:"column:scanner_id;not null"`
	IP        string `gorm:"column:ip;size:50;not null"`
	Port      string `gorm:"column:port;size:50;not null"`
	Type      string `gorm:"column:type;size:50;not null"`
	ApiKey    string `gorm:"column:api_key;size:200;not null"`
}

// SwitchScannerMetadata represents scanner metadata for switch scanners
type SwitchScannerMetadata struct {
	ID         int64   `gorm:"column:id;primaryKey;autoIncrement"`
	ScannerID  int64   `gorm:"column:scanner_id;not null;uniqueIndex:switch_scanner_metadata_unique"`
	AssetID    string  `gorm:"column:asset_id;size:36;not null"` // Links to the created asset
	IP         string  `gorm:"column:ip;size:50;not null"`
	Port       string  `gorm:"column:port;size:50;not null"`
	Username   string  `gorm:"column:username;size:50;not null"`
	Password   string  `gorm:"column:password;size:200;not null"`
	Protocol   string  `gorm:"column:protocol;size:20;not null"` // SSH, Telnet
	SSHKeyPath *string `gorm:"column:ssh_key_path;size:500"`
	DeviceType string  `gorm:"column:device_type;size:50;default:'switch'"`

	// Scanning options
	CollectInterfaces bool `gorm:"column:collect_interfaces;default:true"`
	CollectVLANs      bool `gorm:"column:collect_vlans;default:true"`
	CollectRoutes     bool `gorm:"column:collect_routes;default:true"`
	CollectNeighbors  bool `gorm:"column:collect_neighbors;default:true"`

	// Connection settings
	ConnectionTimeout int `gorm:"column:connection_timeout;default:30"`
	CommandTimeout    int `gorm:"column:command_timeout;default:10"`
	MaxRetries        int `gorm:"column:max_retries;default:3"`

	// Relationships
	Scanner Scanner `gorm:"foreignKey:ScannerID"`
	Asset   Assets  `gorm:"foreignKey:AssetID;constraint:OnDelete:CASCADE"`
}

func (SwitchScannerMetadata) TableName() string {
	return "switch_scanner_metadata"
}
