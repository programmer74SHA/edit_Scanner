package types

import (
	"time"
)

// SwitchMetadata represents the main switch configuration table
type SwitchMetadata struct {
	ID        string    `gorm:"column:id;size:36;primaryKey"`
	ScannerID int64     `gorm:"column:scanner_id;not null;index:idx_scanner_asset"`
	AssetID   string    `gorm:"column:asset_id;size:50;not null;uniqueIndex:unique_asset"`
	Username  string    `gorm:"column:username;size:255;not null"`
	Password  string    `gorm:"column:password;size:255;not null"`
	Port      int       `gorm:"column:port;not null;default:22"`
	Brand     string    `gorm:"column:brand;size:100;default:'Cisco'"`
	CreatedAt time.Time `gorm:"column:created_at;type:timestamp;default:CURRENT_TIMESTAMP"`
	UpdatedAt time.Time `gorm:"column:updated_at;type:timestamp;default:CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP"`

	// Relationships (only keep essential ones)
	Scanner Scanner `gorm:"foreignKey:ScannerID;constraint:OnDelete:CASCADE"`
	Asset   Assets  `gorm:"foreignKey:AssetID;constraint:OnDelete:CASCADE"`
}

func (SwitchMetadata) TableName() string {
	return "switch_metadata"
}

// SwitchNeighbor represents CDP/LLDP neighbor information
type SwitchNeighbor struct {
	ID           string    `gorm:"column:id;size:36;primaryKey"`
	SwitchID     string    `gorm:"column:switch_id;size:50;not null;index"`
	DeviceID     string    `gorm:"column:device_id;size:200;not null"`
	LocalPort    string    `gorm:"column:local_port;size:100;not null"`
	RemotePort   *string   `gorm:"column:remote_port;size:100"`
	Platform     *string   `gorm:"column:platform;size:200"`
	IPAddress    *string   `gorm:"column:ip_address;size:45"`
	Capabilities *string   `gorm:"column:capabilities;size:200"`
	Software     *string   `gorm:"column:software;size:500"`
	Duplex       *string   `gorm:"column:duplex;size:20"`
	Protocol     string    `gorm:"column:protocol;size:20;not null"` // CDP/LLDP
	CreatedAt    time.Time `gorm:"column:created_at;type:timestamp;default:CURRENT_TIMESTAMP"`
	UpdatedAt    time.Time `gorm:"column:updated_at;type:timestamp;default:CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP"`

	// Relationships
	SwitchMetadata SwitchMetadata `gorm:"foreignKey:SwitchID;references:AssetID"`
}

func (SwitchNeighbor) TableName() string {
	return "switch_neighbors"
}
