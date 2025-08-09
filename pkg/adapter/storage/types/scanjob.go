package types

import (
	"time"

	"gorm.io/gorm"
)

type AssetScanJob struct {
	ID           int64     `gorm:"column:id;primaryKey;autoIncrement"`
	AssetID      string    `gorm:"column:asset_id;not null;uniqueIndex:asset_job_unique"`
	ScanJobID    int64     `gorm:"column:scan_job_id;not null;uniqueIndex:asset_job_unique"`
	DiscoveredAt time.Time `gorm:"column:discovered_at;type:datetime;default:CURRENT_TIMESTAMP"`

	Asset   Assets  `gorm:"foreignKey:AssetID"`
	ScanJob ScanJob `gorm:"foreignKey:ScanJobID"`
}

type ScanJob struct {
	ID          int64      `gorm:"column:id;primaryKey;autoIncrement"`
	Name        string     `gorm:"column:name;size:50;not null"`
	Status      string     `gorm:"column:status;type:enum('Pending','Running','Completed','Failed','Error','Cancelled');not null;default:Pending"` // Added 'Cancelled' to the enum
	EndDatetime *time.Time `gorm:"column:end_datetime;type:datetime"`
	StartTime   time.Time  `gorm:"column:start_time;type:datetime;default:CURRENT_TIMESTAMP"`
	EndTime     *time.Time `gorm:"column:end_time;type:datetime"`
	Progress    *int       `gorm:"column:progress"`
	ScannerID   int64      `gorm:"column:scanner_id;not null"`

	AssetScanJobs []AssetScanJob `gorm:"foreignKey:ScanJobID"`
	gorm.Model
}
