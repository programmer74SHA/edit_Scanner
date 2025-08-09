package types

import (
	"time"
)

// ScanJobStatus represents the status of a scan job
type ScanJobStatus string

const (
	ScanJobStatusPending  ScanJobStatus = "Pending"
	ScanJobStatusRunning  ScanJobStatus = "Running"
	ScanJobStatusComplete ScanJobStatus = "Completed"
	ScanJobStatusFailed   ScanJobStatus = "Failed"
	ScanJobStatusError    ScanJobStatus = "Error"
)

// ScheduleFrequencyUnit represents the unit of time for schedule frequency
type ScheduleFrequencyUnit string

const (
	ScheduleFrequencyUnitMinute ScheduleFrequencyUnit = "minute"
	ScheduleFrequencyUnitHour   ScheduleFrequencyUnit = "hour"
	ScheduleFrequencyUnitDay    ScheduleFrequencyUnit = "day"
	ScheduleFrequencyUnitWeek   ScheduleFrequencyUnit = "week"
	ScheduleFrequencyUnitMonth  ScheduleFrequencyUnit = "month"
)

// ScanJobWithSchedule combines a scan job with its schedule information
type ScanJobWithSchedule struct {
	ScanJob  ScanJob
	Schedule Schedule
	Scanner  Scanner
}

// ScheduledScan represents a scanner with its schedule information
type ScheduledScan struct {
	Scanner     Scanner
	Schedule    Schedule
	NextRunTime time.Time
}

// ScheduleType enum for different types of schedules
type ScheduleType string

const (
	ScheduleTypePeriodic    ScheduleType = "PERIODIC"    // Regular scheduled scans
	ScheduleTypeRunOnce     ScheduleType = "RUN_ONCE"    // Run once at specified time
	ScheduleTypeImmediately ScheduleType = "IMMEDIATELY" // Run immediately (next_run_time = now)
)

type Schedule struct {
	ID             int64        `gorm:"column:id;primaryKey;autoIncrement"`
	ScannerID      int64        `gorm:"column:scanner_id;not null"`
	ScheduleType   ScheduleType `gorm:"column:schedule_type;type:enum('PERIODIC','RUN_ONCE','IMMEDIATELY');not null;default:'PERIODIC'"`
	FrequencyValue int64        `gorm:"column:frequency_value;default:1"`
	FrequencyUnit  string       `gorm:"column:frequency_unit;size:50"`
	RunTime        *time.Time   `gorm:"column:run_time;type:datetime"`
	Month          int64        `gorm:"column:month"`
	Week           int64        `gorm:"column:week"`
	Day            int64        `gorm:"column:day"`
	Hour           int64        `gorm:"column:hour"`
	Minute         int64        `gorm:"column:minute"`
	NextRunTime    *time.Time   `gorm:"column:next_run_time;type:datetime"`
	CreatedAt      time.Time    `gorm:"column:created_at;type:datetime;default:CURRENT_TIMESTAMP"`
	UpdatedAt      *time.Time   `gorm:"column:updated_at;type:datetime"`

	Scanner Scanner `gorm:"foreignKey:ScannerID"`
}
