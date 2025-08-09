package domain

import (
	"errors"
	"log"
	"time"

	scannerDomain "gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanner/domain"
)

// Error definitions
var (
	ErrScanJobNotFound   = errors.New("scan job not found")
	ErrScanJobNotRunning = errors.New("scan job is not running")
)

// ScheduleStatus represents the current status of a scheduled job
type ScheduleStatus string

const (
	ScheduleStatusPending   ScheduleStatus = "Pending"
	ScheduleStatusRunning   ScheduleStatus = "Running"
	ScheduleStatusComplete  ScheduleStatus = "Completed"
	ScheduleStatusFailed    ScheduleStatus = "Failed"
	ScheduleStatusError     ScheduleStatus = "Error"
	ScheduleStatusCancelled ScheduleStatus = "Cancelled"
)

// ScheduledScan combines the scanner and its schedule information
type ScheduledScan struct {
	Scanner     scannerDomain.ScannerDomain
	Schedule    scannerDomain.Schedule
	NextRunTime time.Time
}

// ScanJob represents a scan job that has been executed
type ScanJob struct {
	ID        int64
	ScannerID int64
	Name      string
	Type      string
	Status    ScheduleStatus
	StartTime time.Time
	EndTime   *time.Time
	Progress  int
	CreatedAt time.Time
	UpdatedAt time.Time
}

// CalculateNextRunTime determines when the next scan should run based on the schedule configuration
func CalculateNextRunTime(schedule scannerDomain.Schedule, from time.Time) time.Time {
	log.Printf("Calculating next run time from %v with frequency %d %s",
		from, schedule.FrequencyValue, schedule.FrequencyUnit)

	// For minute frequency, simply add the duration to the current time
	if schedule.FrequencyUnit == "minute" {
		nextRun := from.Add(time.Duration(schedule.FrequencyValue) * time.Minute)
		log.Printf("Added %d minutes to %v, result: %v", schedule.FrequencyValue, from, nextRun)
		return nextRun
	}

	// For hourly frequency with specific minute
	if schedule.FrequencyUnit == "hour" && schedule.Minute >= 0 {
		// Calculate the hour part normally
		currMinute := from.Minute()
		targetMinute := int(schedule.Minute)

		// Start with the current time
		nextRun := from

		if currMinute > targetMinute {
			// If we've already passed the target minute in the current hour,
			// we need to move to the next hour and set the target minute
			nextRun = nextRun.Add(time.Duration(schedule.FrequencyValue) * time.Hour)
		}

		// Set the correct minute within the hour
		nextRun = time.Date(
			nextRun.Year(),
			nextRun.Month(),
			nextRun.Day(),
			nextRun.Hour(),
			targetMinute,
			0, 0,
			nextRun.Location(),
		)

		log.Printf("Calculated hourly with specific minute: %v", nextRun)
		return nextRun
	}

	// Simple hourly frequency without specific minute requirement
	if schedule.FrequencyUnit == "hour" {
		nextRun := from.Add(time.Duration(schedule.FrequencyValue) * time.Hour)
		log.Printf("Added %d hours to %v, result: %v", schedule.FrequencyValue, from, nextRun)
		return nextRun
	}

	// If specific hour and minute are provided, use those for scheduling
	if schedule.Hour >= 0 && schedule.Minute >= 0 {
		// Set the specific hour and minute, but keep the current day
		nextRun := time.Date(
			from.Year(),
			from.Month(),
			from.Day(),
			int(schedule.Hour),
			int(schedule.Minute),
			0, 0,
			from.Location(),
		)

		// If this time is already in the past for today, add the appropriate frequency
		if nextRun.Before(from) {
			switch schedule.FrequencyUnit {
			case "day":
				nextRun = nextRun.AddDate(0, 0, int(schedule.FrequencyValue))
			case "week":
				nextRun = nextRun.AddDate(0, 0, int(schedule.FrequencyValue)*7)
			case "month":
				nextRun = nextRun.AddDate(0, int(schedule.FrequencyValue), 0)
			}
		}

		return nextRun
	} else {
		// Handle frequency-based schedules without specific times
		var nextRun time.Time
		switch schedule.FrequencyUnit {
		case "day":
			nextRun = from.AddDate(0, 0, int(schedule.FrequencyValue))
		case "week":
			nextRun = from.AddDate(0, 0, int(schedule.FrequencyValue)*7)
		case "month":
			nextRun = from.AddDate(0, int(schedule.FrequencyValue), 0)
		default:
			// This is a fallback in case the frequency unit is invalid or empty
			// We'll default to a 24-hour interval to prevent immediate rescheduling
			log.Printf("Warning: Unrecognized frequency unit '%s', defaulting to 24h interval", schedule.FrequencyUnit)
			nextRun = from.Add(24 * time.Hour)
		}

		log.Printf("Calculated next run time: %v", nextRun)
		return nextRun
	}
}
