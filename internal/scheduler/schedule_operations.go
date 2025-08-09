package scheduler

import (
	"log"
	"time"

	scannerDomain "gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanner/domain"
)

// CalculateNextRunTime determines when the next scan should run based on the schedule configuration and type
func CalculateNextRunTime(schedule scannerDomain.Schedule, from time.Time) time.Time {
	log.Printf("Calculating next run time from %v with schedule type %s, frequency %d %s",
		from, schedule.ScheduleType, schedule.FrequencyValue, schedule.FrequencyUnit)

	// Handle different schedule types
	switch schedule.ScheduleType {
	case scannerDomain.ScheduleTypeImmediately:
		// For immediate scans, return current time
		nextRun := from
		log.Printf("Immediate schedule: returning %v", nextRun)
		return nextRun

	case scannerDomain.ScheduleTypeRunOnce:
		// For run-once schedules, calculate the specific time based on provided values
		nextRun := calculateRunOnceTime(schedule, from)
		log.Printf("Run-once schedule: calculated time %v", nextRun)
		return nextRun

	case scannerDomain.ScheduleTypePeriodic:
		// For periodic schedules, use the existing logic
		nextRun := calculatePeriodicTime(schedule, from)
		log.Printf("Periodic schedule: calculated time %v", nextRun)
		return nextRun

	default:
		// Default to periodic behavior for backwards compatibility
		log.Printf("Unknown schedule type %s, defaulting to periodic", schedule.ScheduleType)
		return calculatePeriodicTime(schedule, from)
	}
}

// calculateRunOnceTime calculates the next run time for run-once schedules
func calculateRunOnceTime(schedule scannerDomain.Schedule, from time.Time) time.Time {
	// For RUN_ONCE schedules, directly use the RunTime field if provided
	if !schedule.RunTime.IsZero() {
		log.Printf("Run-once schedule: using provided RunTime %v without modification", schedule.RunTime)
		// Return the time exactly as provided - no timezone conversion
		return schedule.RunTime
	}

	// If no RunTime is provided, use the current time as fallback
	log.Printf("Run-once schedule: no RunTime provided, using current time")
	return from
}

// calculatePeriodicTime calculates the next run time for periodic schedules (existing logic)
func calculatePeriodicTime(schedule scannerDomain.Schedule, from time.Time) time.Time {
	// For minute frequencies, simply add the duration
	if schedule.FrequencyUnit == "minute" {
		nextRun := from.Add(time.Duration(schedule.FrequencyValue) * time.Minute)
		log.Printf("Added %d minutes to %v, result: %v", schedule.FrequencyValue, from, nextRun)
		return nextRun
	}

	// For hour frequencies with a specific minute set
	if schedule.FrequencyUnit == "hour" && schedule.Minute >= 0 && schedule.Minute < 60 {
		// Calculate the next occurrence at the specified minute
		nextRun := time.Date(
			from.Year(),
			from.Month(),
			from.Day(),
			from.Hour(),
			int(schedule.Minute),
			0, 0,
			from.Location(),
		)

		// If we've already passed this minute in the current hour, move to the next hour
		if !nextRun.After(from) {
			nextRun = nextRun.Add(time.Duration(schedule.FrequencyValue) * time.Hour)
		}

		log.Printf("Calculated hourly run at minute %d: %v", schedule.Minute, nextRun)
		return nextRun
	}

	// For hour frequencies without a specific minute
	if schedule.FrequencyUnit == "hour" {
		nextRun := from.Add(time.Duration(schedule.FrequencyValue) * time.Hour)
		log.Printf("Added %d hours to %v, result: %v", schedule.FrequencyValue, from, nextRun)
		return nextRun
	}

	var nextRun time.Time

	// Special handling for weekly schedules with specific day of week
	if schedule.FrequencyUnit == "week" && schedule.Day > 0 && schedule.Day <= 7 &&
		schedule.Hour >= 0 && schedule.Hour < 24 && schedule.Minute >= 0 && schedule.Minute < 60 {

		// Convert user day numbering (1=Saturday, 2=Sunday, 3=Monday, ..., 7=Friday)
		targetWeekday := time.Weekday((schedule.Day + 5) % 7)

		// Calculate days until target weekday
		currentWeekday := from.Weekday()
		daysUntilTarget := (int(targetWeekday) - int(currentWeekday) + 7) % 7

		// If daysUntilTarget is 0, it means today is the target day
		// We need to check if the target time has already passed today
		if daysUntilTarget == 0 {
			// Create today's target time to compare
			todayTarget := time.Date(
				from.Year(),
				from.Month(),
				from.Day(),
				int(schedule.Hour),
				int(schedule.Minute),
				0, 0,
				from.Location(),
			)
			// If target time has passed today, schedule for next week
			if !todayTarget.After(from) {
				daysUntilTarget = 7 * int(schedule.FrequencyValue)
			}
		}

		// Create target time on the target day
		targetDate := from.AddDate(0, 0, daysUntilTarget)
		nextRun = time.Date(
			targetDate.Year(),
			targetDate.Month(),
			targetDate.Day(),
			int(schedule.Hour),
			int(schedule.Minute),
			0, 0,
			from.Location(),
		)

		log.Printf("Calculated weekly run for day %d (%v) at %02d:%02d: %v",
			schedule.Day, targetWeekday, schedule.Hour, schedule.Minute, nextRun)
		return nextRun
	}

	// For day/week/month frequencies with specific hour and minute (non-weekly day-specific)
	if schedule.Hour >= 0 && schedule.Hour < 24 && schedule.Minute >= 0 && schedule.Minute < 60 {
		nextRun = time.Date(
			from.Year(),
			from.Month(),
			from.Day(),
			int(schedule.Hour),
			int(schedule.Minute),
			0, 0,
			from.Location(),
		)

		// If this time has already passed today, move to the next occurrence
		if !nextRun.After(from) {
			switch schedule.FrequencyUnit {
			case "day":
				nextRun = nextRun.AddDate(0, 0, int(schedule.FrequencyValue))
			case "week":
				nextRun = nextRun.AddDate(0, 0, int(schedule.FrequencyValue)*7)
			case "month":
				nextRun = nextRun.AddDate(0, int(schedule.FrequencyValue), 0)
			}
		}
	} else {
		// Handle frequency-based schedules without specific times
		switch schedule.FrequencyUnit {
		case "day":
			nextRun = from.AddDate(0, 0, int(schedule.FrequencyValue))
		case "week":
			nextRun = from.AddDate(0, 0, int(schedule.FrequencyValue)*7)
		case "month":
			nextRun = from.AddDate(0, int(schedule.FrequencyValue), 0)
		default:
			log.Printf("Warning: Unrecognized frequency unit '%s', defaulting to 24h interval", schedule.FrequencyUnit)
			nextRun = from.Add(24 * time.Hour)
		}
	}

	log.Printf("Calculated next run time: %v", nextRun)
	return nextRun
}
