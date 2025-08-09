package mapper

import (
	"time"

	scannerDomain "gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanner/domain"
	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/scheduler/domain"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/adapter/storage/types"
)

// ScanJobDomain2Storage converts a domain ScanJob to a storage ScanJob
func ScanJobDomain2Storage(job domain.ScanJob) *types.ScanJob {
	var endTime *time.Time
	var progress *int

	if job.EndTime != nil {
		endTime = job.EndTime
	}

	progress = &job.Progress

	return &types.ScanJob{
		ID:        job.ID,
		ScannerID: job.ScannerID,
		Name:      job.Name,
		Status:    string(job.Status),
		StartTime: job.StartTime,
		EndTime:   endTime,
		Progress:  progress,
	}
}

// ScheduledScanStorage2Domain converts storage types to a domain ScheduledScan with schedule type support
func ScheduledScanStorage2Domain(scanner types.Scanner, schedule types.Schedule, nextRunTime time.Time) *domain.ScheduledScan {
	// Convert scanner to domain model
	scannerDomainModel := &scannerDomain.ScannerDomain{
		ID:        scanner.ID,
		Name:      scanner.Name,
		ScanType:  scanner.ScanType,
		Status:    scanner.Status,
		CreatedAt: scanner.CreatedAt,
	}

	// Set optional fields
	if scanner.UserID != nil {
		scannerDomainModel.UserID = *scanner.UserID
	}

	if scanner.UpdatedAt != nil {
		scannerDomainModel.UpdatedAt = *scanner.UpdatedAt
	}

	if scanner.DeletedAt != nil {
		scannerDomainModel.DeletedAt = *scanner.DeletedAt
	}

	// Convert schedule type from storage to domain
	scheduleType := scannerDomain.ScheduleTypePeriodic // default
	if schedule.ScheduleType != "" {
		scheduleType = scannerDomain.ScheduleType(schedule.ScheduleType)
	}

	// Handle nullable RunTime from storage
	var runTime time.Time
	if schedule.RunTime != nil {
		runTime = *schedule.RunTime
	} else {
		runTime = time.Time{} // Zero time if NULL
	}

	return &domain.ScheduledScan{
		Scanner: *scannerDomainModel,
		Schedule: scannerDomain.Schedule{
			ID:             schedule.ID,
			ScannerID:      schedule.ScannerID,
			ScheduleType:   scheduleType,
			FrequencyValue: schedule.FrequencyValue,
			FrequencyUnit:  schedule.FrequencyUnit,
			RunTime:        runTime,
			Month:          schedule.Month,
			Week:           schedule.Week,
			Day:            schedule.Day,
			Hour:           schedule.Hour,
			Minute:         schedule.Minute,
		},
		NextRunTime: nextRunTime,
	}
}

// ScheduleDomain2Storage converts a domain Schedule to a storage Schedule
func ScheduleDomain2Storage(schedule scannerDomain.Schedule) *types.Schedule {
	storageSchedule := &types.Schedule{
		ID:             schedule.ID,
		ScannerID:      schedule.ScannerID,
		ScheduleType:   types.ScheduleType(schedule.ScheduleType),
		FrequencyValue: schedule.FrequencyValue,
		FrequencyUnit:  schedule.FrequencyUnit,
		Month:          schedule.Month,
		Week:           schedule.Week,
		Day:            schedule.Day,
		Hour:           schedule.Hour,
		Minute:         schedule.Minute,
		CreatedAt:      schedule.CreatedAt,
	}

	// Handle RunTime - only set if not zero (convert from time.Time to *time.Time)
	if !schedule.RunTime.IsZero() {
		storageSchedule.RunTime = &schedule.RunTime
	} else {
		storageSchedule.RunTime = nil
	}

	if schedule.UpdatedAt != nil {
		storageSchedule.UpdatedAt = schedule.UpdatedAt
	}

	return storageSchedule
}

// ScheduleStorage2Domain converts a storage Schedule to a domain Schedule
func ScheduleStorage2Domain(schedule types.Schedule) *scannerDomain.Schedule {
	// Convert schedule type from storage to domain
	scheduleType := scannerDomain.ScheduleTypePeriodic // default
	if schedule.ScheduleType != "" {
		scheduleType = scannerDomain.ScheduleType(schedule.ScheduleType)
	}

	domainSchedule := &scannerDomain.Schedule{
		ID:             schedule.ID,
		ScannerID:      schedule.ScannerID,
		ScheduleType:   scheduleType,
		FrequencyValue: schedule.FrequencyValue,
		FrequencyUnit:  schedule.FrequencyUnit,
		Month:          schedule.Month,
		Week:           schedule.Week,
		Day:            schedule.Day,
		Hour:           schedule.Hour,
		Minute:         schedule.Minute,
		CreatedAt:      schedule.CreatedAt,
	}

	// Handle nullable RunTime (convert from *time.Time to time.Time)
	if schedule.RunTime != nil {
		domainSchedule.RunTime = *schedule.RunTime
	} else {
		domainSchedule.RunTime = time.Time{} // Zero time if NULL
	}

	if schedule.UpdatedAt != nil {
		domainSchedule.UpdatedAt = schedule.UpdatedAt
	}

	return domainSchedule
}
