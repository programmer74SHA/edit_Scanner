package storage

import (
	"context"
	"errors"
	"log"
	"time"

	scannerDomain "gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanner/domain"
	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/scheduler/domain"
	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/scheduler/port"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/adapter/storage/types"
	appCtx "gitlab.apk-group.net/siem/backend/asset-discovery/pkg/context"
	"gorm.io/gorm"
)

type schedulerRepo struct {
	db          *gorm.DB
	scannerRepo *scannerRepo // Add dependency on scannerRepo
}

// NewSchedulerRepo creates a new scheduler repository
func NewSchedulerRepo(db *gorm.DB) port.Repo {
	return &schedulerRepo{
		db:          db,
		scannerRepo: &scannerRepo{db: db}, // Initialize scannerRepo with the same DB
	}
}

// GetDueSchedules retrieves all scheduled scans that are due to run, handling different schedule types
func (r *schedulerRepo) GetDueSchedules(ctx context.Context) ([]domain.ScheduledScan, error) {
	log.Printf("Scheduler Repository: Getting due schedules")

	var scheduledScans []domain.ScheduledScan
	now := time.Now()

	// Query for different schedule types with different criteria:
	rows, err := r.db.WithContext(ctx).Raw(`
		SELECT 
			s.id, s.name, s.scan_type, s.status, s.created_at, s.updated_at, s.user_id, s.deleted_at,
			sch.id, sch.scanner_id, sch.schedule_type, sch.frequency_value, sch.frequency_unit, 
			sch.month, sch.week, sch.day, sch.hour, sch.minute, sch.next_run_time, sch.run_time
		FROM 
			scanners s
		INNER JOIN 
			schedules sch ON s.id = sch.scanner_id
		WHERE 
			s.status = true 
			AND s.deleted_at IS NULL
			AND sch.next_run_time IS NOT NULL
			AND (
				(sch.schedule_type = 'IMMEDIATELY')
				OR (sch.schedule_type = 'RUN_ONCE' AND sch.next_run_time <= ?)
				OR (sch.schedule_type = 'PERIODIC' AND sch.next_run_time <= ?)
				OR (sch.schedule_type IS NULL AND sch.next_run_time <= ?) -- backwards compatibility
			)
	`, now, now, now).Rows()

	if err != nil {
		log.Printf("Scheduler Repository: Error getting due schedules: %v", err)
		return nil, err
	}
	defer rows.Close()

	// Process the results
	for rows.Next() {
		var scanner types.Scanner
		var schedule types.Schedule
		var nextRunTime *time.Time
		var runTime *time.Time // Handle nullable run_time

		// Scan values into our structs
		err := rows.Scan(
			&scanner.ID, &scanner.Name, &scanner.ScanType, &scanner.Status,
			&scanner.CreatedAt, &scanner.UpdatedAt, &scanner.UserID, &scanner.DeletedAt,
			&schedule.ID, &schedule.ScannerID, &schedule.ScheduleType, &schedule.FrequencyValue, &schedule.FrequencyUnit,
			&schedule.Month, &schedule.Week, &schedule.Day, &schedule.Hour, &schedule.Minute,
			&nextRunTime, &runTime, // Updated to scan both nullable times
		)

		if err != nil {
			log.Printf("Scheduler Repository: Error scanning row: %v", err)
			continue
		}

		schedule.NextRunTime = nextRunTime
		schedule.RunTime = runTime // Set the nullable RunTime

		// Convert scanner to domain model
		scannerDomainModel := &scannerDomain.ScannerDomain{
			ID:        scanner.ID,
			Name:      scanner.Name,
			ScanType:  scanner.ScanType,
			Status:    scanner.Status,
			CreatedAt: scanner.CreatedAt,
		}

		if scanner.UserID != nil {
			scannerDomainModel.UserID = *scanner.UserID
		}

		if scanner.UpdatedAt != nil {
			scannerDomainModel.UpdatedAt = *scanner.UpdatedAt
		}

		// Load metadata based on scanner type
		switch scannerDomainModel.ScanType {
		case scannerDomain.ScannerTypeNmap:
			if err := r.scannerRepo.LoadNmapData(ctx, scannerDomainModel); err != nil {
				log.Printf("Error loading Nmap data for scanner %d: %v", scanner.ID, err)
				continue
			}
		case scannerDomain.ScannerTypeVCenter:
			if err := r.scannerRepo.LoadVcenterData(ctx, scannerDomainModel); err != nil {
				log.Printf("Error loading VCenter data for scanner %d: %v", scanner.ID, err)
				continue
			}
		case scannerDomain.ScannerTypeDomain:
			if err := r.scannerRepo.LoadDomainData(ctx, scannerDomainModel); err != nil {
				log.Printf("Error loading Domain data for scanner %d: %v", scanner.ID, err)
				continue
			}
		case scannerDomain.ScannerTypeNessus:
			if err := r.scannerRepo.LoadNessusData(ctx, scannerDomainModel); err != nil {
				log.Printf("Error loading Nessus data for scanner %d: %v", scanner.ID, err)
				continue
			}
		case scannerDomain.ScannerTypeFirewall:
			if err := r.scannerRepo.LoadFirewallData(ctx, scannerDomainModel); err != nil {
				log.Printf("Error loading Firewall data for scanner %d: %v", scanner.ID, err)
				continue
			}
		}

		// Convert schedule to domain model with schedule type
		scheduleType := scannerDomain.ScheduleTypePeriodic // default for backwards compatibility
		if schedule.ScheduleType != "" {
			scheduleType = scannerDomain.ScheduleType(schedule.ScheduleType)
		}

		// Handle nullable RunTime when converting to domain
		var domainRunTime time.Time
		if schedule.RunTime != nil {
			domainRunTime = *schedule.RunTime
		} else {
			domainRunTime = time.Time{} // Zero time if NULL
		}

		scheduleDomainModel := scannerDomain.Schedule{
			ID:             schedule.ID,
			ScannerID:      schedule.ScannerID,
			ScheduleType:   scheduleType,
			FrequencyValue: schedule.FrequencyValue,
			FrequencyUnit:  schedule.FrequencyUnit,
			RunTime:        domainRunTime, // Use the converted time
			Month:          schedule.Month,
			Week:           schedule.Week,
			Day:            schedule.Day,
			Hour:           schedule.Hour,
			Minute:         schedule.Minute,
		}

		// Set next run time from the database
		nextRun := now
		if schedule.NextRunTime != nil {
			nextRun = *schedule.NextRunTime
		}

		// Create scheduled scan entry
		scheduledScan := domain.ScheduledScan{
			Scanner:     *scannerDomainModel,
			Schedule:    scheduleDomainModel,
			NextRunTime: nextRun,
		}

		scheduledScans = append(scheduledScans, scheduledScan)
		log.Printf("Scheduler Repository: Found due schedule ID %d of type %s", schedule.ID, scheduleType)
	}

	log.Printf("Scheduler Repository: Found %d due schedules", len(scheduledScans))
	return scheduledScans, nil
}

// CreateScanJob creates a new scan job record
func (r *schedulerRepo) CreateScanJob(ctx context.Context, job domain.ScanJob) (int64, error) {
	log.Printf("Scheduler Repository: Creating scan job for scanner ID: %d", job.ScannerID)

	// Get the DB from context or use the repo's DB
	db := appCtx.GetDB(ctx)
	if db == nil {
		db = r.db
	}

	// Convert job status to database enum value
	status := string(job.Status)

	// Create scan job record
	scanJob := types.ScanJob{
		Name:      job.Name,
		Status:    status,
		StartTime: job.StartTime,
		Progress:  &job.Progress,
		ScannerID: job.ScannerID,
	}

	// Insert the record
	if err := db.Table("scan_jobs").Create(&scanJob).Error; err != nil {
		log.Printf("Scheduler Repository: Error creating scan job: %v", err)
		return 0, err
	}

	log.Printf("Scheduler Repository: Created scan job with ID: %d", scanJob.ID)
	return scanJob.ID, nil
}

// UpdateScanJob updates the status, progress, and optionally end time of a scan job.
func (r *schedulerRepo) UpdateScanJob(ctx context.Context, jobID int64, status domain.ScheduleStatus, progress int, setEndTime bool) error {
	log.Printf("Scheduler Repository: Updating scan job ID: %d to status: %s with progress: %d", jobID, status, progress)

	// Get the DB from context or use the repo's DB
	db := appCtx.GetDB(ctx)
	if db == nil {
		db = r.db
	}

	// Map domain status to database enum value
	var statusStr string
	switch status {
	case domain.ScheduleStatusComplete:
		statusStr = "Completed"
		progress = 100 // Completed jobs always have 100% progress
	case domain.ScheduleStatusFailed:
		statusStr = "Failed"
		progress = 0 // Failed jobs always have 0% progress
	case domain.ScheduleStatusPending:
		statusStr = "Pending"
	case domain.ScheduleStatusRunning:
		statusStr = "Running"
	case domain.ScheduleStatusCancelled:
		statusStr = "Cancelled"
		progress = 0 // Cancelled jobs have 0% progress
	default:
		statusStr = "Error"
		progress = 0 // Unknown statuses have 0% progress
	}

	// Build update map
	updates := map[string]interface{}{
		"status":   statusStr,
		"progress": progress,
	}
	if setEndTime {
		updates["end_time"] = time.Now()
	}

	// Update the record
	result := db.Table("scan_jobs").
		Where("id = ?", jobID).
		Updates(updates)

	if result.Error != nil {
		log.Printf("Scheduler Repository: Error updating scan job: %v", result.Error)
		return result.Error
	}

	if result.RowsAffected == 0 {
		log.Printf("Scheduler Repository: No rows affected when updating scan job ID: %d", jobID)
		return errors.New("scan job not found")
	}

	log.Printf("Scheduler Repository: Successfully updated scan job ID: %d", jobID)
	return nil
}

// UpdateScheduleNextRun updates the next run time for a schedule (supports setting to NULL)
func (r *schedulerRepo) UpdateScheduleNextRun(ctx context.Context, scheduleID int64, nextRunTimeStr *string) error {
	log.Printf("Scheduler Repository: Updating next run time for schedule ID: %d", scheduleID)

	// Get the DB from context or use the repo's DB
	db := appCtx.GetDB(ctx)
	if db == nil {
		db = r.db
	}

	var formattedTime interface{}
	var err error

	// Handle non-NULL next run time
	if nextRunTimeStr != nil {
		log.Printf("Scheduler Repository: Processing next run time: %s", *nextRunTimeStr)
		var nextRun time.Time
		nextRun, err = time.Parse(time.RFC3339, *nextRunTimeStr)
		if err != nil {
			log.Printf("Scheduler Repository: Error parsing next run time: %v", err)
			return err
		}
		// Format the time for database storage without timezone conversion
		formattedTime = nextRun.Format("2006-01-02 15:04:05")
		log.Printf("Scheduler Repository: Formatted time for database: %s", formattedTime)
	} else {
		log.Printf("Scheduler Repository: Setting next run time to NULL")
		formattedTime = nil
	}

	// Update the schedule using prepared statement
	result := db.Exec(
		"UPDATE schedules SET next_run_time = ?, updated_at = ? WHERE id = ?",
		formattedTime,
		time.Now().Format("2006-01-02 15:04:05"),
		scheduleID,
	)

	if result.Error != nil {
		log.Printf("Scheduler Repository: Error updating next run time: %v", result.Error)
		return result.Error
	}

	if result.RowsAffected == 0 {
		log.Printf("Scheduler Repository: No rows affected when updating schedule ID: %d", scheduleID)
		return errors.New("schedule not found")
	}

	logMsg := "Successfully updated next run time"
	if nextRunTimeStr == nil {
		logMsg = "Successfully set next run time to NULL"
	}
	log.Printf("Scheduler Repository: %s for schedule ID: %d", logMsg, scheduleID)
	return nil
}

// Add the GetScanJobDetails method to support getting job type for cancellation
func (r *schedulerRepo) GetScanJobDetails(ctx context.Context, jobID int64) (*domain.ScanJob, error) {
	log.Printf("Scheduler Repository: Getting details for scan job ID: %d", jobID)

	// Get the DB from context or use the repo's DB
	db := appCtx.GetDB(ctx)
	if db == nil {
		db = r.db
	}

	var job types.ScanJob
	if err := db.Table("scan_jobs").Where("id = ?", jobID).First(&job).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			log.Printf("Scheduler Repository: Job not found for ID: %d", jobID)
			return nil, errors.New("scan job not found")
		}
		return nil, err
	}

	// Convert to domain model
	domainJob := &domain.ScanJob{
		ID:        job.ID,
		ScannerID: job.ScannerID,
		Name:      job.Name,
		Status:    domain.ScheduleStatus(job.Status),
		StartTime: job.StartTime,
		Progress:  *job.Progress,
	}

	if job.EndTime != nil {
		domainJob.EndTime = job.EndTime
	}

	return domainJob, nil
}
