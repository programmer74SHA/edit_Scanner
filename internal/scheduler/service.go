package scheduler

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	scannerDomain "gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanner/domain"
	scannerPort "gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanner/port"
	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/scheduler/domain"
	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/scheduler/port"
)

var (
	ErrSchedulerOnExecute     = errors.New("error on executing scheduled scan")
	ErrScanJobOnCreate        = errors.New("error on creating scan job")
	ErrScanJobOnUpdate        = errors.New("error on updating scan job")
	ErrScanJobOnCancel        = errors.New("error on cancelling scan job")
	ErrScheduleNotFound       = errors.New("schedule not found")
	ErrInvalidScheduleInput   = errors.New("invalid schedule input")
	ErrScanJobNotRunning      = errors.New("scan job is not running")
	ErrScanJobNotFound        = errors.New("scan job not found")
	ErrUnsupportedScannerType = errors.New("unsupported scanner type")
)

// Scanner defines a generic interface for all scanner types
type Scanner interface {
	Execute(ctx context.Context, scanner scannerDomain.ScannerDomain, scanJobID int64) error
	CancelScan(jobID int64) bool
	StatusScan(jobID int64) bool
}

// ScannerFactory manages different scanner implementations
type ScannerFactory struct {
	scanners map[string]Scanner
}

// NewScannerFactory creates a new scanner factory
func NewScannerFactory() *ScannerFactory {
	return &ScannerFactory{
		scanners: make(map[string]Scanner),
	}
}

// RegisterScanner registers a scanner implementation for a specific type
func (f *ScannerFactory) RegisterScanner(scanType string, scanner Scanner) {
	normalizedType := strings.ToUpper(strings.TrimSpace(scanType))
	f.scanners[normalizedType] = scanner
	log.Printf("Scanner Factory: Registered scanner for type: %s", normalizedType)
}

// GetScanner retrieves a scanner implementation for the given type
func (f *ScannerFactory) GetScanner(scanType string) (Scanner, error) {
	normalizedType := strings.ToUpper(strings.TrimSpace(scanType))
	scanner, exists := f.scanners[normalizedType]
	if !exists {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedScannerType, scanType)
	}
	return scanner, nil
}

// GetRegisteredTypes returns all registered scanner types
func (f *ScannerFactory) GetRegisteredTypes() []string {
	types := make([]string, 0, len(f.scanners))
	for scanType := range f.scanners {
		types = append(types, scanType)
	}
	return types
}

// schedulerService with generic scanner support
type schedulerService struct {
	repo           port.Repo
	scannerService scannerPort.Service
	scannerFactory *ScannerFactory
	cancelledJobs  map[int64]bool
	mutex          sync.Mutex // Mutex to protect concurrent access to cancelledJobs
}

// NewSchedulerService creates a new scheduler service with scanner factory
func NewSchedulerService(
	repo port.Repo,
	scannerService scannerPort.Service,
	scannerFactory *ScannerFactory,
) port.Service {
	if scannerFactory == nil {
		log.Printf("Warning: ScannerFactory is nil")
		scannerFactory = NewScannerFactory()
	}

	log.Printf("Scheduler Service: Initialized with scanner types: %v", scannerFactory.GetRegisteredTypes())

	return &schedulerService{
		repo:           repo,
		scannerService: scannerService,
		scannerFactory: scannerFactory,
		cancelledJobs:  make(map[int64]bool),
	}
}

// ExecuteScheduledScan executes a scheduled scan and updates its job status and schedule.
func (s *schedulerService) ExecuteScheduledScan(ctx context.Context, scheduledScan domain.ScheduledScan) error {
	log.Printf("Scheduler Service: Executing scheduled scan for scanner ID: %d with schedule type: %s",
		scheduledScan.Scanner.ID, scheduledScan.Schedule.ScheduleType)

	scanner, err := s.scannerService.GetScannerByID(ctx, scheduledScan.Scanner.ID)
	if err != nil {
		log.Printf("Scheduler Service: Failed to get scanner details: %v", err)
		return fmt.Errorf("failed to get scanner details: %w", err)
	}

	if scanner == nil {
		log.Printf("Scheduler Service: Scanner not found for ID: %d", scheduledScan.Scanner.ID)
		return fmt.Errorf("scanner not found for ID: %d", scheduledScan.Scanner.ID)
	}

	// Use the scanner with decrypted credentials instead of the one from scheduledScan
	scannerToUse := *scanner

	// Create a new scan job record
	scanJob := domain.ScanJob{
		ScannerID: scannerToUse.ID,
		Name:      fmt.Sprintf("%s - %s", scannerToUse.Name, getScheduleDescription(scheduledScan.Schedule)),
		Type:      scannerToUse.ScanType, // Make sure this is not empty
		Status:    domain.ScheduleStatusRunning,
		StartTime: time.Now(),
		Progress:  0,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Add logging to verify the type
	log.Printf("Scheduler Service: Creating job with Type: '%s' for Scanner ID: %d",
		scanJob.Type, scanJob.ScannerID)

	jobID, err := s.repo.CreateScanJob(ctx, scanJob)
	if err != nil {
		log.Printf("Scheduler Service: Failed to create scan job: %v", err)
		return ErrScanJobOnCreate
	}
	log.Printf("Scheduler Service: Created scan job with ID: %d", jobID)

	// Handle next run time calculation based on schedule type
	var nextRunTimeStr *string
	switch scheduledScan.Schedule.ScheduleType {
	case scannerDomain.ScheduleTypeImmediately, scannerDomain.ScheduleTypeRunOnce:
		log.Printf("Scheduler Service: %s scan - will set next run time to NULL", scheduledScan.Schedule.ScheduleType)
		// Leave nextRunTimeStr as nil to set next_run_time to NULL

	case scannerDomain.ScheduleTypePeriodic:
		nextRunTime := CalculateNextRunTime(scheduledScan.Schedule, time.Now())
		formattedTime := nextRunTime.Format(time.RFC3339)
		nextRunTimeStr = &formattedTime
		log.Printf("Scheduler Service: Periodic scan - calculated next run time: %v", nextRunTime)

	default:
		log.Printf("Scheduler Service: Unknown schedule type %s, defaulting to periodic", scheduledScan.Schedule.ScheduleType)
		nextRunTime := CalculateNextRunTime(scheduledScan.Schedule, time.Now())
		formattedTime := nextRunTime.Format(time.RFC3339)
		nextRunTimeStr = &formattedTime
	}

	// Update the schedule's next run time (NULL for immediate/run-once, or calculated time for periodic)
	if err := s.repo.UpdateScheduleNextRun(ctx, scheduledScan.Schedule.ID, nextRunTimeStr); err != nil {
		log.Printf("Scheduler Service: Failed to update next run time: %v", err)
		// Continue execution, as this is not critical
	}

	// Execute the scan in a goroutine using the scanner with decrypted credentials
	go func(scanner scannerDomain.ScannerDomain, jobID int64) {
		bgCtx := context.Background()

		// Update initial status
		if err := s.UpdateScanJob(bgCtx, jobID, domain.ScheduleStatusRunning, 10, false); err != nil {
			log.Printf("Scheduler Service: Failed to update scan job status: %v", err)
		}

		// Get the appropriate scanner implementation
		scannerImpl, err := s.scannerFactory.GetScanner(scanner.ScanType)
		if err != nil {
			log.Printf("Scheduler Service: Error getting scanner implementation: %v", err)
			s.UpdateScanJob(bgCtx, jobID, domain.ScheduleStatusFailed, 0, true)
			return
		}

		log.Printf("Scheduler Service: Executing %s scan for job ID: %d", scanner.ScanType, jobID)

		// Execute the scan
		scanErr := scannerImpl.Execute(bgCtx, scanner, jobID)

		// Update job status based on scan result
		var finalStatus domain.ScheduleStatus
		switch {
		case scanErr == nil:
			finalStatus = domain.ScheduleStatusComplete
		case errors.Is(scanErr, context.Canceled):
			finalStatus = domain.ScheduleStatusCancelled
			log.Printf("Scheduler Service: Scan cancelled for job ID: %d", jobID)
		default:
			finalStatus = domain.ScheduleStatusFailed
			log.Printf("Scheduler Service: Error executing scan: %v", scanErr)
		}

		if err := s.UpdateScanJob(bgCtx, jobID, finalStatus, 100, true); err != nil {
			log.Printf("Scheduler Service: Failed to update job status to %s: %v", finalStatus, err)
		}
		log.Printf("Scheduler Service: Scan job ID %d completed with status: %s", jobID, finalStatus)
	}(scannerToUse, jobID) // Pass the scanner with decrypted credentials

	return nil
}

// Helper function to generate a descriptive name for the scan based on schedule type
func getScheduleDescription(schedule scannerDomain.Schedule) string {
	switch schedule.ScheduleType {
	case scannerDomain.ScheduleTypeImmediately:
		return "Immediate Run"
	case scannerDomain.ScheduleTypeRunOnce:
		return "One-time Run"
	case scannerDomain.ScheduleTypePeriodic:
		return "Scheduled Run"
	default:
		return "Scheduled Run"
	}
}

// GetDueSchedules retrieves all scheduled scans that are due to run
func (s *schedulerService) GetDueSchedules(ctx context.Context) ([]domain.ScheduledScan, error) {
	log.Printf("Scheduler Service: Retrieving due schedules")
	return s.repo.GetDueSchedules(ctx)
}

// UpdateScanJob updates the status, progress, and optionally end time of a scan job.
func (s *schedulerService) UpdateScanJob(ctx context.Context, jobID int64, status domain.ScheduleStatus, progress int, setEndTime bool) error {
	log.Printf("Scheduler Service: Updating scan job ID: %d to status: %s with progress: %d, setEndTime: %v", jobID, status, progress, setEndTime)

	err := s.repo.UpdateScanJob(ctx, jobID, status, progress, setEndTime)
	if err != nil {
		// If there were no rows affected, the job might have been already completed
		// This can happen in a race condition between cancellation and normal completion
		if strings.Contains(err.Error(), "scan job not found") {
			log.Printf("Scheduler Service: Job ID %d was already completed", jobID)
			return ErrScanJobNotFound
		}
		return err
	}
	return nil
}

// CalculateNextRunTime determines when a scheduled scan should next run
func (s *schedulerService) CalculateNextRunTime(schedule scannerDomain.Schedule) string {
	nextRunTime := CalculateNextRunTime(schedule, time.Now())
	return nextRunTime.Format(time.RFC3339)
}

// CancelScanJob cancels a running scan job and marks it as cancelled.
func (s *schedulerService) CancelScanJob(ctx context.Context, jobID int64) error {
	log.Printf("Scheduler Service: Attempting to cancel scan job ID: %d", jobID)

	// First, check if the job exists and get its details
	job, err := s.repo.GetScanJobDetails(ctx, jobID)
	if err != nil {
		log.Printf("Scheduler Service: Error getting job details for ID %d: %v", jobID, err)
		if strings.Contains(err.Error(), "not found") {
			return ErrScanJobNotFound
		}
		return fmt.Errorf("failed to get scan job details: %w", err)
	}

	if job == nil {
		log.Printf("Scheduler Service: Scan job ID %d not found", jobID)
		return ErrScanJobNotFound
	}

	log.Printf("Scheduler Service: Found job ID %d with status: %s, type: '%s'", jobID, job.Status, job.Type)

	// If job type is empty, get it from the scanner
	scannerType := job.Type
	if scannerType == "" {
		log.Printf("Scheduler Service: Job type is empty, getting from scanner service")
		scanner, err := s.scannerService.GetScannerByID(ctx, job.ScannerID)
		if err != nil {
			log.Printf("Scheduler Service: Error getting scanner: %v", err)
			return fmt.Errorf("failed to get scanner details: %w", err)
		}
		if scanner != nil {
			scannerType = scanner.ScanType
			log.Printf("Scheduler Service: Got scanner type from scanner service: '%s'", scannerType)
		}
	}

	if scannerType == "" {
		log.Printf("Scheduler Service: Cannot determine scanner type for job ID %d", jobID)
		return fmt.Errorf("cannot determine scanner type for job")
	}

	// Check if the job is in a cancellable state
	switch job.Status {
	case domain.ScheduleStatusComplete, domain.ScheduleStatusFailed, domain.ScheduleStatusCancelled:
		log.Printf("Scheduler Service: Job ID %d is already completed with status: %s", jobID, job.Status)
		return fmt.Errorf("cannot cancel job in status: %s", job.Status)
	case domain.ScheduleStatusPending, domain.ScheduleStatusRunning:
		log.Printf("Scheduler Service: Job ID %d is in cancellable state: %s", jobID, job.Status)
		// Continue with cancellation
	default:
		log.Printf("Scheduler Service: Job ID %d has unknown status: %s", jobID, job.Status)
		return fmt.Errorf("unknown job status: %s", job.Status)
	}

	// Check if scanner factory is available
	if s.scannerFactory == nil {
		log.Printf("Scheduler Service: Scanner factory is nil - cannot cancel scan")
		return fmt.Errorf("scanner factory not available")
	}

	log.Printf("Scheduler Service: Getting scanner implementation for type: %s", scannerType)

	// Get the appropriate scanner implementation using the corrected scanner type
	scannerImpl, err := s.scannerFactory.GetScanner(scannerType)
	if err != nil {
		log.Printf("Scheduler Service: Error getting scanner implementation for type %s: %v", scannerType, err)
		return fmt.Errorf("failed to get scanner implementation: %w", err)
	}

	log.Printf("Scheduler Service: Successfully got scanner implementation, attempting to cancel...")

	// Cancel the scan
	cancelled := scannerImpl.CancelScan(jobID)
	if !cancelled {
		log.Printf("Scheduler Service: Scanner reported cancellation failed for job ID: %d", jobID)
		// Don't return error here - the job might have just completed
		log.Printf("Scheduler Service: Continuing to update job status despite scanner cancellation failure")
	} else {
		log.Printf("Scheduler Service: Scanner successfully cancelled job ID: %d", jobID)
	}

	// Mark this job as cancelled in our tracking
	s.mutex.Lock()
	s.cancelledJobs[jobID] = true
	s.mutex.Unlock()
	log.Printf("Scheduler Service: Marked job ID %d as cancelled in tracking", jobID)

	// Update job status to cancelled
	log.Printf("Scheduler Service: Updating job status to cancelled...")
	err = s.UpdateScanJob(ctx, jobID, domain.ScheduleStatusCancelled, 0, true)
	if err != nil {
		log.Printf("Scheduler Service: Error updating job status after cancellation: %v", err)
		if strings.Contains(err.Error(), "scan job not found") {
			log.Printf("Scheduler Service: Job ID %d was already completed during cancellation", jobID)
			return ErrScanJobNotFound
		}
		return fmt.Errorf("failed to update job status: %w", err)
	}

	log.Printf("Scheduler Service: Successfully cancelled scan job ID: %d", jobID)
	return nil
}

// CreateScanJob creates a new scan job record
func (s *schedulerService) CreateScanJob(ctx context.Context, job domain.ScanJob) (int64, error) {
	log.Printf("Scheduler Service: Creating scan job for scanner ID: %d", job.ScannerID)

	// Create a new scan job record via the repository
	jobID, err := s.repo.CreateScanJob(ctx, job)
	if err != nil {
		log.Printf("Scheduler Service: Failed to create scan job: %v", err)
		return 0, ErrScanJobOnCreate
	}

	log.Printf("Scheduler Service: Created scan job with ID: %d", jobID)
	return jobID, nil
}

// ExecuteManualScan runs a scan manually for the given scanner with proper progress updates
func (s *schedulerService) ExecuteManualScan(ctx context.Context, scanner scannerDomain.ScannerDomain, jobID int64) error {
	log.Printf("Scheduler Service: Executing manual scan for scanner ID: %d, job ID: %d", scanner.ID, jobID)

	// Check if the scanner is valid
	if scanner.ID == 0 {
		return errors.New("invalid scanner ID")
	}

	log.Printf("Scheduler Service: Manual scan for scanner type: '%s'", scanner.ScanType)

	// Get the appropriate scanner implementation
	scannerImpl, err := s.scannerFactory.GetScanner(scanner.ScanType)
	if err != nil {
		log.Printf("Scheduler Service: Error getting scanner implementation: %v", err)
		// Update job status to failed
		s.UpdateScanJob(ctx, jobID, domain.ScheduleStatusFailed, 0, true)
		return err
	}

	// Update initial status to Running with some progress
	if err := s.UpdateScanJob(ctx, jobID, domain.ScheduleStatusRunning, 10, false); err != nil {
		log.Printf("Scheduler Service: Failed to update scan job status to Running: %v", err)
		// Continue execution even if status update fails
	}

	log.Printf("Scheduler Service: Executing manual scan for job ID: %d", jobID)

	// Execute the scan
	scanErr := scannerImpl.Execute(ctx, scanner, jobID)

	// Update job status based on scan result
	var finalStatus domain.ScheduleStatus
	var finalProgress int

	switch {
	case scanErr == nil:
		finalStatus = domain.ScheduleStatusComplete
		finalProgress = 100
		log.Printf("Scheduler Service: Manual scan completed successfully for job ID: %d", jobID)
	case errors.Is(scanErr, context.Canceled):
		finalStatus = domain.ScheduleStatusCancelled
		finalProgress = 0
		log.Printf("Scheduler Service: Manual scan cancelled for job ID: %d", jobID)
	default:
		finalStatus = domain.ScheduleStatusFailed
		finalProgress = 0
		log.Printf("Scheduler Service: Manual scan failed for job ID: %d, error: %v", jobID, scanErr)
	}

	// Update final job status with end time
	if err := s.UpdateScanJob(ctx, jobID, finalStatus, finalProgress, true); err != nil {
		log.Printf("Scheduler Service: Failed to update final job status to %s: %v", finalStatus, err)
		// Don't override the original scan error
		if scanErr == nil {
			return err
		}
	}

	log.Printf("Scheduler Service: Manual scan job ID %d completed with status: %s, progress: %d", jobID, finalStatus, finalProgress)
	return scanErr
}

// CheckScanStatus checks the status of a running scan
func (s *schedulerService) CheckScanStatus(ctx context.Context, jobID int64) (bool, error) {
	log.Printf("Scheduler Service: Checking status for scan job ID: %d", jobID)

	// Get job details to determine scanner type
	job, err := s.repo.GetScanJobDetails(ctx, jobID)
	if err != nil {
		log.Printf("Scheduler Service: Error getting job details: %v", err)
		return false, err
	}

	// Get the appropriate scanner implementation
	scannerImpl, err := s.scannerFactory.GetScanner(job.Type)
	if err != nil {
		log.Printf("Scheduler Service: Error getting scanner implementation for status check: %v", err)
		return false, err
	}

	// Check the scan status
	return scannerImpl.StatusScan(jobID), nil
}