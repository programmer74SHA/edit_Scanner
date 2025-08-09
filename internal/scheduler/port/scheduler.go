package port

import (
	"context"

	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/scheduler/domain"
)

// Repo defines the repository interface for scheduler operations.
type Repo interface {
	// GetDueSchedules retrieves all scheduled scans that are due to run.
	GetDueSchedules(ctx context.Context) ([]domain.ScheduledScan, error)

	// CreateScanJob creates a new scan job record and returns its ID.
	CreateScanJob(ctx context.Context, job domain.ScanJob) (int64, error)

	// UpdateScanJob updates the status, progress, and optionally end time of a scan job.
	UpdateScanJob(ctx context.Context, jobID int64, status domain.ScheduleStatus, progress int, setEndTime bool) error

	// UpdateScheduleNextRun updates the next run time for a schedule, or sets it to NULL if nextRunTime is nil.
	UpdateScheduleNextRun(ctx context.Context, scheduleID int64, nextRunTime *string) error

	// GetScanJobDetails retrieves details for a specific scan job.
	GetScanJobDetails(ctx context.Context, jobID int64) (*domain.ScanJob, error)
}
