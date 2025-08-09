package port

import (
	"context"

	scannerDomain "gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanner/domain"
)

// Service defines the interface for scheduler operations
type Service interface {
	// CancelScanJob cancels a running scan job
	CancelScanJob(ctx context.Context, jobID int64) error

	// ExecuteManualScan runs a scan manually
	ExecuteManualScan(ctx context.Context, scanner scannerDomain.ScannerDomain, jobID int64) error
}
