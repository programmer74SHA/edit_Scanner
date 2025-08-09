package domain

import (
	"time"

	assetDomain "gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/domain"
)

// AssetScanJob links an asset with its discovery details in a scan job
type AssetScanJob struct {
	Asset        assetDomain.AssetDomain
	DiscoveredAt time.Time
}

// ScanJob represents a scanning job and its related metadata
type ScanJob struct {
	ID            int64
	Name          string
	Status        string
	StartTime     time.Time
	EndTime       *time.Time
	Progress      *int
	ScannerID     int64
	AssetScanJobs []AssetScanJob
}

// ScanJobFilters defines supported filters for querying scan jobs
type ScanJobFilters struct {
	Name          string
	Status        string
	StartTimeFrom *time.Time
	StartTimeTo   *time.Time
}

// SortOption defines sorting options for scan job queries
type SortOption struct {
	Field string
	Order string
}

// JobComparisonResult contains the data needed for comparing two scan jobs
type JobComparisonResult struct {
	ID        int64
	Status    string
	StartTime time.Time
	AssetIDs  []string
}
