package mapper

import (
	scanJobDomain "gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanjob/domain"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/adapter/storage/types"
)

// ScanJobStorage2Domain maps storage ScanJob to domain ScanJob
func ScanJobStorage2Domain(s types.ScanJob) (*scanJobDomain.ScanJob, error) {

	dj := scanJobDomain.ScanJob{
		ID:        s.ID,
		Name:      s.Name,
		Status:    s.Status,
		StartTime: s.StartTime,
		EndTime:   s.EndTime,
		Progress:  s.Progress,
		ScannerID: s.ScannerID,
	}

	// Map AssetScanJobs
	for _, as := range s.AssetScanJobs {
		ad, err := AssetStorage2Domain(as.Asset)
		if err != nil {
			continue
		}

		dj.AssetScanJobs = append(dj.AssetScanJobs, scanJobDomain.AssetScanJob{
			Asset:        *ad,
			DiscoveredAt: as.DiscoveredAt,
		})
	}

	return &dj, nil
}
