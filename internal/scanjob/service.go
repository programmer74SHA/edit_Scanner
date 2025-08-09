package scanjob

import (
	"context"
	"errors"

	"gitlab.apk-group.net/siem/backend/asset-discovery/api/pb"
	assetDomain "gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/domain"
	assetPort "gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/port"
	domain "gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanjob/domain"
	scanJobPort "gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanjob/port"
	scannerPort "gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanner/port"
)

var (
	ErrJobNotComplete   = errors.New("scan job is not complete")
	ErrJobNotFound      = errors.New("scan job not found")
	ErrInvalidScanJobID = errors.New("invalid scan job ID")
	ErrScanJobNotFound  = errors.New("scan job not found")
)

// service implements scanJobPort.Service
type service struct {
	repo           scanJobPort.Repo
	assetService   assetPort.Service
	scannerService scannerPort.Service
}

// NewScanJobService creates a new scan job service
func NewScanJobService(repo scanJobPort.Repo, assetService assetPort.Service, scannerService scannerPort.Service) scanJobPort.Service {
	return &service{
		repo:           repo,
		assetService:   assetService,
		scannerService: scannerService,
	}
}

// GetAssetService returns the asset service
func (s *service) GetAssetService() assetPort.Service {
	return s.assetService
}

// GetScannerService returns the scanner service
func (s *service) GetScannerService() scannerPort.Service {
	return s.scannerService
}

// GetJobs retrieves scan jobs based on filter, pagination, and sorting
func (s *service) GetJobs(ctx context.Context, filter domain.ScanJobFilters, limit, offset int, sortOptions ...domain.SortOption) ([]domain.ScanJob, int, error) {
	return s.repo.Get(ctx, filter, limit, offset, sortOptions...)
}

// GetJobByID retrieves a single scan job by its ID
func (s *service) GetJobByID(ctx context.Context, id int64) (*domain.ScanJob, error) {
	return s.repo.GetByID(ctx, id)
}

// DiffJobs compares two scan jobs and returns the assets that are in the newer job but not in the older job,
// and the assets that are in the older job but not in the newer job
func (s *service) DiffJobs(ctx context.Context, ids []int64, newAssetsLimit, newAssetsOffset, missingAssetsLimit, missingAssetsOffset int) ([]assetDomain.AssetDomain, []assetDomain.AssetDomain, int, int, error) {
	if len(ids) != 2 {
		return nil, nil, 0, 0, errors.New("exactly 2 job IDs must be provided")
	}

	// Get job data with times to determine which is newer/older
	jobsData, err := s.repo.GetJobsForComparison(ctx, ids)
	if err != nil {
		return nil, nil, 0, 0, err
	}

	// Determine which job is newer based on start_time
	var newerJob, olderJob *domain.JobComparisonResult
	if jobsData[0].StartTime.After(jobsData[1].StartTime) {
		newerJob = jobsData[0]
		olderJob = jobsData[1]
	} else {
		newerJob = jobsData[1]
		olderJob = jobsData[0]
	}

	// Check if both jobs are completed
	if newerJob.Status != "Completed" {
		return nil, nil, 0, 0, errors.New("newer job is not complete")
	}

	if olderJob.Status != "Completed" {
		return nil, nil, 0, 0, errors.New("older job is not complete")
	}

	// Create asset ID maps for comparison
	olderIDMap := make(map[string]struct{}, len(olderJob.AssetIDs))
	for _, id := range olderJob.AssetIDs {
		olderIDMap[id] = struct{}{}
	}

	newerIDMap := make(map[string]struct{}, len(newerJob.AssetIDs))
	for _, id := range newerJob.AssetIDs {
		newerIDMap[id] = struct{}{}
	}

	// Find new asset IDs (in newer job but not in older)
	var newAssetIDs []assetDomain.AssetUUID
	for _, id := range newerJob.AssetIDs {
		if _, exists := olderIDMap[id]; !exists {
			assetUUID, err := assetDomain.AssetUUIDFromString(id)
			if err != nil {
				continue // Skip invalid UUIDs
			}
			newAssetIDs = append(newAssetIDs, assetUUID)
		}
	}

	// Find missing asset IDs (in older job but not in newer)
	var missingAssetIDs []assetDomain.AssetUUID
	for _, id := range olderJob.AssetIDs {
		if _, exists := newerIDMap[id]; !exists {
			assetUUID, err := assetDomain.AssetUUIDFromString(id)
			if err != nil {
				continue // Skip invalid UUIDs
			}
			missingAssetIDs = append(missingAssetIDs, assetUUID)
		}
	}

	// Skip pagination if both limits and offsets are zero
	if newAssetsLimit == 0 && newAssetsOffset == 0 && missingAssetsLimit == 0 && missingAssetsOffset == 0 {
		// Get all new assets
		var newAssets []assetDomain.AssetDomain
		if len(newAssetIDs) > 0 {
			newAssets, err = s.assetService.GetByIDs(ctx, newAssetIDs)
			if err != nil {
				return nil, nil, 0, 0, err
			}
		}

		// Get all missing assets
		var missingAssets []assetDomain.AssetDomain
		if len(missingAssetIDs) > 0 {
			missingAssets, err = s.assetService.GetByIDs(ctx, missingAssetIDs)
			if err != nil {
				return nil, nil, 0, 0, err
			}
		}

		return newAssets, missingAssets, len(newAssetIDs), len(missingAssetIDs), nil
	}

	// Apply separate pagination for new and missing assets
	// Handle pagination for new assets
	var paginatedNewAssetIDs []assetDomain.AssetUUID
	if len(newAssetIDs) > 0 && (newAssetsLimit > 0 || newAssetsOffset > 0) {
		startIdx := newAssetsOffset
		endIdx := newAssetsOffset + newAssetsLimit

		if startIdx < len(newAssetIDs) {
			if endIdx > len(newAssetIDs) {
				endIdx = len(newAssetIDs)
			}
			paginatedNewAssetIDs = newAssetIDs[startIdx:endIdx]
		}
	} else if len(newAssetIDs) > 0 {
		// If no pagination specified for new assets, return all
		paginatedNewAssetIDs = newAssetIDs
	}

	// Handle pagination for missing assets
	var paginatedMissingAssetIDs []assetDomain.AssetUUID
	if len(missingAssetIDs) > 0 && (missingAssetsLimit > 0 || missingAssetsOffset > 0) {
		startIdx := missingAssetsOffset
		endIdx := missingAssetsOffset + missingAssetsLimit

		if startIdx < len(missingAssetIDs) {
			if endIdx > len(missingAssetIDs) {
				endIdx = len(missingAssetIDs)
			}
			paginatedMissingAssetIDs = missingAssetIDs[startIdx:endIdx]
		}
	} else if len(missingAssetIDs) > 0 {
		// If no pagination specified for missing assets, return all
		paginatedMissingAssetIDs = missingAssetIDs
	}

	// Get new assets with pagination
	var newAssets []assetDomain.AssetDomain
	if len(paginatedNewAssetIDs) > 0 {
		newAssets, err = s.assetService.GetByIDs(ctx, paginatedNewAssetIDs)
		if err != nil {
			return nil, nil, 0, 0, err
		}
	}

	// Get missing assets with pagination
	var missingAssets []assetDomain.AssetDomain
	if len(paginatedMissingAssetIDs) > 0 {
		missingAssets, err = s.assetService.GetByIDs(ctx, paginatedMissingAssetIDs)
		if err != nil {
			return nil, nil, 0, 0, err
		}
	}

	return newAssets, missingAssets, len(newAssetIDs), len(missingAssetIDs), nil
}

// DiffJobsByType compares two scan jobs and returns assets of the specified type (new or missing)
func (s *service) DiffJobsByType(ctx context.Context, ids []int64, assetType string, limit, offset int, sorts []*pb.SortField) ([]assetDomain.AssetDomain, int, error) {
	if len(ids) != 2 {
		return nil, 0, errors.New("exactly 2 job IDs must be provided")
	}

	if assetType != "new" && assetType != "missing" {
		return nil, 0, errors.New("assetType must be 'new' or 'missing'")
	}

	// Get job data with times to determine which is newer/older
	jobsData, err := s.repo.GetJobsForComparison(ctx, ids)
	if err != nil {
		return nil, 0, err
	}

	// Determine which job is newer based on start_time
	var newerJob, olderJob *domain.JobComparisonResult
	if jobsData[0].StartTime.After(jobsData[1].StartTime) {
		newerJob = jobsData[0]
		olderJob = jobsData[1]
	} else {
		newerJob = jobsData[1]
		olderJob = jobsData[0]
	}

	// Check if both jobs are completed
	if newerJob.Status != "Completed" {
		return nil, 0, errors.New("newer job is not complete")
	}

	if olderJob.Status != "Completed" {
		return nil, 0, errors.New("older job is not complete")
	}

	// Create asset ID maps for comparison
	olderIDMap := make(map[string]struct{}, len(olderJob.AssetIDs))
	for _, id := range olderJob.AssetIDs {
		olderIDMap[id] = struct{}{}
	}

	newerIDMap := make(map[string]struct{}, len(newerJob.AssetIDs))
	for _, id := range newerJob.AssetIDs {
		newerIDMap[id] = struct{}{}
	}

	var targetAssetIDs []assetDomain.AssetUUID

	if assetType == "new" {
		// Find new asset IDs (in newer job but not in older)
		for _, id := range newerJob.AssetIDs {
			if _, exists := olderIDMap[id]; !exists {
				assetUUID, err := assetDomain.AssetUUIDFromString(id)
				if err != nil {
					continue
				}
				targetAssetIDs = append(targetAssetIDs, assetUUID)
			}
		}
	} else {
		// Find missing asset IDs (in older job but not in newer)
		for _, id := range olderJob.AssetIDs {
			if _, exists := newerIDMap[id]; !exists {
				assetUUID, err := assetDomain.AssetUUIDFromString(id)
				if err != nil {
					continue
				}
				targetAssetIDs = append(targetAssetIDs, assetUUID)
			}
		}
	}

	totalCount := len(targetAssetIDs)

	// Apply pagination
	var paginatedAssetIDs []assetDomain.AssetUUID
	if len(targetAssetIDs) > 0 {
		startIdx := offset
		endIdx := offset + limit

		if startIdx < len(targetAssetIDs) {
			if endIdx > len(targetAssetIDs) {
				endIdx = len(targetAssetIDs)
			}
			paginatedAssetIDs = targetAssetIDs[startIdx:endIdx]
		}
	}

	var assets []assetDomain.AssetDomain
	if len(paginatedAssetIDs) > 0 {
		domainSorts := make([]assetDomain.SortOption, 0, len(sorts))
		for _, sort := range sorts {
			domainSorts = append(domainSorts, assetDomain.SortOption{
				Field: sort.Field,
				Order: sort.Order,
			})
		}

		assets, err = s.assetService.GetByIDsWithSort(ctx, paginatedAssetIDs, domainSorts...)
		if err != nil {
			return nil, 0, err
		}
	}

	return assets, totalCount, nil
}

func (s *service) ExportDiffJobs(ctx context.Context, ids []int64) (*assetDomain.ExportData, error) {
	newAssets, missingAssets, _, _, err := s.DiffJobs(ctx, ids, 0, 0, 0, 0)
	if err != nil {
		switch err.Error() {
		case "newer job is not complete", "older job is not complete":
			return nil, ErrJobNotComplete
		case "scan job not found":
			return nil, ErrScanJobNotFound
		default:
			return nil, err
		}
	}

	exportData := &assetDomain.ExportData{
		Assets:    make([]map[string]interface{}, 0),
		Ports:     make([]map[string]interface{}, 0),
		VMwareVMs: make([]map[string]interface{}, 0),
		AssetIPs:  make([]map[string]interface{}, 0),
	}

	for _, asset := range newAssets {
		assetMap, err := assetDomain.ToMap(asset)
		if err != nil {
			return nil, err
		}
		assetMap["status"] = "new_asset"
		exportData.Assets = append(exportData.Assets, assetMap)

		for _, port := range asset.Ports {
			portMap, err := assetDomain.ToMap(port)
			if err != nil {
				return nil, err
			}
			exportData.Ports = append(exportData.Ports, portMap)
		}

		for _, vm := range asset.VMwareVMs {
			vmMap, err := assetDomain.ToMap(vm)
			if err != nil {
				return nil, err
			}
			exportData.VMwareVMs = append(exportData.VMwareVMs, vmMap)
		}

		for _, ip := range asset.AssetIPs {
			ipMap, err := assetDomain.ToMap(ip)
			if err != nil {
				return nil, err
			}
			exportData.AssetIPs = append(exportData.AssetIPs, ipMap)
		}
	}

	for _, asset := range missingAssets {
		assetMap, err := assetDomain.ToMap(asset)
		if err != nil {
			return nil, err
		}
		assetMap["status"] = "missing_asset"
		exportData.Assets = append(exportData.Assets, assetMap)

		for _, port := range asset.Ports {
			portMap, err := assetDomain.ToMap(port)
			if err != nil {
				return nil, err
			}
			exportData.Ports = append(exportData.Ports, portMap)
		}

		for _, vm := range asset.VMwareVMs {
			vmMap, err := assetDomain.ToMap(vm)
			if err != nil {
				return nil, err
			}
			exportData.VMwareVMs = append(exportData.VMwareVMs, vmMap)
		}

		for _, ip := range asset.AssetIPs {
			ipMap, err := assetDomain.ToMap(ip)
			if err != nil {
				return nil, err
			}
			exportData.AssetIPs = append(exportData.AssetIPs, ipMap)
		}
	}

	return exportData, nil
}
