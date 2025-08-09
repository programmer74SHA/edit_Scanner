package storage

import (
	"context"
	"errors"
	"time"

	scanJobDomain "gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanjob/domain"
	scanJobPort "gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanjob/port"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/adapter/storage/types"
	typesMapper "gitlab.apk-group.net/siem/backend/asset-discovery/pkg/adapter/storage/types/mapper"
	"gorm.io/gorm"
)

type scanJobRepo struct {
	db *gorm.DB
}

func NewScanJobRepo(db *gorm.DB) scanJobPort.Repo {
	return &scanJobRepo{db: db}
}

func (r *scanJobRepo) Get(ctx context.Context, filter scanJobDomain.ScanJobFilters, limit, offset int, sortOptions ...scanJobDomain.SortOption) ([]scanJobDomain.ScanJob, int, error) {
	var jobs []types.ScanJob
	var total int64

	query := r.db.WithContext(ctx).Model(&types.ScanJob{})

	needsAssetScanJobJoin := false
	for _, sort := range sortOptions {
		if sort.Field == "discovered_at" {
			needsAssetScanJobJoin = true
			break
		}
	}

	if needsAssetScanJobJoin {
		query = query.Select("scan_jobs.*, MIN(asset_scan_jobs.discovered_at) as earliest_discovered_at").
			Joins("LEFT JOIN asset_scan_jobs ON scan_jobs.id = asset_scan_jobs.scan_job_id").
			Group("scan_jobs.id")
	}

	// Apply filters
	if filter.Name != "" {
		query = query.Where("scan_jobs.name LIKE ?", "%"+filter.Name+"%")
	}
	if filter.Status != "" {
		query = query.Where("scan_jobs.status = ?", filter.Status)
	}
	if filter.StartTimeFrom != nil {
		query = query.Where("scan_jobs.start_time >= ?", filter.StartTimeFrom)
	}
	if filter.StartTimeTo != nil {
		query = query.Where("scan_jobs.start_time <= ?", filter.StartTimeTo)
	}

	countQuery := r.db.WithContext(ctx).Model(&types.ScanJob{})
	if filter.Name != "" {
		countQuery = countQuery.Where("name LIKE ?", "%"+filter.Name+"%")
	}
	if filter.Status != "" {
		countQuery = countQuery.Where("status = ?", filter.Status)
	}
	if filter.StartTimeFrom != nil {
		countQuery = countQuery.Where("start_time >= ?", filter.StartTimeFrom)
	}
	if filter.StartTimeTo != nil {
		countQuery = countQuery.Where("start_time <= ?", filter.StartTimeTo)
	}

	if err := countQuery.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	// Apply sorting
	for _, sort := range sortOptions {
		order := "ASC"
		if sort.Order == "desc" {
			order = "DESC"
		}

		switch sort.Field {
		case "discovered_at":
			query = query.Order("earliest_discovered_at " + order)
		case "id", "name", "status", "start_time", "end_time", "progress", "scanner_id", "created_at", "updated_at":
			query = query.Order("scan_jobs." + sort.Field + " " + order)
		default:
			query = query.Order("scan_jobs." + sort.Field + " " + order)
		}
	}

	// Apply pagination
	query = query.Limit(limit).Offset(offset)

	// Execute query
	if err := query.Find(&jobs).Error; err != nil {
		return nil, 0, err
	}

	// If we have jobs, we need to load AssetScanJobs separately since we used GROUP BY
	if len(jobs) > 0 {
		jobIDs := make([]int64, len(jobs))
		for i, job := range jobs {
			jobIDs[i] = job.ID
		}

		var assetScanJobs []types.AssetScanJob
		if err := r.db.WithContext(ctx).
			Preload("Asset").
			Where("scan_job_id IN ?", jobIDs).
			Find(&assetScanJobs).Error; err != nil {
			return nil, 0, err
		}

		assetScanJobsMap := make(map[int64][]types.AssetScanJob)
		for _, asj := range assetScanJobs {
			assetScanJobsMap[asj.ScanJobID] = append(assetScanJobsMap[asj.ScanJobID], asj)
		}

		for i := range jobs {
			if asjs, exists := assetScanJobsMap[jobs[i].ID]; exists {
				jobs[i].AssetScanJobs = asjs
			}
		}
	}

	// Map to domain
	result := make([]scanJobDomain.ScanJob, 0, len(jobs))
	for _, j := range jobs {
		d, err := typesMapper.ScanJobStorage2Domain(j)
		if err != nil {
			continue
		}
		result = append(result, *d)
	}

	return result, int(total), nil
}

func (r *scanJobRepo) GetByID(ctx context.Context, id int64) (*scanJobDomain.ScanJob, error) {
	var job types.ScanJob
	err := r.db.WithContext(ctx).Preload("AssetScanJobs.Asset").Where("id = ?", id).First(&job).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}

	d, err := typesMapper.ScanJobStorage2Domain(job)
	if err != nil {
		return nil, err
	}
	return d, nil
}

// GetJobsForComparison retrieves job data with times for determining which job is newer and comparison
func (r *scanJobRepo) GetJobsForComparison(ctx context.Context, ids []int64) ([]*scanJobDomain.JobComparisonResult, error) {
	if len(ids) != 2 {
		return nil, errors.New("exactly 2 job IDs must be provided")
	}

	// Use a database transaction to ensure data consistency
	tx := r.db.WithContext(ctx).Begin()
	if tx.Error != nil {
		return nil, tx.Error
	}
	defer func() {
		if err := recover(); err != nil {
			tx.Rollback()
		} else {
			tx.Commit()
		}
	}()

	// Get job details including start_time and status
	var jobDetails []struct {
		ID        int64     `gorm:"column:id"`
		Status    string    `gorm:"column:status"`
		StartTime time.Time `gorm:"column:start_time"`
	}

	err := tx.Table("scan_jobs").
		Select("id, status, start_time").
		Where("id IN ?", ids).
		Find(&jobDetails).Error
	if err != nil {
		return nil, err
	}

	if len(jobDetails) != 2 {
		return nil, errors.New("one or both jobs not found")
	}

	// Get asset IDs for each job (only non-deleted assets)
	var assetScanJobs []struct {
		ScanJobID int64  `gorm:"column:scan_job_id"`
		AssetID   string `gorm:"column:asset_id"`
	}

	err = tx.Table("asset_scan_jobs").
		Select("asset_scan_jobs.scan_job_id, asset_scan_jobs.asset_id").
		Joins("JOIN assets ON asset_scan_jobs.asset_id = assets.id").
		Where("asset_scan_jobs.scan_job_id IN ? AND assets.deleted_at IS NULL", ids).
		Find(&assetScanJobs).Error
	if err != nil {
		return nil, err
	}

	// Group asset IDs by job ID
	assetsByJob := make(map[int64][]string)
	for _, asj := range assetScanJobs {
		assetsByJob[asj.ScanJobID] = append(assetsByJob[asj.ScanJobID], asj.AssetID)
	}

	// Create result objects
	results := make([]*scanJobDomain.JobComparisonResult, len(jobDetails))
	for i, job := range jobDetails {
		results[i] = &scanJobDomain.JobComparisonResult{
			ID:        job.ID,
			Status:    job.Status,
			StartTime: job.StartTime,
			AssetIDs:  assetsByJob[job.ID],
		}
	}

	return results, nil
}
