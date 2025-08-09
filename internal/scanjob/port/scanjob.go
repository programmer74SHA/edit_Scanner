package port

import (
	"context"

	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanjob/domain"
)

type Repo interface {
	Get(ctx context.Context, filter domain.ScanJobFilters, limit, offset int, sortOptions ...domain.SortOption) ([]domain.ScanJob, int, error)
	GetByID(ctx context.Context, id int64) (*domain.ScanJob, error)
	GetJobsForComparison(ctx context.Context, ids []int64) ([]*domain.JobComparisonResult, error)
}
