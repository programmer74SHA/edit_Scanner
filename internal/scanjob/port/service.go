package port

import (
	"context"

	"gitlab.apk-group.net/siem/backend/asset-discovery/api/pb"
	assetDomain "gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/domain"
	assetPort "gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/port"
	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanjob/domain"
	scannerPort "gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanner/port"
)

type Service interface {
	GetJobs(ctx context.Context, filter domain.ScanJobFilters, limit, offset int, sortOptions ...domain.SortOption) ([]domain.ScanJob, int, error)
	GetJobByID(ctx context.Context, id int64) (*domain.ScanJob, error)
	DiffJobs(ctx context.Context, ids []int64, newAssetsLimit, newAssetsOffset, missingAssetsLimit, missingAssetsOffset int) ([]assetDomain.AssetDomain, []assetDomain.AssetDomain, int, int, error)
	DiffJobsByType(ctx context.Context, ids []int64, assetType string, limit, offset int, sorts []*pb.SortField) ([]assetDomain.AssetDomain, int, error)
	ExportDiffJobs(ctx context.Context, ids []int64) (*assetDomain.ExportData, error)
	GetAssetService() assetPort.Service
	GetScannerService() scannerPort.Service
}
