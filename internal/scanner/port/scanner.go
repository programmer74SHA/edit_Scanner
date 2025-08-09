package port

import (
	"context"

	"github.com/google/uuid"
	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanner/domain"
)

// Repo is the unified repository interface for all scanner operations
type Repo interface {
	// Basic Scanner CRUD operations
	Create(ctx context.Context, scanner domain.ScannerDomain) (int64, error)
	GetByID(ctx context.Context, scannerID int64) (*domain.ScannerDomain, error)
	Update(ctx context.Context, scanner domain.ScannerDomain) error
	Delete(ctx context.Context, scannerID int64) error
	DeleteBatch(ctx context.Context, params domain.DeleteParams) (int, error)
	List(ctx context.Context, filter domain.ScannerFilter, pagination domain.Pagination) ([]domain.ScannerDomain, int, error)
	UpdateScannerStatus(ctx context.Context, params domain.StatusUpdateParams) (int, error)

	// Nmap Profile methods
	GetNmapProfiles(ctx context.Context) ([]domain.NmapProfile, error)
	GetNmapProfileByID(ctx context.Context, profileID int64) (*domain.NmapProfile, error)
	GetDefaultNmapProfile(ctx context.Context) (*domain.NmapProfile, error)
	CreateNmapProfile(ctx context.Context, profile domain.NmapProfile) (int64, error)

	// Switch scan operations
	StoreSwitchScanResult(ctx context.Context, result *domain.SwitchScanResult) error
	GetSwitchMetadataByAssetID(ctx context.Context, assetID uuid.UUID) (*domain.SwitchMetadata, error)
	StoreSwitchMetadata(ctx context.Context, metadata *domain.SwitchMetadata) error
	UpdateSwitchMetadata(ctx context.Context, metadata *domain.SwitchMetadata) error
	DeleteSwitchDataByAssetID(ctx context.Context, assetID uuid.UUID) error

	// Switch component storage
	StoreInterfaces(ctx context.Context, interfaces []domain.SwitchInterface, assetID uuid.UUID) error
	StoreVLANs(ctx context.Context, vlans []domain.SwitchVLAN, assetID uuid.UUID) error
	StoreNeighbors(ctx context.Context, neighbors []domain.SwitchNeighbor, assetID uuid.UUID) error

	// Switch asset management
	GetAssetIDForScanner(ctx context.Context, scannerID int64) (uuid.UUID, error)
	UpdateAssetWithScanResults(ctx context.Context, assetID uuid.UUID, result *domain.SwitchScanResult) error
	LinkAssetToScanJob(ctx context.Context, assetID uuid.UUID, scanJobID int64) error
	CreateSwitchAsset(ctx context.Context, scannerID int64, config domain.SwitchConfig) (uuid.UUID, error)
	GetSwitchDataByAssetID(ctx context.Context, assetID uuid.UUID) (*domain.SwitchData, error)
}
