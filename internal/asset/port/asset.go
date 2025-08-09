package port

import (
	"context"

	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/domain"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/adapter/storage/types"
)

type Repo interface {
	Create(ctx context.Context, asset domain.AssetDomain, scannerType ...string) (domain.AssetUUID, error)
	Get(ctx context.Context, assetFilter domain.AssetFilters) ([]domain.AssetDomain, error)
	LinkAssetToScanJob(ctx context.Context, assetID domain.AssetUUID, scanJobID int64) error
	StoreVMwareVM(ctx context.Context, vmData domain.VMwareVM) error
	StoreVCenterDatacenter(ctx context.Context, datacenterData domain.VCenterDatacenter) error
	GetVCenterDatacenterID(ctx context.Context, datacenterID, vcenterServer string) (string, error)
	StoreVCenterHost(ctx context.Context, hostData domain.VCenterHost) error
	GetVCenterHostID(ctx context.Context, hostID, vcenterServer string) (string, error)
	StoreVCenterDatastore(ctx context.Context, datastoreData domain.VCenterDatastore) error
	GetVCenterDatastoreID(ctx context.Context, datastoreID, vcenterServer string) (string, error)
	StoreVCenterNetwork(ctx context.Context, networkData domain.VCenterNetwork) error
	GetVCenterNetworkID(ctx context.Context, networkID, vcenterServer string) (string, error)
	GetVCenterNetworkIDByName(ctx context.Context, networkName, vcenterServer string) (string, error)
	StoreVCenterCluster(ctx context.Context, clusterData domain.VCenterCluster) error
	GetVCenterClusterID(ctx context.Context, clusterID, vcenterServer string) (string, error)
	StoreVCenterHostIP(ctx context.Context, hostIPData domain.VCenterHostIP) error
	StoreVCenterHostNIC(ctx context.Context, hostNICData domain.VCenterHostNIC) error
	StoreVCenterVirtualSwitch(ctx context.Context, virtualSwitchData domain.VCenterVirtualSwitch) error
	StoreVMDatastoreRelation(ctx context.Context, relationData domain.VMDatastoreRelation) error
	StoreVMNetworkRelation(ctx context.Context, relationData domain.VMNetworkRelation) error
	StoreHostDatastoreRelation(ctx context.Context, relationData domain.HostDatastoreRelation) error
	GetVCenterClusters(ctx context.Context, datacenterID string) ([]domain.VCenterCluster, error)
	GetVCenterHostIPs(ctx context.Context, hostID string) ([]domain.VCenterHostIP, error)
	GetVCenterHostNICs(ctx context.Context, hostID string) ([]domain.VCenterHostNIC, error)
	GetVCenterVirtualSwitches(ctx context.Context, hostID string) ([]domain.VCenterVirtualSwitch, error)
	GetVMDatastoreRelations(ctx context.Context, vmID string) ([]domain.VMDatastoreRelation, error)
	GetVMNetworkRelations(ctx context.Context, vmID string) ([]domain.VMNetworkRelation, error)
	GetHostDatastoreRelations(ctx context.Context, hostID string) ([]domain.HostDatastoreRelation, error)

	UpdateAssetPorts(ctx context.Context, assetID domain.AssetUUID, ports []types.Port) error
	GetByFilter(ctx context.Context, assetFilter domain.AssetFilters, limit, offset int, sortOptions ...domain.SortOption) ([]domain.AssetDomain, int, error)
	Update(ctx context.Context, asset domain.AssetDomain) error
	DeleteAssets(ctx context.Context, params domain.DeleteParams) (int, error)
	GetByIDs(ctx context.Context, assetUUIDs []domain.AssetUUID) ([]domain.AssetDomain, error)
	GetByIDsWithSort(ctx context.Context, assetUUIDs []domain.AssetUUID, sortOptions ...domain.SortOption) ([]domain.AssetDomain, error)
	ExportAssets(ctx context.Context, assetIDs []domain.AssetUUID, exportType domain.ExportType, selectedColumns []string) (*domain.ExportData, error)
	GetDistinctOSNames(ctx context.Context) ([]string, error)

	// Dashboard methods
	GetAssetCount(ctx context.Context) (int, error)
	GetAssetCountByScanner(ctx context.Context) ([]domain.ScannerTypeCount, error)
	GetLoggingCompletedByOS(ctx context.Context) ([]domain.OSLoggingStats, error)
	GetAssetsPerSource(ctx context.Context) ([]domain.AssetSourceStats, int, error)

	// Vulnerability methods
	StoreVulnerability(ctx context.Context, vulnerability domain.Vulnerability) (*domain.Vulnerability, error)
	StoreAssetVulnerability(ctx context.Context, assetVuln domain.AssetVulnerability) error
	StoreNessusScan(ctx context.Context, scan domain.NessusScan) error
}
