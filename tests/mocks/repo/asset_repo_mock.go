package mocks

import (
	"context"

	"github.com/stretchr/testify/mock"
	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/domain"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/adapter/storage/types"
)

// MockAssetRepo is a mock implementation of the assetPort.Repo interface
type MockAssetRepo struct {
	mock.Mock
}

func (m *MockAssetRepo) Create(ctx context.Context, asset domain.AssetDomain, scannerType ...string) (domain.AssetUUID, error) {
	args := m.Called(ctx, asset, scannerType)
	return args.Get(0).(domain.AssetUUID), args.Error(1)
}

func (m *MockAssetRepo) Get(ctx context.Context, assetFilter domain.AssetFilters) ([]domain.AssetDomain, error) {
	args := m.Called(ctx, assetFilter)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]domain.AssetDomain), args.Error(1)
}

func (m *MockAssetRepo) GetByIDs(ctx context.Context, assetUUIDs []domain.AssetUUID) ([]domain.AssetDomain, error) {
	args := m.Called(ctx, assetUUIDs)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]domain.AssetDomain), args.Error(1)
}

func (m *MockAssetRepo) GetByIDsWithSort(ctx context.Context, assetUUIDs []domain.AssetUUID, sortOptions ...domain.SortOption) ([]domain.AssetDomain, error) {
	args := m.Called(ctx, assetUUIDs, sortOptions)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]domain.AssetDomain), args.Error(1)
}

func (m *MockAssetRepo) GetByFilter(ctx context.Context, assetFilter domain.AssetFilters, limit, offset int, sortOptions ...domain.SortOption) ([]domain.AssetDomain, int, error) {
	args := m.Called(ctx, assetFilter, limit, offset, sortOptions)
	if args.Get(0) == nil {
		return nil, args.Get(1).(int), args.Error(2)
	}
	return args.Get(0).([]domain.AssetDomain), args.Get(1).(int), args.Error(2)
}

func (m *MockAssetRepo) Update(ctx context.Context, asset domain.AssetDomain) error {
	args := m.Called(ctx, asset)
	return args.Error(0)
}

func (m *MockAssetRepo) DeleteAssets(ctx context.Context, params domain.DeleteParams) (int, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(int), args.Error(1)
}

func (m *MockAssetRepo) LinkAssetToScanJob(ctx context.Context, assetID domain.AssetUUID, scanJobID int64) error {
	args := m.Called(ctx, assetID, scanJobID)
	return args.Error(0)
}

func (m *MockAssetRepo) StoreVMwareVM(ctx context.Context, vmData domain.VMwareVM) error {
	args := m.Called(ctx, vmData)
	return args.Error(0)
}

func (m *MockAssetRepo) UpdateAssetPorts(ctx context.Context, assetID domain.AssetUUID, ports []types.Port) error {
	args := m.Called(ctx, assetID, ports)
	return args.Error(0)
}

func (m *MockAssetRepo) ExportAssets(ctx context.Context, assetIDs []domain.AssetUUID, exportType domain.ExportType, selectedColumns []string) (*domain.ExportData, error) {
	args := m.Called(ctx, assetIDs, exportType, selectedColumns)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.ExportData), args.Error(1)
}

func (m *MockAssetRepo) GetDistinctOSNames(ctx context.Context) ([]string, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]string), args.Error(1)
}

// Dashboard methods
func (m *MockAssetRepo) GetAssetCount(ctx context.Context) (int, error) {
	args := m.Called(ctx)
	return args.Get(0).(int), args.Error(1)
}

func (m *MockAssetRepo) GetAssetCountByScanner(ctx context.Context) ([]domain.ScannerTypeCount, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]domain.ScannerTypeCount), args.Error(1)
}

func (m *MockAssetRepo) GetLoggingCompletedByOS(ctx context.Context) ([]domain.OSLoggingStats, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]domain.OSLoggingStats), args.Error(1)
}

func (m *MockAssetRepo) GetAssetsPerSource(ctx context.Context) ([]domain.AssetSourceStats, int, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Get(1).(int), args.Error(2)
	}
	return args.Get(0).([]domain.AssetSourceStats), args.Get(1).(int), args.Error(2)
}

// Vulnerability methods
func (m *MockAssetRepo) StoreVulnerability(ctx context.Context, vulnerability domain.Vulnerability) (*domain.Vulnerability, error) {
	args := m.Called(ctx, vulnerability)
	return args.Get(0).(*domain.Vulnerability), args.Error(1)
}

func (m *MockAssetRepo) StoreAssetVulnerability(ctx context.Context, assetVuln domain.AssetVulnerability) error {
	args := m.Called(ctx, assetVuln)
	return args.Error(0)
}

func (m *MockAssetRepo) StoreNessusScan(ctx context.Context, scan domain.NessusScan) error {
	args := m.Called(ctx, scan)
	return args.Error(0)
}

// New vCenter infrastructure methods
func (m *MockAssetRepo) StoreVCenterDatacenter(ctx context.Context, datacenterData domain.VCenterDatacenter) error {
	args := m.Called(ctx, datacenterData)
	return args.Error(0)
}

func (m *MockAssetRepo) GetVCenterDatacenterID(ctx context.Context, datacenterID, vcenterServer string) (string, error) {
	args := m.Called(ctx, datacenterID, vcenterServer)
	return args.String(0), args.Error(1)
}

func (m *MockAssetRepo) StoreVCenterHost(ctx context.Context, hostData domain.VCenterHost) error {
	args := m.Called(ctx, hostData)
	return args.Error(0)
}

func (m *MockAssetRepo) GetVCenterHostID(ctx context.Context, hostID, vcenterServer string) (string, error) {
	args := m.Called(ctx, hostID, vcenterServer)
	return args.String(0), args.Error(1)
}

func (m *MockAssetRepo) StoreVCenterDatastore(ctx context.Context, datastoreData domain.VCenterDatastore) error {
	args := m.Called(ctx, datastoreData)
	return args.Error(0)
}

func (m *MockAssetRepo) StoreVCenterNetwork(ctx context.Context, networkData domain.VCenterNetwork) error {
	args := m.Called(ctx, networkData)
	return args.Error(0)
}

func (m *MockAssetRepo) GetVCenterNetworkID(ctx context.Context, networkID, vcenterServer string) (string, error) {
	args := m.Called(ctx, networkID, vcenterServer)
	return args.String(0), args.Error(1)
}

func (m *MockAssetRepo) GetVCenterNetworkIDByName(ctx context.Context, networkName, vcenterServer string) (string, error) {
	args := m.Called(ctx, networkName, vcenterServer)
	return args.String(0), args.Error(1)
}

func (m *MockAssetRepo) StoreVCenterCluster(ctx context.Context, clusterData domain.VCenterCluster) error {
	args := m.Called(ctx, clusterData)
	return args.Error(0)
}

func (m *MockAssetRepo) GetVCenterClusterID(ctx context.Context, clusterID, vcenterServer string) (string, error) {
	args := m.Called(ctx, clusterID, vcenterServer)
	return args.String(0), args.Error(1)
}

func (m *MockAssetRepo) StoreVCenterHostIP(ctx context.Context, hostIPData domain.VCenterHostIP) error {
	args := m.Called(ctx, hostIPData)
	return args.Error(0)
}

func (m *MockAssetRepo) StoreVCenterHostNIC(ctx context.Context, hostNICData domain.VCenterHostNIC) error {
	args := m.Called(ctx, hostNICData)
	return args.Error(0)
}

func (m *MockAssetRepo) StoreVCenterVirtualSwitch(ctx context.Context, virtualSwitchData domain.VCenterVirtualSwitch) error {
	args := m.Called(ctx, virtualSwitchData)
	return args.Error(0)
}

func (m *MockAssetRepo) StoreVMDatastoreRelation(ctx context.Context, relationData domain.VMDatastoreRelation) error {
	args := m.Called(ctx, relationData)
	return args.Error(0)
}

func (m *MockAssetRepo) StoreVMNetworkRelation(ctx context.Context, relationData domain.VMNetworkRelation) error {
	args := m.Called(ctx, relationData)
	return args.Error(0)
}

func (m *MockAssetRepo) StoreHostDatastoreRelation(ctx context.Context, relationData domain.HostDatastoreRelation) error {
	args := m.Called(ctx, relationData)
	return args.Error(0)
}

func (m *MockAssetRepo) GetVCenterClusters(ctx context.Context, datacenterID string) ([]domain.VCenterCluster, error) {
	args := m.Called(ctx, datacenterID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]domain.VCenterCluster), args.Error(1)
}

func (m *MockAssetRepo) GetVCenterHostIPs(ctx context.Context, hostID string) ([]domain.VCenterHostIP, error) {
	args := m.Called(ctx, hostID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]domain.VCenterHostIP), args.Error(1)
}

func (m *MockAssetRepo) GetVCenterHostNICs(ctx context.Context, hostID string) ([]domain.VCenterHostNIC, error) {
	args := m.Called(ctx, hostID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]domain.VCenterHostNIC), args.Error(1)
}

func (m *MockAssetRepo) GetVCenterVirtualSwitches(ctx context.Context, hostID string) ([]domain.VCenterVirtualSwitch, error) {
	args := m.Called(ctx, hostID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]domain.VCenterVirtualSwitch), args.Error(1)
}

func (m *MockAssetRepo) GetVMDatastoreRelations(ctx context.Context, vmID string) ([]domain.VMDatastoreRelation, error) {
	args := m.Called(ctx, vmID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]domain.VMDatastoreRelation), args.Error(1)
}

func (m *MockAssetRepo) GetVMNetworkRelations(ctx context.Context, vmID string) ([]domain.VMNetworkRelation, error) {
	args := m.Called(ctx, vmID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]domain.VMNetworkRelation), args.Error(1)
}

func (m *MockAssetRepo) GetHostDatastoreRelations(ctx context.Context, hostID string) ([]domain.HostDatastoreRelation, error) {
	args := m.Called(ctx, hostID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]domain.HostDatastoreRelation), args.Error(1)
}

func (m *MockAssetRepo) GetVCenterDatastoreID(ctx context.Context, datastoreID, vcenterServer string) (string, error) {
	args := m.Called(ctx, datastoreID, vcenterServer)
	return args.String(0), args.Error(1)
}
