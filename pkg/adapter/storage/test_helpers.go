package storage

import (
	"context"

	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/domain"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/adapter/storage/types"
	"gorm.io/gorm"
)

// Test helper functions to expose private methods for testing

// TestMapFieldToDBColumn exposes mapFieldToDBColumn for testing
func TestMapFieldToDBColumn(field string) ColumnMapping {
	return mapFieldToDBColumn(field)
}

// TestAssetRepository wraps assetRepository to access private methods in tests
type TestAssetRepository struct {
	*assetRepository
}

// NewTestAssetRepo creates a new test asset repository wrapper
func NewTestAssetRepo(db *gorm.DB) *TestAssetRepository {
	return &TestAssetRepository{
		assetRepository: &assetRepository{db: db},
	}
}

// TestUpdateOrUndeleteIP exposes updateOrUndeleteIP for testing
func (r *TestAssetRepository) TestUpdateOrUndeleteIP(tx *gorm.DB, foundIP types.IPs, newAssetID string, macAddress string) error {
	return r.updateOrUndeleteIP(tx, foundIP, newAssetID, macAddress)
}

// TestCheckActiveIPsAssets exposes checkActiveIPsAssets for testing
func (r *TestAssetRepository) TestCheckActiveIPsAssets(ctx context.Context, activeIPs []types.IPs) (bool, error) {
	return r.checkActiveIPsAssets(ctx, activeIPs)
}

// TestFindMACForIP exposes findMACForIP for testing
func (r *TestAssetRepository) TestFindMACForIP(ip string, validAssetIPs []domain.AssetIP) string {
	return r.findMACForIP(ip, validAssetIPs)
}

// TestHandleExistingIPs exposes handleExistingIPs for testing
func (r *TestAssetRepository) TestHandleExistingIPs(ctx context.Context, tx *gorm.DB, asset domain.AssetDomain,
	validAssetIPs []domain.AssetIP, assetRecord *types.Assets, assetIPs []*types.IPs, portRecords []types.Port) error {
	return r.handleExistingIPs(ctx, tx, asset, validAssetIPs, assetRecord, assetIPs, portRecords)
}

// TestUpdateDiscoveredBy exposes updateDiscoveredBy for testing
func (r *TestAssetRepository) TestUpdateDiscoveredBy(currentDiscoveredBy, scannerType string) string {
	return r.updateDiscoveredBy(currentDiscoveredBy, scannerType)
}
