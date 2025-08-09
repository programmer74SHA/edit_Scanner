package storage_test

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/go-sql-driver/mysql"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gormMysql "gorm.io/driver/mysql"
	"gorm.io/gorm"

	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/domain"
	assetPort "gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/port"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/adapter/storage"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/adapter/storage/types"
	domainFixtures "gitlab.apk-group.net/siem/backend/asset-discovery/tests/fixtures/domain"
)

type AssetRepoTestSuite struct {
	db     *sql.DB
	gormDB *gorm.DB
	mock   sqlmock.Sqlmock
	repo   assetPort.Repo
	ctx    context.Context
	now    time.Time
}

func setupAssetRepoTest(t *testing.T) *AssetRepoTestSuite {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)

	gormDB, err := gorm.Open(gormMysql.New(gormMysql.Config{
		Conn:                      db,
		SkipInitializeWithVersion: true,
	}), &gorm.Config{})
	require.NoError(t, err)

	repo := storage.NewAssetRepo(gormDB)
	ctx := context.Background()
	now := time.Now()

	return &AssetRepoTestSuite{
		db:     db,
		gormDB: gormDB,
		mock:   mock,
		repo:   repo,
		ctx:    ctx,
		now:    now,
	}
}

func (suite *AssetRepoTestSuite) tearDown() {
	suite.db.Close()
}

func TestAssetRepository_Create_Success(t *testing.T) {
	suite := setupAssetRepoTest(t)
	defer suite.tearDown()

	// Arrange
	assetDomain := domainFixtures.NewTestAssetDomain()

	// Mock the hostname check query first (must return 0 for no duplicates)
	suite.mock.ExpectQuery("SELECT count\\(\\*\\) FROM `assets`").
		WithArgs(assetDomain.Hostname).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

	// Mock the transaction
	suite.mock.ExpectBegin()

	// Mock the asset INSERT - GORM fields in actual order
	// Risk is now stored as int directly without conversion
	expectedRisk := 1
	expectedAssetValue := float64(assetDomain.AssetValue)

	// Account for normalization that will happen in the mapper
	expectedOSName := "Linux"
	expectedAssetType := "Unknown"

	suite.mock.ExpectExec("INSERT INTO `assets`").
		WithArgs(
			assetDomain.ID.String(),
			sqlmock.AnyArg(),
			&assetDomain.Name,
			&assetDomain.Domain,
			assetDomain.Hostname,
			&expectedOSName,
			&assetDomain.OSVersion,
			&assetDomain.Description,
			expectedAssetType,
			sqlmock.AnyArg(),
			expectedRisk,
			&assetDomain.LoggingCompleted,
			expectedAssetValue,
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	suite.mock.ExpectCommit()

	// Act
	assetID, err := suite.repo.Create(suite.ctx, assetDomain)

	// Assert
	assert.NoError(t, err)
	assert.NotEqual(t, domain.AssetUUID{}, assetID)
	assert.NoError(t, suite.mock.ExpectationsWereMet())
}

func TestAssetRepository_Create_DuplicateHostname(t *testing.T) {
	suite := setupAssetRepoTest(t)
	defer suite.tearDown()

	// Arrange
	assetDomain := domainFixtures.NewTestAssetDomain()

	// Mock the hostname check query to return 1 (duplicate exists)
	suite.mock.ExpectQuery("SELECT count\\(\\*\\) FROM `assets`").
		WithArgs(assetDomain.Hostname).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))

	// Act
	assetID, err := suite.repo.Create(suite.ctx, assetDomain)

	// Assert
	assert.Error(t, err)
	assert.Equal(t, domain.ErrHostnameAlreadyExists, err)
	assert.Equal(t, domain.AssetUUID{}, assetID)
	assert.NoError(t, suite.mock.ExpectationsWereMet())
}

func TestAssetRepository_Create_DatabaseConnectionError(t *testing.T) {
	suite := setupAssetRepoTest(t)
	defer suite.tearDown()

	// Arrange
	assetDomain := domainFixtures.NewTestAssetDomain()

	// Mock database connection error on hostname check
	suite.mock.ExpectQuery("SELECT count\\(\\*\\) FROM `assets`").
		WithArgs(assetDomain.Hostname).
		WillReturnError(sql.ErrConnDone)

	// Act
	assetID, err := suite.repo.Create(suite.ctx, assetDomain)

	// Assert
	assert.Error(t, err)
	assert.Equal(t, sql.ErrConnDone, err)
	assert.Equal(t, domain.AssetUUID{}, assetID)
	assert.NoError(t, suite.mock.ExpectationsWereMet())
}

func TestAssetRepository_Create_WithAssetIPs(t *testing.T) {
	suite := setupAssetRepoTest(t)
	defer suite.tearDown()

	// Arrange
	assetDomain := domainFixtures.NewTestAssetDomainWithIPs([]string{"192.168.1.100", "10.0.0.50"})

	// Mock hostname check
	suite.mock.ExpectQuery("SELECT count\\(\\*\\) FROM `assets`").
		WithArgs(assetDomain.Hostname).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

	// Mock the transaction
	suite.mock.ExpectBegin()

	// Mock the IP existence check that happens when there are IPs
	suite.mock.ExpectQuery("SELECT \\* FROM `ips` WHERE ip_address IN \\(\\?\\,\\?\\)").
		WithArgs("192.168.1.100", "10.0.0.50").
		WillReturnRows(sqlmock.NewRows([]string{"id", "asset_id", "ip_address", "mac_address", "created_at", "updated_at", "deleted_at"}))

	// Mock asset insert
	// Risk is now stored as int directly without conversion
	expectedRisk := 1 // domain risk 1 stays as 1
	expectedAssetValue := float64(assetDomain.AssetValue)

	expectedOSName := "Linux"
	expectedAssetType := "Unknown"

	suite.mock.ExpectExec("INSERT INTO `assets`").
		WithArgs(
			assetDomain.ID.String(),
			sqlmock.AnyArg(),
			&assetDomain.Name,
			&assetDomain.Domain,
			assetDomain.Hostname,
			&expectedOSName,
			&assetDomain.OSVersion,
			&assetDomain.Description,
			expectedAssetType,
			sqlmock.AnyArg(),
			expectedRisk,
			&assetDomain.LoggingCompleted,
			expectedAssetValue,
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	// Mock asset IP inserts
	for range assetDomain.AssetIPs {
		suite.mock.ExpectExec("INSERT INTO `ips`").
			WithArgs(
				sqlmock.AnyArg(),
				assetDomain.ID.String(), // AssetID
				sqlmock.AnyArg(),        // IP
				sqlmock.AnyArg(),        // MACAddress
				sqlmock.AnyArg(),
				sqlmock.AnyArg(),
				sqlmock.AnyArg(), // CreatedAt
				sqlmock.AnyArg(), // UpdatedAt
				sqlmock.AnyArg(), // DeletedAt
			).
			WillReturnResult(sqlmock.NewResult(1, 1))
	}

	suite.mock.ExpectCommit()

	// Act
	assetID, err := suite.repo.Create(suite.ctx, assetDomain)

	// Assert
	assert.NoError(t, err)
	assert.NotEqual(t, domain.AssetUUID{}, assetID)
	assert.NoError(t, suite.mock.ExpectationsWereMet())
}

func TestAssetRepository_Create_WithPorts(t *testing.T) {
	suite := setupAssetRepoTest(t)
	defer suite.tearDown()

	// Arrange
	assetDomain := domainFixtures.NewTestAssetDomainWithPorts(3)

	// Mock hostname check
	suite.mock.ExpectQuery("SELECT count\\(\\*\\) FROM `assets`").
		WithArgs(assetDomain.Hostname).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

	// Mock the transaction
	suite.mock.ExpectBegin()

	// Mock asset insert
	// Risk is now stored as int directly without conversion
	expectedRisk := 1 // domain risk 1 stays as 1
	expectedAssetValue := float64(assetDomain.AssetValue)

	expectedOSName := "Linux"
	expectedAssetType := "Unknown"

	suite.mock.ExpectExec("INSERT INTO `assets`").
		WithArgs(
			assetDomain.ID.String(),
			sqlmock.AnyArg(),
			&assetDomain.Name,
			&assetDomain.Domain,
			assetDomain.Hostname,
			&expectedOSName,
			&assetDomain.OSVersion,
			&assetDomain.Description,
			expectedAssetType,
			sqlmock.AnyArg(),
			expectedRisk,
			&assetDomain.LoggingCompleted,
			expectedAssetValue,
			sqlmock.AnyArg(), // created_at
			sqlmock.AnyArg(), // updated_at
			sqlmock.AnyArg(), // deleted_at
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	// Mock port inserts - based on actual Port structure in types
	for range assetDomain.Ports {
		suite.mock.ExpectExec("INSERT INTO `ports`").
			WithArgs(
				sqlmock.AnyArg(),        // ID
				assetDomain.ID.String(), // AssetID
				sqlmock.AnyArg(),        // PortNumber
				sqlmock.AnyArg(),        // Protocol
				sqlmock.AnyArg(),        // State
				sqlmock.AnyArg(),        // ServiceName (pointer)
				sqlmock.AnyArg(),        // ServiceVersion (pointer)
				sqlmock.AnyArg(),        // Description (pointer)
				sqlmock.AnyArg(),        // DeletedAt (pointer)
				sqlmock.AnyArg(),        // DiscoveredAt
			).
			WillReturnResult(sqlmock.NewResult(1, 1))
	}

	suite.mock.ExpectCommit()

	// Act
	assetID, err := suite.repo.Create(suite.ctx, assetDomain)

	// Assert
	assert.NoError(t, err)
	assert.NotEqual(t, domain.AssetUUID{}, assetID)
	assert.NoError(t, suite.mock.ExpectationsWereMet())
}

func TestAssetRepository_Create_InvalidAssetData(t *testing.T) {
	suite := setupAssetRepoTest(t)
	defer suite.tearDown()

	// Arrange
	assetDomain := domainFixtures.NewTestAssetDomain()
	assetDomain.Hostname = "" // Invalid empty hostname

	// Mock hostname check (empty hostname won't match)
	suite.mock.ExpectQuery("SELECT count\\(\\*\\) FROM `assets`").
		WithArgs("").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

	// Mock transaction and constraint violation
	suite.mock.ExpectBegin()
	suite.mock.ExpectExec("INSERT INTO `assets`").
		WillReturnError(&mysql.MySQLError{Number: 1048, Message: "Column 'hostname' cannot be null"})
	suite.mock.ExpectRollback()

	// Act
	assetID, err := suite.repo.Create(suite.ctx, assetDomain)

	// Assert
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot be null")
	assert.Equal(t, domain.AssetUUID{}, assetID)
	assert.NoError(t, suite.mock.ExpectationsWereMet())
}

func TestAssetRepository_Create_ContextCancellation(t *testing.T) {
	suite := setupAssetRepoTest(t)
	defer suite.tearDown()

	// Arrange
	assetDomain := domainFixtures.NewTestAssetDomain()

	// Mock context cancellation error during the hostname check
	suite.mock.ExpectQuery("SELECT count\\(\\*\\) FROM `assets`").
		WithArgs(assetDomain.Hostname).
		WillReturnError(context.Canceled)

	// Act
	assetID, err := suite.repo.Create(suite.ctx, assetDomain)

	// Assert
	assert.Error(t, err)
	assert.Equal(t, context.Canceled, err)
	assert.Equal(t, domain.AssetUUID{}, assetID)
	assert.NoError(t, suite.mock.ExpectationsWereMet())
}

// Tests for GetByIDs method
func TestAssetRepository_GetByIDs_Success(t *testing.T) {
	suite := setupAssetRepoTest(t)
	defer suite.tearDown()

	// Arrange
	assetID1 := uuid.New()
	assetUUIDs := []domain.AssetUUID{assetID1}

	// Mock the main query with a simplified expected result
	assetRows := sqlmock.NewRows([]string{
		"id", "name", "domain", "hostname", "os_name", "os_version",
		"description", "asset_type", "risk", "logging_completed",
		"asset_value", "created_at", "updated_at", "deleted_at",
	}).
		AddRow(assetID1.String(), "Test Asset 1", "test.local", "host1",
			"Ubuntu", "20.04", "Test description 1", "Server", 1, false,
			100, suite.now, suite.now, nil)

	suite.mock.ExpectQuery("SELECT \\* FROM `assets`").
		WithArgs(assetID1.String()).
		WillReturnRows(assetRows)

	// Mock the AssetIPs preload query
	ipsRows := sqlmock.NewRows([]string{"id", "asset_id", "ip_address", "scan_type", "created_at", "updated_at", "deleted_at"})
	suite.mock.ExpectQuery("SELECT \\* FROM `ips`").
		WithArgs(assetID1.String()).
		WillReturnRows(ipsRows)

	// Mock the Ports preload query
	portsRows := sqlmock.NewRows([]string{"id", "asset_id", "port_number", "service_name", "protocol", "state", "scan_type", "banner", "version", "created_at", "updated_at", "deleted_at"})
	suite.mock.ExpectQuery("SELECT \\* FROM `ports`").
		WithArgs(assetID1.String()).
		WillReturnRows(portsRows)

	// Mock the VMwareVMs preload query
	vmwareRows := sqlmock.NewRows([]string{"id", "asset_id", "vm_id", "vm_name", "created_at", "updated_at"})
	suite.mock.ExpectQuery("SELECT \\* FROM `vmware_vms`").
		WithArgs(assetID1.String()).
		WillReturnRows(vmwareRows)

	// Mock the scanner types query
	scannerRows := sqlmock.NewRows([]string{"asset_id", "scan_type"}).
		AddRow(assetID1.String(), "nmap")

	suite.mock.ExpectQuery("SELECT asj\\.asset_id, scanners\\.scan_type FROM asset_scan_jobs asj").
		WithArgs(assetID1.String()).
		WillReturnRows(scannerRows)

	// Act
	assets, err := suite.repo.GetByIDs(suite.ctx, assetUUIDs)

	// Assert
	assert.NoError(t, err)
	assert.Len(t, assets, 1)
	assert.Equal(t, "Test Asset 1", assets[0].Name)
	assert.NoError(t, suite.mock.ExpectationsWereMet())
}

func TestAssetRepository_GetByIDs_EmptyList(t *testing.T) {
	suite := setupAssetRepoTest(t)
	defer suite.tearDown()

	// Act
	assets, err := suite.repo.GetByIDs(suite.ctx, []domain.AssetUUID{})

	// Assert
	assert.NoError(t, err)
	assert.Len(t, assets, 0)
	assert.NoError(t, suite.mock.ExpectationsWereMet())
}

func TestAssetRepository_GetByIDs_DatabaseError(t *testing.T) {
	suite := setupAssetRepoTest(t)
	defer suite.tearDown()

	// Arrange
	assetID := uuid.New()
	assetUUIDs := []domain.AssetUUID{assetID}

	// Mock database error
	suite.mock.ExpectQuery("SELECT \\* FROM `assets`").
		WithArgs(assetID.String()).
		WillReturnError(sql.ErrConnDone)

	// Act
	assets, err := suite.repo.GetByIDs(suite.ctx, assetUUIDs)

	// Assert
	assert.Error(t, err)
	assert.Equal(t, sql.ErrConnDone, err)
	assert.Nil(t, assets)
	assert.NoError(t, suite.mock.ExpectationsWereMet())
}

// Tests for Get method
func TestAssetRepository_Get_WithFilters(t *testing.T) {
	suite := setupAssetRepoTest(t)
	defer suite.tearDown()

	// Arrange
	filters := domain.AssetFilters{
		Hostname: "test-host",
	}

	assetID := uuid.New()
	assetRows := sqlmock.NewRows([]string{
		"id", "name", "domain", "hostname", "os_name", "os_version",
		"description", "asset_type", "risk", "logging_completed",
		"asset_value", "created_at", "updated_at", "deleted_at",
	}).AddRow(assetID.String(), "Test Asset", "test.local", "test-host",
		"Ubuntu", "20.04", "Test description", "Server", 1, false,
		100, suite.now, suite.now, nil)

	suite.mock.ExpectQuery("SELECT \\* FROM `assets`").
		WithArgs("%test-host%").
		WillReturnRows(assetRows)

	// Mock scanner types query
	suite.mock.ExpectQuery("SELECT asj").
		WillReturnRows(sqlmock.NewRows([]string{"asset_id", "scan_type"}))

	// Mock asset IPs query (called by getAssetIPs)
	suite.mock.ExpectQuery("SELECT \\* FROM `ips`").
		WithArgs(assetID.String()).
		WillReturnRows(sqlmock.NewRows([]string{"id", "asset_id", "ip_address", "mac_address", "created_at", "updated_at", "deleted_at"}))

	// Act
	assets, err := suite.repo.Get(suite.ctx, filters)

	// Assert
	assert.NoError(t, err)
	assert.Len(t, assets, 1)
	assert.Equal(t, "Test Asset", assets[0].Name)
	assert.Equal(t, "test-host", assets[0].Hostname)
	assert.NoError(t, suite.mock.ExpectationsWereMet())
}

func TestAssetRepository_Get_NoResults(t *testing.T) {
	suite := setupAssetRepoTest(t)
	defer suite.tearDown()

	// Arrange
	filters := domain.AssetFilters{
		Hostname: "nonexistent",
	}

	suite.mock.ExpectQuery("SELECT \\* FROM `assets`").
		WithArgs("%nonexistent%").
		WillReturnRows(sqlmock.NewRows([]string{"id", "name", "domain", "hostname", "os_name", "os_version", "description", "asset_type", "risk", "logging_completed", "asset_value", "created_at", "updated_at", "deleted_at"}))

	// Act
	assets, err := suite.repo.Get(suite.ctx, filters)

	// Assert
	assert.NoError(t, err)
	assert.Len(t, assets, 0)
	assert.NoError(t, suite.mock.ExpectationsWereMet())
}

// Tests for Update method
func TestAssetRepository_Update_Success(t *testing.T) {
	suite := setupAssetRepoTest(t)
	defer suite.tearDown()

	// Arrange
	assetDomain := domainFixtures.NewTestAssetDomain()
	assetDomain.Name = "Updated Asset"
	assetDomain.Description = "Updated description"

	// Mock hostname uniqueness check
	suite.mock.ExpectQuery("SELECT count\\(\\*\\) FROM `assets` WHERE hostname = \\? AND id != \\? AND deleted_at IS NULL").
		WithArgs(assetDomain.Hostname, assetDomain.ID.String()).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

	// Mock transaction
	suite.mock.ExpectBegin()

	// Mock current IPs query (happens inside transaction)
	suite.mock.ExpectQuery("SELECT \\* FROM `ips` WHERE asset_id = \\? AND deleted_at IS NULL").
		WithArgs(assetDomain.ID.String()).
		WillReturnRows(sqlmock.NewRows([]string{"id", "asset_id", "ip_address", "mac_address", "created_at", "updated_at", "deleted_at"}))

	// Mock asset update (simplified)
	suite.mock.ExpectExec("UPDATE `assets`").
		WillReturnResult(sqlmock.NewResult(1, 1))

	// Mock current ports query
	suite.mock.ExpectQuery("SELECT \\* FROM `ports` WHERE asset_id = \\? AND deleted_at IS NULL").
		WithArgs(assetDomain.ID.String()).
		WillReturnRows(sqlmock.NewRows([]string{"id", "asset_id", "port", "protocol", "service", "created_at", "updated_at", "deleted_at"}))

	suite.mock.ExpectCommit()

	// Act
	err := suite.repo.Update(suite.ctx, assetDomain)

	// Assert
	assert.NoError(t, err)
	assert.NoError(t, suite.mock.ExpectationsWereMet())
}

func TestAssetRepository_Update_DatabaseError(t *testing.T) {
	suite := setupAssetRepoTest(t)
	defer suite.tearDown()

	// Arrange
	assetDomain := domainFixtures.NewTestAssetDomain()

	// Mock hostname uniqueness check with error
	suite.mock.ExpectQuery("SELECT count\\(\\*\\) FROM `assets` WHERE hostname = \\? AND id != \\? AND deleted_at IS NULL").
		WithArgs(assetDomain.Hostname, assetDomain.ID.String()).
		WillReturnError(sql.ErrConnDone)

	// Act
	err := suite.repo.Update(suite.ctx, assetDomain)

	// Assert
	assert.Error(t, err)
	assert.Equal(t, sql.ErrConnDone, err)
	assert.NoError(t, suite.mock.ExpectationsWereMet())
}

// Tests for UpdateAssetPorts method
func TestAssetRepository_UpdateAssetPorts_Success(t *testing.T) {
	suite := setupAssetRepoTest(t)
	defer suite.tearDown()

	// Arrange
	assetID := uuid.New()
	ports := []types.Port{
		{
			ID:         uuid.New().String(),
			AssetID:    assetID.String(),
			PortNumber: 80,
			Protocol:   "TCP",
			State:      "Up",
		},
	}

	// Mock transaction
	suite.mock.ExpectBegin()

	// Mock marking existing ports as deleted
	suite.mock.ExpectExec("UPDATE `ports`").
		WillReturnResult(sqlmock.NewResult(1, 1))

	// Mock creating new ports
	suite.mock.ExpectExec("INSERT INTO `ports`").
		WillReturnResult(sqlmock.NewResult(1, 1))

	suite.mock.ExpectCommit()

	// Act
	err := suite.repo.UpdateAssetPorts(suite.ctx, assetID, ports)

	// Assert
	assert.NoError(t, err)
	assert.NoError(t, suite.mock.ExpectationsWereMet())
}

func TestAssetRepository_UpdateAssetPorts_TransactionError(t *testing.T) {
	suite := setupAssetRepoTest(t)
	defer suite.tearDown()

	// Arrange
	assetID := uuid.New()
	ports := []types.Port{}

	// Mock transaction begin error
	suite.mock.ExpectBegin().WillReturnError(sql.ErrConnDone)

	// Act
	err := suite.repo.UpdateAssetPorts(suite.ctx, assetID, ports)

	// Assert
	assert.Error(t, err)
	assert.Equal(t, sql.ErrConnDone, err)
	assert.NoError(t, suite.mock.ExpectationsWereMet())
}

// Tests for LinkAssetToScanJob method
func TestAssetRepository_LinkAssetToScanJob_Success(t *testing.T) {
	suite := setupAssetRepoTest(t)
	defer suite.tearDown()

	// Arrange
	assetID := uuid.New()
	scanJobID := int64(123)

	// Mock transaction
	suite.mock.ExpectBegin()

	// Mock the asset-scanjob link insertion
	suite.mock.ExpectExec("INSERT INTO `asset_scan_jobs`").
		WithArgs(
			assetID.String(), // AssetID
			scanJobID,        // ScanJobID
			sqlmock.AnyArg(), // discovered_at
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	suite.mock.ExpectCommit()

	// Act
	err := suite.repo.LinkAssetToScanJob(suite.ctx, assetID, scanJobID)

	// Assert
	assert.NoError(t, err)
	assert.NoError(t, suite.mock.ExpectationsWereMet())
}

func TestAssetRepository_LinkAssetToScanJob_DatabaseError(t *testing.T) {
	suite := setupAssetRepoTest(t)
	defer suite.tearDown()

	// Arrange
	assetID := uuid.New()
	scanJobID := int64(123)

	// Mock transaction
	suite.mock.ExpectBegin()

	// Mock database error
	suite.mock.ExpectExec("INSERT INTO `asset_scan_jobs`").
		WillReturnError(sql.ErrConnDone)

	suite.mock.ExpectRollback()

	// Act
	err := suite.repo.LinkAssetToScanJob(suite.ctx, assetID, scanJobID)

	// Assert
	assert.Error(t, err)
	assert.Equal(t, sql.ErrConnDone, err)
	assert.NoError(t, suite.mock.ExpectationsWereMet())
}

// Tests for StoreVMwareVM method
func TestAssetRepository_StoreVMwareVM_NewVM(t *testing.T) {
	suite := setupAssetRepoTest(t)
	defer suite.tearDown()

	// Arrange
	vmData := domain.VMwareVM{
		VMID:         "vm-123",
		AssetID:      uuid.New().String(),
		VMName:       "Test VM",
		Hypervisor:   "ESXi 7.0",
		CPUCount:     4,
		MemoryMB:     8192,
		DiskSizeGB:   100,
		PowerState:   "On",
		LastSyncedAt: time.Now(),
	}

	// Mock VM existence check
	suite.mock.ExpectQuery("SELECT count\\(\\*\\) FROM `vmware_vms`").
		WithArgs(vmData.VMID).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

	// Mock transaction
	suite.mock.ExpectBegin()

	// Mock VM insertion
	suite.mock.ExpectExec("INSERT INTO `vmware_vms`").
		WithArgs(
			vmData.VMID,
			vmData.AssetID,
			vmData.VMName,
			sqlmock.AnyArg(), // host_id
			sqlmock.AnyArg(), // cluster_id
			vmData.Hypervisor,
			int(vmData.CPUCount),
			int(vmData.MemoryMB),
			vmData.DiskSizeGB,
			vmData.PowerState,
			sqlmock.AnyArg(), // LastSyncedAt
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	suite.mock.ExpectCommit()

	// Act
	err := suite.repo.StoreVMwareVM(suite.ctx, vmData)

	// Assert
	assert.NoError(t, err)
	assert.NoError(t, suite.mock.ExpectationsWereMet())
}

func TestAssetRepository_StoreVMwareVM_UpdateExisting(t *testing.T) {
	suite := setupAssetRepoTest(t)
	defer suite.tearDown()

	// Arrange
	vmData := domain.VMwareVM{
		VMID:         "vm-123",
		AssetID:      uuid.New().String(),
		VMName:       "Updated VM",
		Hypervisor:   "ESXi 7.0",
		CPUCount:     8,
		MemoryMB:     16384,
		DiskSizeGB:   200,
		PowerState:   "On",
		LastSyncedAt: time.Now(),
	}

	// Mock VM existence check (returns 1, meaning VM exists)
	suite.mock.ExpectQuery("SELECT count\\(\\*\\) FROM `vmware_vms`").
		WithArgs(vmData.VMID).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))

	// Mock transaction
	suite.mock.ExpectBegin()

	// Mock VM update
	suite.mock.ExpectExec("UPDATE `vmware_vms`").
		WithArgs(
			vmData.AssetID,       // asset_id
			int(vmData.CPUCount), // cpu_count
			vmData.DiskSizeGB,    // disk_size_gb
			sqlmock.AnyArg(),     // host_id
			vmData.Hypervisor,    // hypervisor
			sqlmock.AnyArg(),     // last_synced_at
			int(vmData.MemoryMB), // memory_mb
			vmData.PowerState,    // power_state
			vmData.VMName,        // vm_name
			vmData.VMID,          // WHERE vm_id condition
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	suite.mock.ExpectCommit()

	// Act
	err := suite.repo.StoreVMwareVM(suite.ctx, vmData)

	// Assert
	assert.NoError(t, err)
	assert.NoError(t, suite.mock.ExpectationsWereMet())
}

func TestAssetRepository_StoreVMwareVM_CheckExistenceError(t *testing.T) {
	suite := setupAssetRepoTest(t)
	defer suite.tearDown()

	// Arrange
	vmData := domain.VMwareVM{
		VMID:    "vm-123",
		AssetID: uuid.New().String(),
		VMName:  "Test VM",
	}

	// Mock VM existence check with error
	suite.mock.ExpectQuery("SELECT count\\(\\*\\) FROM `vmware_vms`").
		WithArgs(vmData.VMID).
		WillReturnError(sql.ErrConnDone)

	// Act
	err := suite.repo.StoreVMwareVM(suite.ctx, vmData)

	// Assert
	assert.Error(t, err)
	assert.Equal(t, sql.ErrConnDone, err)
	assert.NoError(t, suite.mock.ExpectationsWereMet())
}

func TestAssetRepository_StoreVMwareVM_DatabaseError(t *testing.T) {
	suite := setupAssetRepoTest(t)
	defer suite.tearDown()

	// Arrange
	vmData := domainFixtures.NewTestVMwareVM("test-asset-id")

	// Mock database error on check query
	suite.mock.ExpectQuery("SELECT count\\(\\*\\) FROM `vmware_vms`").
		WithArgs(vmData.VMID).
		WillReturnError(sql.ErrConnDone)

	// Act
	err := suite.repo.StoreVMwareVM(suite.ctx, vmData)

	// Assert
	assert.Error(t, err)
	assert.Equal(t, sql.ErrConnDone, err)
	assert.NoError(t, suite.mock.ExpectationsWereMet())
}

func TestAssetRepository_GetByFilter_Success(t *testing.T) {
	suite := setupAssetRepoTest(t)
	defer suite.tearDown()

	// Arrange
	filter := domain.AssetFilters{
		Name: "test-asset",
	}

	// Mock count query
	suite.mock.ExpectQuery("SELECT count\\(\\*\\) FROM `assets`").
		WithArgs("%test-asset%", "%test-asset%").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))

	// Mock assets query with preloads
	suite.mock.ExpectQuery("SELECT \\* FROM `assets`").
		WithArgs("%test-asset%", "%test-asset%", 10).
		WillReturnRows(sqlmock.NewRows([]string{"id", "name", "hostname", "deleted_at"}).
			AddRow("550e8400-e29b-41d4-a716-446655440000", "test-asset", "test-host", nil))

	// Mock ips query
	suite.mock.ExpectQuery("SELECT \\* FROM `ips`").
		WithArgs("550e8400-e29b-41d4-a716-446655440000").
		WillReturnRows(sqlmock.NewRows([]string{"id", "asset_id", "ip_address", "deleted_at"}))

	// Mock ports query
	suite.mock.ExpectQuery("SELECT \\* FROM `ports`").
		WithArgs("550e8400-e29b-41d4-a716-446655440000").
		WillReturnRows(sqlmock.NewRows([]string{"id", "asset_id", "port_number", "protocol", "deleted_at"}))

	// Mock vmware_vms query
	suite.mock.ExpectQuery("SELECT \\* FROM `vmware_vms`").
		WithArgs("550e8400-e29b-41d4-a716-446655440000").
		WillReturnRows(sqlmock.NewRows([]string{"id", "asset_id", "vm_id", "vm_name"}))

	// Mock scanner types query
	suite.mock.ExpectQuery("SELECT asj\\.asset_id, scanners\\.scan_type").
		WithArgs(sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"asset_id", "scan_type"}))

	// Act
	assets, total, err := suite.repo.GetByFilter(suite.ctx, filter, 10, 0)

	// Assert
	assert.NoError(t, err)
	assert.Equal(t, 1, total)
	assert.Len(t, assets, 1)
	assert.NoError(t, suite.mock.ExpectationsWereMet())
}

func TestAssetRepository_GetByFilter_DatabaseError(t *testing.T) {
	suite := setupAssetRepoTest(t)
	defer suite.tearDown()

	// Arrange
	filter := domain.AssetFilters{Name: "test"}

	// Mock database error on count query
	suite.mock.ExpectQuery("SELECT count\\(\\*\\) FROM `assets`").
		WithArgs("%test%", "%test%").
		WillReturnError(sql.ErrConnDone)

	// Act
	assets, total, err := suite.repo.GetByFilter(suite.ctx, filter, 10, 0)

	// Assert
	assert.Error(t, err)
	assert.Equal(t, sql.ErrConnDone, err)
	assert.Equal(t, 0, total)
	assert.Nil(t, assets)
	assert.NoError(t, suite.mock.ExpectationsWereMet())
}

func TestAssetRepository_DeleteAssets_SingleUUID(t *testing.T) {
	suite := setupAssetRepoTest(t)
	defer suite.tearDown()

	// Arrange
	assetID := uuid.New()
	params := domain.DeleteParams{
		UUID: &assetID,
	}

	// Mock delete operation
	suite.mock.ExpectBegin()
	suite.mock.ExpectExec("UPDATE `assets` SET `deleted_at`").
		WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), assetID).
		WillReturnResult(sqlmock.NewResult(1, 1))
	suite.mock.ExpectCommit()

	// Act
	deletedCount, err := suite.repo.DeleteAssets(suite.ctx, params)

	// Assert
	assert.NoError(t, err)
	assert.Equal(t, 1, deletedCount)
	assert.NoError(t, suite.mock.ExpectationsWereMet())
}

func TestAssetRepository_DeleteAssets_MultipeUUIDs(t *testing.T) {
	suite := setupAssetRepoTest(t)
	defer suite.tearDown()

	// Arrange
	assetIDs := []domain.AssetUUID{uuid.New(), uuid.New()}
	params := domain.DeleteParams{
		UUIDs: assetIDs,
	}

	// Mock transaction
	suite.mock.ExpectBegin()
	suite.mock.ExpectExec("UPDATE `assets` SET `deleted_at`").
		WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), assetIDs[0], assetIDs[1]).
		WillReturnResult(sqlmock.NewResult(1, 2))
	suite.mock.ExpectCommit()

	// Act
	deletedCount, err := suite.repo.DeleteAssets(suite.ctx, params)

	// Assert
	assert.NoError(t, err)
	assert.Equal(t, 2, deletedCount)
	assert.NoError(t, suite.mock.ExpectationsWereMet())
}

func TestAssetRepository_DeleteAssets_WithFilters(t *testing.T) {
	suite := setupAssetRepoTest(t)
	defer suite.tearDown()

	// Arrange
	filters := domain.AssetFilters{
		Name: "test",
	}
	params := domain.DeleteParams{
		Filters: &filters,
	}

	// Mock transaction
	suite.mock.ExpectBegin()
	suite.mock.ExpectExec("UPDATE `assets` SET `deleted_at`").
		WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), "%test%", "%test%").
		WillReturnResult(sqlmock.NewResult(1, 3))
	suite.mock.ExpectCommit()

	// Act
	deletedCount, err := suite.repo.DeleteAssets(suite.ctx, params)

	// Assert
	assert.NoError(t, err)
	assert.Equal(t, 3, deletedCount)
	assert.NoError(t, suite.mock.ExpectationsWereMet())
}

func TestAssetRepository_DeleteAssets_DatabaseError(t *testing.T) {
	suite := setupAssetRepoTest(t)
	defer suite.tearDown()

	// Arrange
	assetID := uuid.New()
	params := domain.DeleteParams{
		UUID: &assetID,
	}

	// Mock database error
	suite.mock.ExpectBegin()
	suite.mock.ExpectExec("UPDATE `assets` SET `deleted_at`").
		WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), assetID).
		WillReturnError(sql.ErrConnDone)
	suite.mock.ExpectRollback()

	// Act
	deletedCount, err := suite.repo.DeleteAssets(suite.ctx, params)

	// Assert
	assert.Error(t, err)
	assert.Equal(t, sql.ErrConnDone, err)
	assert.Equal(t, 0, deletedCount)
	assert.NoError(t, suite.mock.ExpectationsWereMet())
}

func TestAssetRepository_ExportAssets_FullExport(t *testing.T) {
	suite := setupAssetRepoTest(t)
	defer suite.tearDown()

	// Arrange
	assetIDs := []domain.AssetUUID{uuid.New()}

	// Mock assets query
	suite.mock.ExpectQuery("SELECT \\* FROM `assets`").
		WithArgs(assetIDs[0].String()).
		WillReturnRows(sqlmock.NewRows([]string{"id", "name"}).
			AddRow(assetIDs[0].String(), "test-asset"))

	// Mock ports query
	suite.mock.ExpectQuery("SELECT ports\\.\\* FROM `ports`").
		WithArgs(assetIDs[0].String()).
		WillReturnRows(sqlmock.NewRows([]string{"id", "asset_id", "port_number"}).
			AddRow("port-1", assetIDs[0].String(), 80))

	// Mock vmware_vms query
	suite.mock.ExpectQuery("SELECT vmware_vms\\.\\* FROM `vmware_vms`").
		WithArgs(assetIDs[0].String()).
		WillReturnRows(sqlmock.NewRows([]string{"id", "asset_id", "vm_name"}).
			AddRow("vm-1", assetIDs[0].String(), "test-vm"))

	// Mock ips query
	suite.mock.ExpectQuery("SELECT ips\\.\\* FROM `ips`").
		WithArgs(assetIDs[0].String()).
		WillReturnRows(sqlmock.NewRows([]string{"id", "asset_id", "ip_address"}).
			AddRow("ip-1", assetIDs[0].String(), "192.168.1.1"))

	// Act
	exportData, err := suite.repo.ExportAssets(suite.ctx, assetIDs, domain.FullExport, nil)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, exportData)
	assert.Len(t, exportData.Assets, 1)
	assert.Len(t, exportData.Ports, 1)
	assert.Len(t, exportData.VMwareVMs, 1)
	assert.Len(t, exportData.AssetIPs, 1)
	assert.NoError(t, suite.mock.ExpectationsWereMet())
}

func TestAssetRepository_ExportAssets_SelectiveExport(t *testing.T) {
	suite := setupAssetRepoTest(t)
	defer suite.tearDown()

	// Arrange
	assetIDs := []domain.AssetUUID{uuid.New()}
	selectedColumns := []string{"assets.name", "assets.hostname"}

	// Mock assets query with selected columns
	suite.mock.ExpectQuery("SELECT name,hostname,id FROM `assets`").
		WithArgs(assetIDs[0].String()).
		WillReturnRows(sqlmock.NewRows([]string{"name", "hostname", "id"}).
			AddRow("test-asset", "test-host", assetIDs[0].String()))

	// Act
	exportData, err := suite.repo.ExportAssets(suite.ctx, assetIDs, domain.SelectedColumnsExport, selectedColumns)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, exportData)
	assert.Len(t, exportData.Assets, 1)
	assert.Len(t, exportData.Ports, 0)
	assert.Len(t, exportData.VMwareVMs, 0)
	assert.Len(t, exportData.AssetIPs, 0)
	assert.NoError(t, suite.mock.ExpectationsWereMet())
}

func TestAssetRepository_ExportAssets_AllAssets(t *testing.T) {
	suite := setupAssetRepoTest(t)
	defer suite.tearDown()

	// Arrange - empty asset IDs means export all
	var assetIDs []domain.AssetUUID

	// Mock assets query without WHERE clause
	suite.mock.ExpectQuery("SELECT \\* FROM `assets`").
		WillReturnRows(sqlmock.NewRows([]string{"id", "name"}).
			AddRow("asset-1", "test-asset-1").
			AddRow("asset-2", "test-asset-2"))

	// Mock ports query without WHERE clause
	suite.mock.ExpectQuery("SELECT ports\\.\\* FROM `ports`").
		WillReturnRows(sqlmock.NewRows([]string{"id", "asset_id", "port_number"}))

	// Mock vmware_vms query without WHERE clause
	suite.mock.ExpectQuery("SELECT vmware_vms\\.\\* FROM `vmware_vms`").
		WillReturnRows(sqlmock.NewRows([]string{"id", "asset_id", "vm_name"}))

	// Mock ips query without WHERE clause
	suite.mock.ExpectQuery("SELECT ips\\.\\* FROM `ips`").
		WillReturnRows(sqlmock.NewRows([]string{"id", "asset_id", "ip_address"}))

	// Act
	exportData, err := suite.repo.ExportAssets(suite.ctx, assetIDs, domain.FullExport, nil)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, exportData)
	assert.Len(t, exportData.Assets, 2)
	assert.NoError(t, suite.mock.ExpectationsWereMet())
}

func TestAssetRepository_ExportAssets_DatabaseError(t *testing.T) {
	suite := setupAssetRepoTest(t)
	defer suite.tearDown()

	// Arrange
	assetIDs := []domain.AssetUUID{uuid.New()}

	// Mock database error on assets query
	suite.mock.ExpectQuery("SELECT \\* FROM `assets`").
		WithArgs(assetIDs[0].String()).
		WillReturnError(sql.ErrConnDone)

	// Act
	exportData, err := suite.repo.ExportAssets(suite.ctx, assetIDs, domain.FullExport, nil)

	// Assert
	assert.Error(t, err)
	assert.Equal(t, sql.ErrConnDone, err)
	assert.Nil(t, exportData)
	assert.NoError(t, suite.mock.ExpectationsWereMet())
}

func TestAssetRepository_GetDistinctOSNames_Success(t *testing.T) {
	suite := setupAssetRepoTest(t)
	defer suite.tearDown()

	// Mock query for distinct OS names
	suite.mock.ExpectQuery("SELECT DISTINCT os_name FROM `assets`").
		WillReturnRows(sqlmock.NewRows([]string{"os_name"}).
			AddRow("Windows 10").
			AddRow("Ubuntu 20.04").
			AddRow("CentOS 7"))

	// Act
	osNames, err := suite.repo.GetDistinctOSNames(suite.ctx)

	// Assert
	assert.NoError(t, err)
	assert.Len(t, osNames, 3)
	assert.Contains(t, osNames, "Windows 10")
	assert.Contains(t, osNames, "Ubuntu 20.04")
	assert.Contains(t, osNames, "CentOS 7")
	assert.NoError(t, suite.mock.ExpectationsWereMet())
}

func TestAssetRepository_GetDistinctOSNames_DatabaseError(t *testing.T) {
	suite := setupAssetRepoTest(t)
	defer suite.tearDown()

	// Mock database error
	suite.mock.ExpectQuery("SELECT DISTINCT os_name FROM `assets`").
		WillReturnError(sql.ErrConnDone)

	// Act
	osNames, err := suite.repo.GetDistinctOSNames(suite.ctx)

	// Assert
	assert.Error(t, err)
	assert.Equal(t, sql.ErrConnDone, err)
	assert.Nil(t, osNames)
	assert.NoError(t, suite.mock.ExpectationsWereMet())
}

// Dashboard methods tests
func TestAssetRepository_GetAssetCount_Success(t *testing.T) {
	suite := setupAssetRepoTest(t)
	defer suite.tearDown()

	// Mock count query
	suite.mock.ExpectQuery("SELECT count\\(\\*\\) FROM `assets`").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(42))

	// Act
	count, err := suite.repo.GetAssetCount(suite.ctx)

	// Assert
	assert.NoError(t, err)
	assert.Equal(t, 42, count)
	assert.NoError(t, suite.mock.ExpectationsWereMet())
}

func TestAssetRepository_GetAssetCount_DatabaseError(t *testing.T) {
	suite := setupAssetRepoTest(t)
	defer suite.tearDown()

	// Mock database error
	suite.mock.ExpectQuery("SELECT count\\(\\*\\) FROM `assets`").
		WillReturnError(sql.ErrConnDone)

	// Act
	count, err := suite.repo.GetAssetCount(suite.ctx)

	// Assert
	assert.Error(t, err)
	assert.Equal(t, sql.ErrConnDone, err)
	assert.Equal(t, 0, count)
	assert.NoError(t, suite.mock.ExpectationsWereMet())
}

func TestAssetRepository_GetAssetCountByScanner_Success(t *testing.T) {
	suite := setupAssetRepoTest(t)
	defer suite.tearDown()

	// Mock query for asset count by scanner
	suite.mock.ExpectQuery("SELECT COALESCE\\(s\\.scan_type, 'Unknown'\\) as scan_type, COUNT\\(a\\.id\\) as count").
		WillReturnRows(sqlmock.NewRows([]string{"scan_type", "count"}).
			AddRow("nmap", 15).
			AddRow("nessus", 10).
			AddRow("Unknown", 5))

	// Act
	scannerCounts, err := suite.repo.GetAssetCountByScanner(suite.ctx)

	// Assert
	assert.NoError(t, err)
	assert.Len(t, scannerCounts, 3)
	assert.Equal(t, "nmap", scannerCounts[0].Source)
	assert.Equal(t, 15, scannerCounts[0].Count)
	assert.NoError(t, suite.mock.ExpectationsWereMet())
}

func TestAssetRepository_GetAssetCountByScanner_DatabaseError(t *testing.T) {
	suite := setupAssetRepoTest(t)
	defer suite.tearDown()

	// Mock database error
	suite.mock.ExpectQuery("SELECT COALESCE\\(s\\.scan_type, 'Unknown'\\) as scan_type, COUNT\\(a\\.id\\) as count").
		WillReturnError(sql.ErrConnDone)

	// Act
	scannerCounts, err := suite.repo.GetAssetCountByScanner(suite.ctx)

	// Assert
	assert.Error(t, err)
	assert.Equal(t, sql.ErrConnDone, err)
	assert.Nil(t, scannerCounts)
	assert.NoError(t, suite.mock.ExpectationsWereMet())
}

func TestAssetRepository_GetLoggingCompletedByOS_Success(t *testing.T) {
	suite := setupAssetRepoTest(t)
	defer suite.tearDown()

	// Mock query for logging completed by OS
	suite.mock.ExpectQuery("SELECT.*COALESCE\\(NULLIF\\(os_name, ''\\), 'Unknown'\\) as os_name.*").
		WillReturnRows(sqlmock.NewRows([]string{"os_name", "completed_count", "total_count"}).
			AddRow("Windows", 8, 10).
			AddRow("Linux", 12, 15).
			AddRow("Unknown", 3, 5))

	// Act
	osStats, err := suite.repo.GetLoggingCompletedByOS(suite.ctx)

	// Assert
	assert.NoError(t, err)
	assert.Len(t, osStats, 3)
	assert.Equal(t, "Windows", osStats[0].Source)
	assert.Equal(t, 8, osStats[0].Count)
	assert.Equal(t, 10, osStats[0].Total)
	assert.NoError(t, suite.mock.ExpectationsWereMet())
}

func TestAssetRepository_GetLoggingCompletedByOS_DatabaseError(t *testing.T) {
	suite := setupAssetRepoTest(t)
	defer suite.tearDown()

	// Mock database error
	suite.mock.ExpectQuery("SELECT.*COALESCE\\(NULLIF\\(os_name, ''\\), 'Unknown'\\) as os_name.*").
		WillReturnError(sql.ErrConnDone)

	// Act
	osStats, err := suite.repo.GetLoggingCompletedByOS(suite.ctx)

	// Assert
	assert.Error(t, err)
	assert.Equal(t, sql.ErrConnDone, err)
	assert.Nil(t, osStats)
	assert.NoError(t, suite.mock.ExpectationsWereMet())
}

func TestAssetRepository_GetAssetsPerSource_Success(t *testing.T) {
	suite := setupAssetRepoTest(t)
	defer suite.tearDown()

	// Mock query for assets per source
	suite.mock.ExpectQuery("SELECT.*COALESCE\\(NULLIF\\(os_name, ''\\), 'Unknown'\\) as os_name.*").
		WillReturnRows(sqlmock.NewRows([]string{"os_name", "count"}).
			AddRow("Windows", 40).
			AddRow("Linux", 30).
			AddRow("macOS", 20).
			AddRow("Unknown", 10))

	// Act
	sourceStats, totalCount, err := suite.repo.GetAssetsPerSource(suite.ctx)

	// Assert
	assert.NoError(t, err)
	assert.Equal(t, 100, totalCount)
	assert.Len(t, sourceStats, 4)
	assert.Equal(t, "Windows", sourceStats[0].Source)
	assert.Equal(t, 40, sourceStats[0].Percent)
	assert.Equal(t, "Linux", sourceStats[1].Source)
	assert.Equal(t, 30, sourceStats[1].Percent)
	assert.NoError(t, suite.mock.ExpectationsWereMet())
}

func TestAssetRepository_GetAssetsPerSource_DatabaseError(t *testing.T) {
	suite := setupAssetRepoTest(t)
	defer suite.tearDown()

	// Mock database error
	suite.mock.ExpectQuery("SELECT.*COALESCE\\(NULLIF\\(os_name, ''\\), 'Unknown'\\) as os_name.*").
		WillReturnError(sql.ErrConnDone)

	// Act
	sourceStats, totalCount, err := suite.repo.GetAssetsPerSource(suite.ctx)

	// Assert
	assert.Error(t, err)
	assert.Equal(t, sql.ErrConnDone, err)
	assert.Equal(t, 0, totalCount)
	assert.Nil(t, sourceStats)
	assert.NoError(t, suite.mock.ExpectationsWereMet())
}

// Vulnerability methods tests
func TestAssetRepository_StoreVulnerability_NewVulnerability(t *testing.T) {
	suite := setupAssetRepoTest(t)
	defer suite.tearDown()

	// Arrange
	vulnerability := domainFixtures.NewTestVulnerability()

	// Mock transaction
	suite.mock.ExpectBegin()

	// Mock check for existing vulnerability
	suite.mock.ExpectQuery("SELECT \\* FROM `vulnerabilities`").
		WithArgs(vulnerability.PluginID, 1).
		WillReturnError(gorm.ErrRecordNotFound)

	// Mock create new vulnerability
	suite.mock.ExpectExec("INSERT INTO `vulnerabilities`").
		WithArgs(
			sqlmock.AnyArg(),
			vulnerability.PluginID,
			vulnerability.PluginName,
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	suite.mock.ExpectCommit()

	// Act
	storedVuln, err := suite.repo.StoreVulnerability(suite.ctx, vulnerability)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, storedVuln)
	assert.Equal(t, vulnerability.PluginID, storedVuln.PluginID)
	assert.NoError(t, suite.mock.ExpectationsWereMet())
}

func TestAssetRepository_StoreVulnerability_UpdateExisting(t *testing.T) {
	suite := setupAssetRepoTest(t)
	defer suite.tearDown()

	// Arrange
	vulnerability := domainFixtures.NewTestVulnerability()
	existingID := uuid.New().String()

	// Mock transaction
	suite.mock.ExpectBegin()

	// Mock finding existing vulnerability
	suite.mock.ExpectQuery("SELECT \\* FROM `vulnerabilities`").
		WithArgs(vulnerability.PluginID, 1).
		WillReturnRows(sqlmock.NewRows([]string{"id", "plugin_id", "plugin_name", "created_at", "updated_at"}).
			AddRow(existingID, vulnerability.PluginID, "old-name", suite.now, suite.now))

	// Mock update existing vulnerability
	suite.mock.ExpectExec("UPDATE `vulnerabilities`").
		WithArgs(
			sqlmock.AnyArg(),
			vulnerability.PluginName,
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
			existingID,
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	suite.mock.ExpectCommit()

	// Act
	storedVuln, err := suite.repo.StoreVulnerability(suite.ctx, vulnerability)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, storedVuln)
	assert.Equal(t, existingID, storedVuln.ID.String())
	assert.Equal(t, vulnerability.PluginID, storedVuln.PluginID)
	assert.NoError(t, suite.mock.ExpectationsWereMet())
}

func TestAssetRepository_StoreVulnerability_DatabaseError(t *testing.T) {
	suite := setupAssetRepoTest(t)
	defer suite.tearDown()

	// Arrange
	vulnerability := domainFixtures.NewTestVulnerability()

	// Mock transaction
	suite.mock.ExpectBegin()

	// Mock database error
	suite.mock.ExpectQuery("SELECT \\* FROM `vulnerabilities`").
		WithArgs(vulnerability.PluginID, 1).
		WillReturnError(sql.ErrConnDone)

	suite.mock.ExpectRollback()

	// Act
	storedVuln, err := suite.repo.StoreVulnerability(suite.ctx, vulnerability)

	// Assert
	assert.Error(t, err)
	assert.Equal(t, sql.ErrConnDone, err)
	assert.Nil(t, storedVuln)
	assert.NoError(t, suite.mock.ExpectationsWereMet())
}

func TestAssetRepository_StoreAssetVulnerability_Success(t *testing.T) {
	suite := setupAssetRepoTest(t)
	defer suite.tearDown()

	// Arrange
	assetVuln := domainFixtures.NewTestAssetVulnerability()

	// Mock check for existing asset vulnerability (not found)
	suite.mock.ExpectQuery("SELECT \\* FROM `asset_vulnerabilities`").
		WithArgs(assetVuln.AssetID.String(), assetVuln.VulnerabilityID.String(), assetVuln.Port, assetVuln.Protocol, 1).
		WillReturnError(gorm.ErrRecordNotFound)

	// Mock transaction for create
	suite.mock.ExpectBegin()

	// Mock create asset vulnerability
	suite.mock.ExpectExec("INSERT INTO `asset_vulnerabilities`").
		WithArgs(
			sqlmock.AnyArg(),                   // id
			assetVuln.AssetID.String(),         // asset_id
			assetVuln.VulnerabilityID.String(), // vulnerability_id
			sqlmock.AnyArg(),                   // port_id
			assetVuln.Port,                     // port
			assetVuln.Protocol,                 // protocol
			assetVuln.PluginOutput,             // plugin_output
			sqlmock.AnyArg(),                   // status
			sqlmock.AnyArg(),                   // scan_id
			sqlmock.AnyArg(),                   // host_id_nessus
			sqlmock.AnyArg(),                   // vuln_index_nessus
			sqlmock.AnyArg(),                   // severity_index_nessus
			sqlmock.AnyArg(),                   // count_nessus
			sqlmock.AnyArg(),                   // created_at
			sqlmock.AnyArg(),                   // updated_at
			sqlmock.AnyArg(),                   // first_detected
			sqlmock.AnyArg(),                   // last_detected
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	suite.mock.ExpectCommit()

	// Act
	err := suite.repo.StoreAssetVulnerability(suite.ctx, assetVuln)

	// Assert
	assert.NoError(t, err)
	assert.NoError(t, suite.mock.ExpectationsWereMet())
}

func TestAssetRepository_StoreAssetVulnerability_DatabaseError(t *testing.T) {
	suite := setupAssetRepoTest(t)
	defer suite.tearDown()

	// Arrange
	assetVuln := domainFixtures.NewTestAssetVulnerability()

	// Mock check for existing asset vulnerability (database error)
	suite.mock.ExpectQuery("SELECT \\* FROM `asset_vulnerabilities`").
		WithArgs(assetVuln.AssetID.String(), assetVuln.VulnerabilityID.String(), assetVuln.Port, assetVuln.Protocol, 1).
		WillReturnError(sql.ErrConnDone)

	suite.mock.ExpectBegin()

	// Mock create failure too
	suite.mock.ExpectExec("INSERT INTO `asset_vulnerabilities`").
		WithArgs(
			sqlmock.AnyArg(),                   // id
			assetVuln.AssetID.String(),         // asset_id
			assetVuln.VulnerabilityID.String(), // vulnerability_id
			sqlmock.AnyArg(),                   // port_id
			assetVuln.Port,                     // port
			assetVuln.Protocol,                 // protocol
			assetVuln.PluginOutput,             // plugin_output
			sqlmock.AnyArg(),                   // status
			sqlmock.AnyArg(),                   // scan_id
			sqlmock.AnyArg(),                   // host_id_nessus
			sqlmock.AnyArg(),                   // vuln_index_nessus
			sqlmock.AnyArg(),                   // severity_index_nessus
			sqlmock.AnyArg(),                   // count_nessus
			sqlmock.AnyArg(),                   // created_at
			sqlmock.AnyArg(),                   // updated_at
			sqlmock.AnyArg(),                   // first_detected
			sqlmock.AnyArg(),                   // last_detected
		).
		WillReturnError(sql.ErrConnDone)

	suite.mock.ExpectRollback()

	// Act
	err := suite.repo.StoreAssetVulnerability(suite.ctx, assetVuln)

	// Assert
	assert.Error(t, err)
	assert.Equal(t, sql.ErrConnDone, err)
	assert.NoError(t, suite.mock.ExpectationsWereMet())
}

func TestAssetRepository_StoreNessusScan_Success(t *testing.T) {
	suite := setupAssetRepoTest(t)
	defer suite.tearDown()

	// Arrange
	nessusScan := domainFixtures.NewTestNessusScan()

	// Mock FirstOrCreate - first check if exists (not found)
	suite.mock.ExpectQuery("SELECT \\* FROM `nessus_scans`").
		WithArgs(nessusScan.ID, nessusScan.ID, 1).
		WillReturnRows(sqlmock.NewRows([]string{"id", "uuid", "name", "status", "scanner_name", "targets", "scan_start_time", "scan_end_time", "folder_id", "owner_id", "policy_name", "created_at", "updated_at"}))

	// Mock transaction for create
	suite.mock.ExpectBegin()

	// Mock create nessus scan
	suite.mock.ExpectExec("INSERT INTO `nessus_scans`").
		WithArgs(
			sqlmock.AnyArg(),   // uuid
			nessusScan.Name,    // name
			nessusScan.Status,  // status
			sqlmock.AnyArg(),   // scanner_name
			nessusScan.Targets, // targets
			sqlmock.AnyArg(),   // scan_start_time
			sqlmock.AnyArg(),   // scan_end_time
			sqlmock.AnyArg(),   // folder_id
			sqlmock.AnyArg(),   // owner_id
			sqlmock.AnyArg(),   // policy_name
			sqlmock.AnyArg(),   // created_at
			sqlmock.AnyArg(),   // updated_at
			nessusScan.ID,      // id
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	suite.mock.ExpectCommit()

	// Act
	err := suite.repo.StoreNessusScan(suite.ctx, nessusScan)

	// Assert
	assert.NoError(t, err)
	assert.NoError(t, suite.mock.ExpectationsWereMet())
}

func TestAssetRepository_StoreNessusScan_DatabaseError(t *testing.T) {
	suite := setupAssetRepoTest(t)
	defer suite.tearDown()

	// Arrange
	nessusScan := domainFixtures.NewTestNessusScan()

	// Mock FirstOrCreate - database error on check
	suite.mock.ExpectQuery("SELECT \\* FROM `nessus_scans`").
		WithArgs(nessusScan.ID, nessusScan.ID, 1).
		WillReturnError(sql.ErrConnDone)

	// Act
	err := suite.repo.StoreNessusScan(suite.ctx, nessusScan)

	// Assert
	assert.Error(t, err)
	assert.Equal(t, sql.ErrConnDone, err)
	assert.NoError(t, suite.mock.ExpectationsWereMet())
}

// Test error scenarios in existing methods
func TestAssetRepository_UpdateAssetPorts_TransactionBeginError(t *testing.T) {
	suite := setupAssetRepoTest(t)
	defer suite.tearDown()

	// Arrange
	assetID := uuid.New()
	ports := []types.Port{
		{
			ID:         uuid.New().String(),
			AssetID:    assetID.String(),
			PortNumber: 80,
			Protocol:   "tcp",
		},
	}

	// Mock transaction begin error
	suite.mock.ExpectBegin().WillReturnError(sql.ErrConnDone)

	// Act
	err := suite.repo.UpdateAssetPorts(suite.ctx, assetID, ports)

	// Assert
	assert.Error(t, err)
	assert.Equal(t, sql.ErrConnDone, err)
	assert.NoError(t, suite.mock.ExpectationsWereMet())
}

func TestAssetRepository_UpdateAssetPorts_DeleteError(t *testing.T) {
	suite := setupAssetRepoTest(t)
	defer suite.tearDown()

	// Arrange
	assetID := uuid.New()
	ports := []types.Port{}

	// Mock transaction
	suite.mock.ExpectBegin()

	// Mock delete error
	suite.mock.ExpectExec("UPDATE `ports` SET `deleted_at`").
		WithArgs(sqlmock.AnyArg(), assetID.String()).
		WillReturnError(sql.ErrConnDone)

	suite.mock.ExpectRollback()

	// Act
	err := suite.repo.UpdateAssetPorts(suite.ctx, assetID, ports)

	// Assert
	assert.Error(t, err)
	assert.Equal(t, sql.ErrConnDone, err)
	assert.NoError(t, suite.mock.ExpectationsWereMet())
}

func TestAssetRepository_Create_WithScannerType(t *testing.T) {
	suite := setupAssetRepoTest(t)
	defer suite.tearDown()

	// Arrange
	assetDomain := domainFixtures.NewTestAssetDomain()
	scannerType := "nmap"

	// Mock hostname check
	suite.mock.ExpectQuery("SELECT count\\(\\*\\) FROM `assets`").
		WithArgs(assetDomain.Hostname).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

	// Mock transaction
	suite.mock.ExpectBegin()

	// Mock asset INSERT
	expectedRisk := 1
	expectedAssetValue := float64(assetDomain.AssetValue)

	expectedOSName := "Linux"
	expectedAssetType := "Unknown"

	suite.mock.ExpectExec("INSERT INTO `assets`").
		WithArgs(
			assetDomain.ID.String(),
			sqlmock.AnyArg(),
			&assetDomain.Name,
			&assetDomain.Domain,
			assetDomain.Hostname,
			&expectedOSName,
			&assetDomain.OSVersion,
			&assetDomain.Description,
			expectedAssetType,
			sqlmock.AnyArg(),
			expectedRisk,
			&assetDomain.LoggingCompleted,
			expectedAssetValue,
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	suite.mock.ExpectCommit()

	// Act
	assetID, err := suite.repo.Create(suite.ctx, assetDomain, scannerType)

	// Assert
	assert.NoError(t, err)
	assert.Equal(t, assetDomain.ID, assetID)
	assert.NoError(t, suite.mock.ExpectationsWereMet())
}

func TestAssetRepository_ValidateIP_EdgeCases(t *testing.T) {
	suite := setupAssetRepoTest(t)
	defer suite.tearDown()

	// Test various IP validation scenarios
	testCases := []struct {
		name     string
		ip       string
		expected bool
	}{
		{"Empty IP", "", false},
		{"Valid IP", "192.168.1.1", true},
		{"Invalid IP - no dots", "192168111", false},
		{"Invalid IP - too many octets", "192.168.1.1.1", false},
		{"Invalid IP - negative number", "192.168.-1.1", false},
		{"Invalid IP - too large number", "192.168.256.1", false},
		{"Invalid IP - non-numeric", "192.168.abc.1", false},
		{"Hostname not IP", "example.com", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			asset := domainFixtures.NewTestAssetDomainWithIPs([]string{tc.ip})

			if tc.expected {
				// Mock successful creation for valid IPs
				suite.mock.ExpectQuery("SELECT count\\(\\*\\) FROM `assets`").
					WithArgs(asset.Hostname).
					WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

				suite.mock.ExpectBegin()
				suite.mock.ExpectQuery("SELECT \\* FROM `ips`").
					WillReturnRows(sqlmock.NewRows([]string{"id", "asset_id", "ip_address", "mac_address", "created_at", "updated_at", "deleted_at"}))

				suite.mock.ExpectExec("INSERT INTO `assets`").
					WillReturnResult(sqlmock.NewResult(1, 1))

				if tc.ip != "" {
					suite.mock.ExpectExec("INSERT INTO `ips`").
						WillReturnResult(sqlmock.NewResult(1, 1))
				}

				suite.mock.ExpectCommit()

				_, err := suite.repo.Create(suite.ctx, asset)
				assert.NoError(t, err)
			} else if tc.ip != "" {
				// For invalid IPs, they should be filtered out and not cause errors
				suite.mock.ExpectQuery("SELECT count\\(\\*\\) FROM `assets`").
					WithArgs(asset.Hostname).
					WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

				suite.mock.ExpectBegin()
				suite.mock.ExpectExec("INSERT INTO `assets`").
					WillReturnResult(sqlmock.NewResult(1, 1))
				suite.mock.ExpectCommit()

				_, err := suite.repo.Create(suite.ctx, asset)
				assert.NoError(t, err) // Should not error, just filter out invalid IPs
			}
		})
	}
}

// Test helper functions

// TestMapFieldToDBColumn tests the mapFieldToDBColumn function comprehensively
func TestMapFieldToDBColumn(t *testing.T) {
	tests := []struct {
		name           string
		field          string
		expectedColumn string
		expectedTable  string
		requiresJoin   bool
		joinType       string
	}{
		// Special scanner field mappings
		{
			name:           "scanner type field",
			field:          "scanner.type",
			expectedColumn: "scanners.scan_type",
			expectedTable:  "scanners",
			requiresJoin:   true,
			joinType:       "LEFT",
		},

		// Table-prefixed fields
		{
			name:           "ips ip_address field",
			field:          "ips.ip_address",
			expectedColumn: "ips.ip_address",
			expectedTable:  "ips",
			requiresJoin:   true,
			joinType:       "LEFT",
		},
		{
			name:           "vmware_vms vm_name field",
			field:          "vmware_vms.vm_name",
			expectedColumn: "vmware_vms.vm_name",
			expectedTable:  "vmware_vms",
			requiresJoin:   true,
			joinType:       "LEFT",
		},
		{
			name:           "ips mac_address field",
			field:          "ips.mac_address",
			expectedColumn: "ips.mac_address",
			expectedTable:  "ips",
			requiresJoin:   true,
			joinType:       "LEFT",
		},

		// Assets table fields
		{
			name:           "name field",
			field:          "name",
			expectedColumn: "assets.name",
			expectedTable:  "assets",
			requiresJoin:   false,
		},
		{
			name:           "domain field",
			field:          "domain",
			expectedColumn: "assets.domain",
			expectedTable:  "assets",
			requiresJoin:   false,
		},
		{
			name:           "hostname field",
			field:          "hostname",
			expectedColumn: "assets.hostname",
			expectedTable:  "assets",
			requiresJoin:   false,
		},
		{
			name:           "os_name field",
			field:          "os_name",
			expectedColumn: "assets.os_name",
			expectedTable:  "assets",
			requiresJoin:   false,
		},
		{
			name:           "os_version field",
			field:          "os_version",
			expectedColumn: "assets.os_version",
			expectedTable:  "assets",
			requiresJoin:   false,
		},
		{
			name:           "asset_type field",
			field:          "asset_type",
			expectedColumn: "assets.asset_type",
			expectedTable:  "assets",
			requiresJoin:   false,
		},
		{
			name:           "description field",
			field:          "description",
			expectedColumn: "assets.description",
			expectedTable:  "assets",
			requiresJoin:   false,
		},
		{
			name:           "created_at field",
			field:          "created_at",
			expectedColumn: "assets.created_at",
			expectedTable:  "assets",
			requiresJoin:   false,
		},
		{
			name:           "updated_at field",
			field:          "updated_at",
			expectedColumn: "assets.updated_at",
			expectedTable:  "assets",
			requiresJoin:   false,
		},
		{
			name:           "logging_completed field",
			field:          "logging_completed",
			expectedColumn: "assets.logging_completed",
			expectedTable:  "assets",
			requiresJoin:   false,
		},
		{
			name:           "asset_value field",
			field:          "asset_value",
			expectedColumn: "assets.asset_value",
			expectedTable:  "assets",
			requiresJoin:   false,
		},
		{
			name:           "risk field",
			field:          "risk",
			expectedColumn: "assets.risk",
			expectedTable:  "assets",
			requiresJoin:   false,
		},

		// Default fallback case
		{
			name:           "unknown field",
			field:          "unknown_field",
			expectedColumn: "assets.created_at",
			expectedTable:  "assets",
			requiresJoin:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := storage.TestMapFieldToDBColumn(tt.field)

			assert.Equal(t, tt.expectedColumn, result.Column)
			assert.Equal(t, tt.expectedTable, result.Table)
			assert.Equal(t, tt.requiresJoin, result.RequiresJoin)
			if tt.requiresJoin {
				assert.Equal(t, tt.joinType, result.JoinType)
				assert.NotEmpty(t, result.JoinQuery)
			}
		})
	}
}

// TestUpdateOrUndeleteIP tests the updateOrUndeleteIP function
func TestUpdateOrUndeleteIP(t *testing.T) {
	suite := setupAssetRepoTest(t)
	defer suite.tearDown()

	tests := []struct {
		name           string
		foundIP        types.IPs
		newAssetID     string
		macAddress     string
		shouldUndelete bool
		expectError    bool
	}{
		{
			name: "update active IP with MAC address",
			foundIP: types.IPs{
				ID:         "ip-123",
				AssetID:    "old-asset-id",
				IPAddress:  "192.168.1.100",
				MacAddress: "00:11:22:33:44:55",
				DeletedAt:  nil,
				CreatedAt:  time.Now(),
			},
			newAssetID:     "new-asset-id",
			macAddress:     "00:11:22:33:44:66",
			shouldUndelete: false,
			expectError:    false,
		},
		{
			name: "undelete IP and update",
			foundIP: types.IPs{
				ID:        "ip-456",
				AssetID:   "old-asset-id",
				IPAddress: "10.0.0.50",
				DeletedAt: &time.Time{},
				CreatedAt: time.Now(),
			},
			newAssetID:     "new-asset-id",
			macAddress:     "00:11:22:33:44:77",
			shouldUndelete: true,
			expectError:    false,
		},
		{
			name: "update without MAC address",
			foundIP: types.IPs{
				ID:        "ip-789",
				AssetID:   "old-asset-id",
				IPAddress: "172.16.1.10",
				DeletedAt: nil,
				CreatedAt: time.Now(),
			},
			newAssetID:     "new-asset-id",
			macAddress:     "",
			shouldUndelete: false,
			expectError:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Mock the transaction
			suite.mock.ExpectBegin()
			tx := suite.gormDB.Begin()

			// Mock the update query
			updateQuery := "UPDATE `ips` SET"

			suite.mock.ExpectExec(updateQuery).
				WillReturnResult(sqlmock.NewResult(1, 1))

			testRepo := storage.NewTestAssetRepo(suite.gormDB)
			err := testRepo.TestUpdateOrUndeleteIP(tx, tt.foundIP, tt.newAssetID, tt.macAddress)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			assert.NoError(t, suite.mock.ExpectationsWereMet())
		})
	}
}

// TestCheckActiveIPsAssets tests the checkActiveIPsAssets function
func TestCheckActiveIPsAssets(t *testing.T) {
	suite := setupAssetRepoTest(t)
	defer suite.tearDown()

	tests := []struct {
		name             string
		activeIPs        []types.IPs
		assetExists      bool
		assetDeleted     bool
		expectedConflict bool
		expectError      bool
	}{
		{
			name: "active asset with active IPs - conflict",
			activeIPs: []types.IPs{
				{
					ID:        "ip-1",
					AssetID:   "asset-1",
					IPAddress: "192.168.1.100",
					DeletedAt: nil,
				},
			},
			assetExists:      true,
			assetDeleted:     false,
			expectedConflict: true,
			expectError:      false,
		},
		{
			name: "deleted asset with active IPs - no conflict",
			activeIPs: []types.IPs{
				{
					ID:        "ip-2",
					AssetID:   "asset-2",
					IPAddress: "10.0.0.50",
					DeletedAt: nil,
				},
			},
			assetExists:      true,
			assetDeleted:     true,
			expectedConflict: false,
			expectError:      false,
		},
		{
			name:             "no active IPs",
			activeIPs:        []types.IPs{},
			expectedConflict: false,
			expectError:      false,
		},
		{
			name: "asset not found - error expected",
			activeIPs: []types.IPs{
				{
					ID:        "ip-3",
					AssetID:   "asset-3",
					IPAddress: "172.16.1.10",
					DeletedAt: nil,
				},
			},
			assetExists:      false,
			expectedConflict: false,
			expectError:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if len(tt.activeIPs) > 0 {
				// Mock the asset existence check
				if tt.assetExists {
					deletedAt := interface{}(nil)
					if tt.assetDeleted {
						now := time.Now()
						deletedAt = &now
					}

					suite.mock.ExpectQuery("SELECT \\* FROM `assets` WHERE id = \\? ORDER BY `assets`.`id` LIMIT \\?").
						WithArgs(tt.activeIPs[0].AssetID, 1).
						WillReturnRows(sqlmock.NewRows([]string{"id", "deleted_at"}).
							AddRow(tt.activeIPs[0].AssetID, deletedAt))
				} else {
					suite.mock.ExpectQuery("SELECT \\* FROM `assets` WHERE id = \\? ORDER BY `assets`.`id` LIMIT \\?").
						WithArgs(tt.activeIPs[0].AssetID, 1).
						WillReturnError(gorm.ErrRecordNotFound)
				}
			}

			repo := storage.NewTestAssetRepo(suite.gormDB)
			hasConflict, err := repo.TestCheckActiveIPsAssets(suite.ctx, tt.activeIPs)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedConflict, hasConflict)
			}

			assert.NoError(t, suite.mock.ExpectationsWereMet())
		})
	}
}

// TestFindMACForIP tests the findMACForIP function
func TestFindMACForIP(t *testing.T) {
	tests := []struct {
		name          string
		targetIP      string
		validAssetIPs []domain.AssetIP
		expectedMAC   string
	}{
		{
			name:     "find existing MAC address",
			targetIP: "192.168.1.100",
			validAssetIPs: []domain.AssetIP{
				{
					IP:         "10.0.0.1",
					MACAddress: "00:11:22:33:44:55",
				},
				{
					IP:         "192.168.1.100",
					MACAddress: "00:11:22:33:44:66",
				},
				{
					IP:         "172.16.1.1",
					MACAddress: "00:11:22:33:44:77",
				},
			},
			expectedMAC: "00:11:22:33:44:66",
		},
		{
			name:     "IP not found",
			targetIP: "192.168.1.200",
			validAssetIPs: []domain.AssetIP{
				{
					IP:         "10.0.0.1",
					MACAddress: "00:11:22:33:44:55",
				},
				{
					IP:         "192.168.1.100",
					MACAddress: "00:11:22:33:44:66",
				},
			},
			expectedMAC: "",
		},
		{
			name:          "empty IP list",
			targetIP:      "192.168.1.100",
			validAssetIPs: []domain.AssetIP{},
			expectedMAC:   "",
		},
		{
			name:     "empty target IP",
			targetIP: "",
			validAssetIPs: []domain.AssetIP{
				{
					IP:         "192.168.1.100",
					MACAddress: "00:11:22:33:44:66",
				},
			},
			expectedMAC: "",
		},
		{
			name:     "IP with empty MAC address",
			targetIP: "192.168.1.100",
			validAssetIPs: []domain.AssetIP{
				{
					IP:         "192.168.1.100",
					MACAddress: "",
				},
			},
			expectedMAC: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			suite := setupAssetRepoTest(t)
			defer suite.tearDown()

			repo := storage.NewTestAssetRepo(suite.gormDB)
			result := repo.TestFindMACForIP(tt.targetIP, tt.validAssetIPs)

			assert.Equal(t, tt.expectedMAC, result)
		})
	}
}

// TestHandleExistingIPs tests the handleExistingIPs function
func TestHandleExistingIPs(t *testing.T) {
	suite := setupAssetRepoTest(t)
	defer suite.tearDown()

	t.Run("successful handling with no conflicts", func(t *testing.T) {
		// Arrange
		asset := domainFixtures.NewTestAssetDomainWithIPs([]string{"192.168.1.100", "10.0.0.50"})
		validAssetIPs := asset.AssetIPs
		assetRecord := &types.Assets{
			ID:       asset.ID.String(),
			Name:     asset.Name,
			Hostname: asset.Hostname,
		}
		assetIPs := []*types.IPs{
			{
				ID:        uuid.New().String(),
				AssetID:   asset.ID.String(),
				IPAddress: "192.168.1.100",
			},
			{
				ID:        uuid.New().String(),
				AssetID:   asset.ID.String(),
				IPAddress: "10.0.0.50",
			},
		}
		portRecords := []types.Port{}

		// Mock transaction
		suite.mock.ExpectBegin()
		tx := suite.gormDB.Begin()

		// Mock IP existence check - no existing IPs
		suite.mock.ExpectQuery("SELECT \\* FROM `ips` WHERE ip_address IN \\(\\?\\,\\?\\)").
			WithArgs("192.168.1.100", "10.0.0.50").
			WillReturnRows(sqlmock.NewRows([]string{"id", "asset_id", "ip_address", "mac_address", "created_at", "updated_at", "deleted_at"}))

		// Mock asset creation
		suite.mock.ExpectExec("INSERT INTO `assets`").
			WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
				sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
				sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
				sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg()).
			WillReturnResult(sqlmock.NewResult(1, 1))

		// Mock IP creation
		for range assetIPs {
			suite.mock.ExpectExec("INSERT INTO `ips`").
				WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
					sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
					sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg()).
				WillReturnResult(sqlmock.NewResult(1, 1))
		}

		// Act
		testRepo := storage.NewTestAssetRepo(suite.gormDB)
		err := testRepo.TestHandleExistingIPs(suite.ctx, tx, asset, validAssetIPs, assetRecord, assetIPs, portRecords)

		// Assert
		assert.NoError(t, err)
		assert.NoError(t, suite.mock.ExpectationsWereMet())
	})

	t.Run("handle IP conflict", func(t *testing.T) {
		// Arrange
		asset := domainFixtures.NewTestAssetDomainWithIPs([]string{"192.168.1.100"})
		validAssetIPs := asset.AssetIPs
		assetRecord := &types.Assets{
			ID:       asset.ID.String(),
			Name:     asset.Name,
			Hostname: asset.Hostname,
		}
		assetIPs := []*types.IPs{
			{
				ID:        uuid.New().String(),
				AssetID:   asset.ID.String(),
				IPAddress: "192.168.1.100",
			},
		}
		portRecords := []types.Port{}

		// Mock transaction
		suite.mock.ExpectBegin()
		tx := suite.gormDB.Begin()

		// Mock IP existence check - existing active IP
		suite.mock.ExpectQuery("SELECT \\* FROM `ips` WHERE ip_address IN \\(\\?\\)").
			WithArgs("192.168.1.100").
			WillReturnRows(sqlmock.NewRows([]string{"id", "asset_id", "ip_address", "mac_address", "created_at", "updated_at", "deleted_at"}).
				AddRow("existing-ip-id", "existing-asset-id", "192.168.1.100", "00:11:22:33:44:55", time.Now(), time.Now(), nil))

		// Mock asset check for conflict - active asset
		suite.mock.ExpectQuery("SELECT \\* FROM `assets` WHERE id = \\? ORDER BY `assets`\\.`id` LIMIT \\?").
			WithArgs("existing-asset-id", 1).
			WillReturnRows(sqlmock.NewRows([]string{"id", "deleted_at"}).
				AddRow("existing-asset-id", nil))

		// Act
		testRepo := storage.NewTestAssetRepo(suite.gormDB)
		err := testRepo.TestHandleExistingIPs(suite.ctx, tx, asset, validAssetIPs, assetRecord, assetIPs, portRecords)

		// Assert
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "IP address already exists")
		assert.NoError(t, suite.mock.ExpectationsWereMet())
	})
}

// TestUpdateDiscoveredBy tests the updateDiscoveredBy function
func TestUpdateDiscoveredBy(t *testing.T) {
	tests := []struct {
		name                 string
		currentDiscoveredBy  string
		scannerType          string
		expectedDiscoveredBy string
	}{
		{
			name:                 "add first scanner type to empty field",
			currentDiscoveredBy:  "",
			scannerType:          "NMap",
			expectedDiscoveredBy: "NMap",
		},
		{
			name:                 "add scanner type to existing single type",
			currentDiscoveredBy:  "Nessus",
			scannerType:          "NMap",
			expectedDiscoveredBy: "Nessus, NMap",
		},
		{
			name:                 "add scanner type to existing multiple types",
			currentDiscoveredBy:  "Nessus, Firewall",
			scannerType:          "NMap",
			expectedDiscoveredBy: "Nessus, Firewall, NMap",
		},
		{
			name:                 "scanner type already exists - no change",
			currentDiscoveredBy:  "Nessus, NMap, Firewall",
			scannerType:          "NMap",
			expectedDiscoveredBy: "Nessus, NMap, Firewall",
		},
		{
			name:                 "scanner type exists at beginning - no change",
			currentDiscoveredBy:  "NMap, Nessus, Firewall",
			scannerType:          "NMap",
			expectedDiscoveredBy: "NMap, Nessus, Firewall",
		},
		{
			name:                 "scanner type exists at end - no change",
			currentDiscoveredBy:  "Nessus, Firewall, NMap",
			scannerType:          "NMap",
			expectedDiscoveredBy: "Nessus, Firewall, NMap",
		},
		{
			name:                 "empty scanner type - no change",
			currentDiscoveredBy:  "Nessus, NMap",
			scannerType:          "",
			expectedDiscoveredBy: "Nessus, NMap",
		},
		{
			name:                 "whitespace in scanner type - trimmed and added",
			currentDiscoveredBy:  "Nessus",
			scannerType:          "  NMap  ",
			expectedDiscoveredBy: "Nessus, NMap",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			suite := setupAssetRepoTest(t)
			defer suite.tearDown()

			testRepo := storage.NewTestAssetRepo(suite.gormDB)
			result := testRepo.TestUpdateDiscoveredBy(tt.currentDiscoveredBy, tt.scannerType)

			assert.Equal(t, tt.expectedDiscoveredBy, result)
		})
	}
}
