package asset_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset"
	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/domain"
	domainFixtures "gitlab.apk-group.net/siem/backend/asset-discovery/tests/fixtures/domain"
	repoMocks "gitlab.apk-group.net/siem/backend/asset-discovery/tests/mocks/repo"
)

func TestAssetService_CreateAsset(t *testing.T) {
	tests := []struct {
		name           string
		inputAsset     domain.AssetDomain
		setupMock      func(*repoMocks.MockAssetRepo)
		expectedError  error
		validateResult func(t *testing.T, assetID domain.AssetUUID, err error)
	}{
		{
			name:       "successful asset creation",
			inputAsset: domainFixtures.NewTestAssetDomain(),
			setupMock: func(mockRepo *repoMocks.MockAssetRepo) {
				expectedID := uuid.New()
				mockRepo.On("Create", mock.Anything, mock.AnythingOfType("domain.AssetDomain"), []string(nil)).
					Return(expectedID, nil)
			},
			expectedError: nil,
			validateResult: func(t *testing.T, assetID domain.AssetUUID, err error) {
				assert.NoError(t, err)
				assert.NotEqual(t, uuid.Nil, assetID)
			},
		},
		{
			name:       "asset creation with ports",
			inputAsset: domainFixtures.NewTestAssetDomainWithPorts(3),
			setupMock: func(mockRepo *repoMocks.MockAssetRepo) {
				expectedID := uuid.New()
				mockRepo.On("Create", mock.Anything, mock.MatchedBy(func(asset domain.AssetDomain) bool {
					// Verify business logic: ports should be associated with asset
					return len(asset.Ports) == 3 &&
						asset.Ports[0].AssetID == asset.ID.String()
				}), []string(nil)).Return(expectedID, nil)
			},
			expectedError: nil,
			validateResult: func(t *testing.T, assetID domain.AssetUUID, err error) {
				assert.NoError(t, err)
				assert.NotEqual(t, uuid.Nil, assetID)
			},
		},
		{
			name:       "asset creation with IPs",
			inputAsset: domainFixtures.NewTestAssetDomainWithIPs([]string{"192.168.1.1", "10.0.0.1"}),
			setupMock: func(mockRepo *repoMocks.MockAssetRepo) {
				expectedID := uuid.New()
				mockRepo.On("Create", mock.Anything, mock.MatchedBy(func(asset domain.AssetDomain) bool {
					// Verify business logic: IPs should be associated with asset
					return len(asset.AssetIPs) == 2 &&
						asset.AssetIPs[0].AssetID == asset.ID.String() &&
						asset.AssetIPs[1].AssetID == asset.ID.String()
				}), []string(nil)).Return(expectedID, nil)
			},
			expectedError: nil,
			validateResult: func(t *testing.T, assetID domain.AssetUUID, err error) {
				assert.NoError(t, err)
				assert.NotEqual(t, uuid.Nil, assetID)
			},
		},
		{
			name:       "IP already exists error",
			inputAsset: domainFixtures.NewTestAssetDomainWithDuplicateIP("192.168.1.100"),
			setupMock: func(mockRepo *repoMocks.MockAssetRepo) {
				mockRepo.On("Create", mock.Anything, mock.AnythingOfType("domain.AssetDomain"), []string(nil)).
					Return(uuid.Nil, domain.ErrIPAlreadyExists)
			},
			expectedError: domain.ErrIPAlreadyExists,
			validateResult: func(t *testing.T, assetID domain.AssetUUID, err error) {
				assert.Error(t, err)
				assert.Equal(t, domain.ErrIPAlreadyExists, err)
				assert.Equal(t, uuid.Nil, assetID)
			},
		},
		{
			name:       "hostname already exists error",
			inputAsset: domainFixtures.NewTestAssetDomainWithDuplicateHostname("existing-host"),
			setupMock: func(mockRepo *repoMocks.MockAssetRepo) {
				mockRepo.On("Create", mock.Anything, mock.AnythingOfType("domain.AssetDomain"), []string(nil)).
					Return(uuid.Nil, domain.ErrHostnameAlreadyExists)
			},
			expectedError: domain.ErrHostnameAlreadyExists,
			validateResult: func(t *testing.T, assetID domain.AssetUUID, err error) {
				assert.Error(t, err)
				assert.Equal(t, domain.ErrHostnameAlreadyExists, err)
				assert.Equal(t, uuid.Nil, assetID)
			},
		},
		{
			name:       "repository error mapped to service error",
			inputAsset: domainFixtures.NewTestAssetDomain(),
			setupMock: func(mockRepo *repoMocks.MockAssetRepo) {
				mockRepo.On("Create", mock.Anything, mock.AnythingOfType("domain.AssetDomain"), []string(nil)).
					Return(uuid.Nil, errors.New("database connection failed"))
			},
			expectedError: asset.ErrAssetCreateFailed,
			validateResult: func(t *testing.T, assetID domain.AssetUUID, err error) {
				assert.Error(t, err)
				assert.Equal(t, asset.ErrAssetCreateFailed, err)
				assert.Equal(t, uuid.Nil, assetID)
			},
		},
		{
			name:       "minimal asset creation",
			inputAsset: domainFixtures.NewTestAssetDomainMinimal(),
			setupMock: func(mockRepo *repoMocks.MockAssetRepo) {
				expectedID := uuid.New()
				mockRepo.On("Create", mock.Anything, mock.MatchedBy(func(asset domain.AssetDomain) bool {
					// Verify minimal requirements are met
					return asset.Hostname == "minimal-host" &&
						asset.Type == "Server" &&
						len(asset.Ports) == 0 &&
						len(asset.AssetIPs) == 0
				}), []string(nil)).Return(expectedID, nil)
			},
			expectedError: nil,
			validateResult: func(t *testing.T, assetID domain.AssetUUID, err error) {
				assert.NoError(t, err)
				assert.NotEqual(t, uuid.Nil, assetID)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			mockRepo := new(repoMocks.MockAssetRepo)
			tt.setupMock(mockRepo)

			// Create service with mock repository
			service := asset.NewAssetService(mockRepo)

			// Execute
			ctx := context.Background()
			assetID, err := service.CreateAsset(ctx, tt.inputAsset)

			// Assert
			tt.validateResult(t, assetID, err)

			// Verify mock expectations
			mockRepo.AssertExpectations(t)
		})
	}
}

func TestAssetService_CreateAsset_BusinessLogic(t *testing.T) {
	tests := []struct {
		name          string
		setupAsset    func() domain.AssetDomain
		validateLogic func(t *testing.T, asset domain.AssetDomain)
	}{
		{
			name: "asset ID consistency across ports and IPs",
			setupAsset: func() domain.AssetDomain {
				asset := domainFixtures.NewTestAssetDomain()
				asset.Ports = []domain.Port{
					domainFixtures.NewTestPort(asset.ID.String(), 80),
					domainFixtures.NewTestPort(asset.ID.String(), 443),
				}
				asset.AssetIPs = []domain.AssetIP{
					{AssetID: asset.ID.String(), IP: "192.168.1.1", MACAddress: "00:11:22:33:44:55"},
				}
				return asset
			},
			validateLogic: func(t *testing.T, asset domain.AssetDomain) {
				// All ports should have the same asset ID
				for _, port := range asset.Ports {
					assert.Equal(t, asset.ID.String(), port.AssetID)
				}
				// All IPs should have the same asset ID
				for _, ip := range asset.AssetIPs {
					assert.Equal(t, asset.ID.String(), ip.AssetID)
				}
			},
		},
		{
			name: "timestamp validation",
			setupAsset: func() domain.AssetDomain {
				return domainFixtures.NewTestAssetDomain()
			},
			validateLogic: func(t *testing.T, asset domain.AssetDomain) {
				assert.False(t, asset.CreatedAt.IsZero())
				assert.False(t, asset.UpdatedAt.IsZero())
				// CreatedAt should be before or equal to UpdatedAt
				assert.True(t, asset.CreatedAt.Before(asset.UpdatedAt) || asset.CreatedAt.Equal(asset.UpdatedAt))
			},
		},
		{
			name: "default values validation",
			setupAsset: func() domain.AssetDomain {
				return domainFixtures.NewTestAssetDomainMinimal()
			},
			validateLogic: func(t *testing.T, asset domain.AssetDomain) {
				// Required fields should be set
				assert.NotEmpty(t, asset.Hostname)
				assert.NotEmpty(t, asset.Type)
				assert.NotEqual(t, uuid.Nil, asset.ID)

				// Optional fields can be empty/zero values
				assert.Equal(t, "", asset.Name)
				assert.Equal(t, "", asset.Domain)
				assert.Equal(t, 0, asset.Risk)
				assert.Equal(t, false, asset.LoggingCompleted)
			},
		},
		{
			name: "asset with maximum complexity",
			setupAsset: func() domain.AssetDomain {
				asset := domainFixtures.NewTestAssetDomain()
				// Add multiple ports
				for i := 0; i < 10; i++ {
					asset.Ports = append(asset.Ports, domainFixtures.NewTestPort(asset.ID.String(), 80+i))
				}
				// Add multiple IPs
				for i := 0; i < 5; i++ {
					asset.AssetIPs = append(asset.AssetIPs, domain.AssetIP{
						AssetID:    asset.ID.String(),
						IP:         fmt.Sprintf("192.168.1.%d", i+1),
						MACAddress: domainFixtures.NewTestMACAddress(i),
					})
				}
				return asset
			},
			validateLogic: func(t *testing.T, asset domain.AssetDomain) {
				assert.Equal(t, 10, len(asset.Ports))
				assert.Equal(t, 5, len(asset.AssetIPs))

				// Verify all relationships are correct
				for _, port := range asset.Ports {
					assert.Equal(t, asset.ID.String(), port.AssetID)
				}
				for _, ip := range asset.AssetIPs {
					assert.Equal(t, asset.ID.String(), ip.AssetID)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			assetDomain := tt.setupAsset()

			// Validate business logic
			tt.validateLogic(t, assetDomain)

			// Setup mock repo for service test
			mockRepo := new(repoMocks.MockAssetRepo)
			expectedID := uuid.New()
			mockRepo.On("Create", mock.Anything, mock.AnythingOfType("domain.AssetDomain"), []string(nil)).
				Return(expectedID, nil)

			// Create service and test
			service := asset.NewAssetService(mockRepo)
			ctx := context.Background()

			resultID, err := service.CreateAsset(ctx, assetDomain)

			assert.NoError(t, err)
			assert.Equal(t, expectedID, resultID)
			mockRepo.AssertExpectations(t)
		})
	}
}

func TestAssetService_CreateAsset_ErrorScenarios(t *testing.T) {
	tests := []struct {
		name            string
		repositoryError error
		expectedError   error
		errorMessage    string
	}{
		{
			name:            "IP already exists should pass through",
			repositoryError: domain.ErrIPAlreadyExists,
			expectedError:   domain.ErrIPAlreadyExists,
			errorMessage:    "IP address already exists",
		},
		{
			name:            "hostname already exists should pass through",
			repositoryError: domain.ErrHostnameAlreadyExists,
			expectedError:   domain.ErrHostnameAlreadyExists,
			errorMessage:    "Hostname already exists",
		},
		{
			name:            "database connection error should map to create failed",
			repositoryError: errors.New("database connection failed"),
			expectedError:   asset.ErrAssetCreateFailed,
			errorMessage:    "failed to create asset",
		},
		{
			name:            "transaction rollback error should map to create failed",
			repositoryError: errors.New("transaction rollback failed"),
			expectedError:   asset.ErrAssetCreateFailed,
			errorMessage:    "failed to create asset",
		},
		{
			name:            "constraint violation should map to create failed",
			repositoryError: errors.New("constraint violation"),
			expectedError:   asset.ErrAssetCreateFailed,
			errorMessage:    "failed to create asset",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			mockRepo := new(repoMocks.MockAssetRepo)
			mockRepo.On("Create", mock.Anything, mock.AnythingOfType("domain.AssetDomain"), []string(nil)).
				Return(uuid.Nil, tt.repositoryError)

			service := asset.NewAssetService(mockRepo)

			// Execute
			ctx := context.Background()
			testAsset := domainFixtures.NewTestAssetDomain()

			assetID, err := service.CreateAsset(ctx, testAsset)

			// Assert
			assert.Error(t, err)
			assert.Equal(t, tt.expectedError, err)
			assert.Equal(t, uuid.Nil, assetID)

			mockRepo.AssertExpectations(t)
		})
	}
}

func TestAssetService_CreateAsset_ConcurrentAccess(t *testing.T) {
	t.Run("concurrent creation with same hostname should fail for second attempt", func(t *testing.T) {
		mockRepo := new(repoMocks.MockAssetRepo)

		// First call succeeds
		firstID := uuid.New()
		mockRepo.On("Create", mock.Anything, mock.MatchedBy(func(asset domain.AssetDomain) bool {
			return asset.Hostname == "concurrent-host"
		}), []string(nil)).Return(firstID, nil).Once()

		// Second call fails with hostname already exists
		mockRepo.On("Create", mock.Anything, mock.MatchedBy(func(asset domain.AssetDomain) bool {
			return asset.Hostname == "concurrent-host"
		}), []string(nil)).Return(uuid.Nil, domain.ErrHostnameAlreadyExists).Once()

		service := asset.NewAssetService(mockRepo)
		ctx := context.Background()

		// First asset creation
		asset1 := domainFixtures.NewTestAssetDomainWithDuplicateHostname("concurrent-host")
		resultID1, err1 := service.CreateAsset(ctx, asset1)

		assert.NoError(t, err1)
		assert.Equal(t, firstID, resultID1)

		// Second asset creation with same hostname
		asset2 := domainFixtures.NewTestAssetDomainWithDuplicateHostname("concurrent-host")
		resultID2, err2 := service.CreateAsset(ctx, asset2)

		assert.Error(t, err2)
		assert.Equal(t, domain.ErrHostnameAlreadyExists, err2)
		assert.Equal(t, uuid.Nil, resultID2)

		mockRepo.AssertExpectations(t)
	})
}

func TestAssetService_GetByID(t *testing.T) {
	tests := []struct {
		name           string
		assetUUID      domain.AssetUUID
		setupMock      func(*repoMocks.MockAssetRepo)
		expectedError  error
		validateResult func(t *testing.T, result *domain.AssetDomain, err error)
	}{
		{
			name:      "successful asset retrieval",
			assetUUID: uuid.MustParse("550e8400-e29b-41d4-a716-446655440000"),
			setupMock: func(mockRepo *repoMocks.MockAssetRepo) {
				testAsset := domainFixtures.NewTestAssetDomain()
				testAsset.ID = uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")
				mockRepo.On("GetByIDs", mock.Anything, []domain.AssetUUID{uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")}).
					Return([]domain.AssetDomain{testAsset}, nil)
			},
			expectedError: nil,
			validateResult: func(t *testing.T, result *domain.AssetDomain, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, result)
				assert.Equal(t, "550e8400-e29b-41d4-a716-446655440000", result.ID.String())
			},
		},
		{
			name:      "asset not found - empty result",
			assetUUID: uuid.MustParse("550e8400-e29b-41d4-a716-446655440000"),
			setupMock: func(mockRepo *repoMocks.MockAssetRepo) {
				mockRepo.On("GetByIDs", mock.Anything, []domain.AssetUUID{uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")}).
					Return([]domain.AssetDomain{}, nil)
			},
			expectedError: asset.ErrAssetNotFound,
			validateResult: func(t *testing.T, result *domain.AssetDomain, err error) {
				assert.Error(t, err)
				assert.Equal(t, asset.ErrAssetNotFound, err)
				assert.Nil(t, result)
			},
		},
		{
			name:      "asset not found - nil result",
			assetUUID: uuid.MustParse("550e8400-e29b-41d4-a716-446655440000"),
			setupMock: func(mockRepo *repoMocks.MockAssetRepo) {
				mockRepo.On("GetByIDs", mock.Anything, []domain.AssetUUID{uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")}).
					Return(nil, nil)
			},
			expectedError: asset.ErrAssetNotFound,
			validateResult: func(t *testing.T, result *domain.AssetDomain, err error) {
				assert.Error(t, err)
				assert.Equal(t, asset.ErrAssetNotFound, err)
				assert.Nil(t, result)
			},
		},
		{
			name:      "repository error",
			assetUUID: uuid.MustParse("550e8400-e29b-41d4-a716-446655440000"),
			setupMock: func(mockRepo *repoMocks.MockAssetRepo) {
				mockRepo.On("GetByIDs", mock.Anything, []domain.AssetUUID{uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")}).
					Return(nil, errors.New("database connection failed"))
			},
			expectedError: errors.New("database connection failed"),
			validateResult: func(t *testing.T, result *domain.AssetDomain, err error) {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "database connection failed")
				assert.Nil(t, result)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			mockRepo := new(repoMocks.MockAssetRepo)
			tt.setupMock(mockRepo)

			// Create service
			service := asset.NewAssetService(mockRepo)

			// Execute
			ctx := context.Background()
			result, err := service.GetByID(ctx, tt.assetUUID)

			// Validate
			tt.validateResult(t, result, err)

			// Verify mock expectations
			mockRepo.AssertExpectations(t)
		})
	}
}

func TestAssetService_GetByIDs(t *testing.T) {
	tests := []struct {
		name           string
		assetUUIDs     []domain.AssetUUID
		setupMock      func(*repoMocks.MockAssetRepo)
		expectedError  error
		validateResult func(t *testing.T, result []domain.AssetDomain, err error)
	}{
		{
			name: "successful multiple assets retrieval",
			assetUUIDs: []domain.AssetUUID{
				uuid.MustParse("550e8400-e29b-41d4-a716-446655440000"),
				uuid.MustParse("550e8400-e29b-41d4-a716-446655440001"),
			},
			setupMock: func(mockRepo *repoMocks.MockAssetRepo) {
				testAssets := []domain.AssetDomain{
					domainFixtures.NewTestAssetDomain(),
					domainFixtures.NewTestAssetDomain(),
				}
				testAssets[0].ID = uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")
				testAssets[1].ID = uuid.MustParse("550e8400-e29b-41d4-a716-446655440001")
				mockRepo.On("GetByIDs", mock.Anything, mock.AnythingOfType("[]uuid.UUID")).
					Return(testAssets, nil)
			},
			expectedError: nil,
			validateResult: func(t *testing.T, result []domain.AssetDomain, err error) {
				assert.NoError(t, err)
				assert.Len(t, result, 2)
				assert.Equal(t, "550e8400-e29b-41d4-a716-446655440000", result[0].ID.String())
				assert.Equal(t, "550e8400-e29b-41d4-a716-446655440001", result[1].ID.String())
			},
		},
		{
			name:       "empty UUIDs list",
			assetUUIDs: []domain.AssetUUID{},
			setupMock: func(mockRepo *repoMocks.MockAssetRepo) {
				mockRepo.On("GetByIDs", mock.Anything, []domain.AssetUUID{}).
					Return([]domain.AssetDomain{}, nil)
			},
			expectedError: nil,
			validateResult: func(t *testing.T, result []domain.AssetDomain, err error) {
				assert.NoError(t, err)
				assert.Len(t, result, 0)
			},
		},
		{
			name: "repository error",
			assetUUIDs: []domain.AssetUUID{
				uuid.MustParse("550e8400-e29b-41d4-a716-446655440000"),
			},
			setupMock: func(mockRepo *repoMocks.MockAssetRepo) {
				mockRepo.On("GetByIDs", mock.Anything, mock.AnythingOfType("[]uuid.UUID")).
					Return(nil, errors.New("database connection failed"))
			},
			expectedError: errors.New("database connection failed"),
			validateResult: func(t *testing.T, result []domain.AssetDomain, err error) {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "database connection failed")
				assert.Nil(t, result)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			mockRepo := new(repoMocks.MockAssetRepo)
			tt.setupMock(mockRepo)

			// Create service
			service := asset.NewAssetService(mockRepo)

			// Execute
			ctx := context.Background()
			result, err := service.GetByIDs(ctx, tt.assetUUIDs)

			// Validate
			tt.validateResult(t, result, err)

			// Verify mock expectations
			mockRepo.AssertExpectations(t)
		})
	}
}

func TestAssetService_Get(t *testing.T) {
	tests := []struct {
		name           string
		filter         domain.AssetFilters
		limit          int
		offset         int
		sortOptions    []domain.SortOption
		setupMock      func(*repoMocks.MockAssetRepo)
		expectedError  error
		validateResult func(t *testing.T, assets []domain.AssetDomain, total int, err error)
	}{
		{
			name: "successful assets retrieval with filters",
			filter: domain.AssetFilters{
				Name:     "test",
				Hostname: "test-host",
			},
			limit:  10,
			offset: 0,
			sortOptions: []domain.SortOption{
				{Field: "name", Order: "asc"},
			},
			setupMock: func(mockRepo *repoMocks.MockAssetRepo) {
				testAssets := []domain.AssetDomain{
					domainFixtures.NewTestAssetDomain(),
					domainFixtures.NewTestAssetDomain(),
				}
				mockRepo.On("GetByFilter", mock.Anything,
					mock.MatchedBy(func(filter domain.AssetFilters) bool {
						return filter.Name == "test" && filter.Hostname == "test-host"
					}),
					10, 0, mock.AnythingOfType("[]domain.SortOption")).
					Return(testAssets, 15, nil)
			},
			expectedError: nil,
			validateResult: func(t *testing.T, assets []domain.AssetDomain, total int, err error) {
				assert.NoError(t, err)
				assert.Len(t, assets, 2)
				assert.Equal(t, 15, total)
			},
		},
		{
			name:        "empty filter returns all assets",
			filter:      domain.AssetFilters{},
			limit:       5,
			offset:      10,
			sortOptions: []domain.SortOption{},
			setupMock: func(mockRepo *repoMocks.MockAssetRepo) {
				testAssets := []domain.AssetDomain{
					domainFixtures.NewTestAssetDomain(),
				}
				mockRepo.On("GetByFilter", mock.Anything,
					mock.AnythingOfType("domain.AssetFilters"),
					5, 10, mock.AnythingOfType("[]domain.SortOption")).
					Return(testAssets, 100, nil)
			},
			expectedError: nil,
			validateResult: func(t *testing.T, assets []domain.AssetDomain, total int, err error) {
				assert.NoError(t, err)
				assert.Len(t, assets, 1)
				assert.Equal(t, 100, total)
			},
		},
		{
			name:   "repository error",
			filter: domain.AssetFilters{},
			limit:  10,
			offset: 0,
			setupMock: func(mockRepo *repoMocks.MockAssetRepo) {
				mockRepo.On("GetByFilter", mock.Anything,
					mock.AnythingOfType("domain.AssetFilters"),
					10, 0, mock.AnythingOfType("[]domain.SortOption")).
					Return(nil, 0, errors.New("database connection failed"))
			},
			expectedError: errors.New("database connection failed"),
			validateResult: func(t *testing.T, assets []domain.AssetDomain, total int, err error) {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "database connection failed")
				assert.Nil(t, assets)
				assert.Equal(t, 0, total)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			mockRepo := new(repoMocks.MockAssetRepo)
			tt.setupMock(mockRepo)

			// Create service
			service := asset.NewAssetService(mockRepo)

			// Execute
			ctx := context.Background()
			assets, total, err := service.Get(ctx, tt.filter, tt.limit, tt.offset, tt.sortOptions...)

			// Validate
			tt.validateResult(t, assets, total, err)

			// Verify mock expectations
			mockRepo.AssertExpectations(t)
		})
	}
}

func TestAssetService_UpdateAsset(t *testing.T) {
	tests := []struct {
		name           string
		inputAsset     domain.AssetDomain
		setupMock      func(*repoMocks.MockAssetRepo)
		expectedError  error
		validateResult func(t *testing.T, err error)
	}{
		{
			name:       "successful asset update",
			inputAsset: domainFixtures.NewTestAssetDomain(),
			setupMock: func(mockRepo *repoMocks.MockAssetRepo) {
				mockRepo.On("Update", mock.Anything, mock.AnythingOfType("domain.AssetDomain")).
					Return(nil)
			},
			expectedError: nil,
			validateResult: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
		},
		{
			name:       "asset update with ports and IPs",
			inputAsset: domainFixtures.NewTestAssetDomainWithPorts(2),
			setupMock: func(mockRepo *repoMocks.MockAssetRepo) {
				mockRepo.On("Update", mock.Anything, mock.MatchedBy(func(asset domain.AssetDomain) bool {
					return len(asset.Ports) == 2
				})).Return(nil)
			},
			expectedError: nil,
			validateResult: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
		},
		{
			name:       "IP already exists error",
			inputAsset: domainFixtures.NewTestAssetDomainWithDuplicateIP("192.168.1.100"),
			setupMock: func(mockRepo *repoMocks.MockAssetRepo) {
				mockRepo.On("Update", mock.Anything, mock.AnythingOfType("domain.AssetDomain")).
					Return(domain.ErrIPAlreadyExists)
			},
			expectedError: domain.ErrIPAlreadyExists,
			validateResult: func(t *testing.T, err error) {
				assert.Error(t, err)
				assert.Equal(t, domain.ErrIPAlreadyExists, err)
			},
		},
		{
			name:       "repository error mapped to service error",
			inputAsset: domainFixtures.NewTestAssetDomain(),
			setupMock: func(mockRepo *repoMocks.MockAssetRepo) {
				mockRepo.On("Update", mock.Anything, mock.AnythingOfType("domain.AssetDomain")).
					Return(errors.New("database connection failed"))
			},
			expectedError: asset.ErrAssetUpdateFailed,
			validateResult: func(t *testing.T, err error) {
				assert.Error(t, err)
				assert.Equal(t, asset.ErrAssetUpdateFailed, err)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			mockRepo := new(repoMocks.MockAssetRepo)
			tt.setupMock(mockRepo)

			// Create service
			service := asset.NewAssetService(mockRepo)

			// Execute
			ctx := context.Background()
			err := service.UpdateAsset(ctx, tt.inputAsset)

			// Validate
			tt.validateResult(t, err)

			// Verify mock expectations
			mockRepo.AssertExpectations(t)
		})
	}
}

func TestAssetService_DeleteAssets(t *testing.T) {
	tests := []struct {
		name           string
		ids            []string
		filter         *domain.AssetFilters
		exclude        bool
		setupMock      func(*repoMocks.MockAssetRepo)
		expectedError  error
		validateResult func(t *testing.T, err error)
	}{
		{
			name: "successful single asset deletion",
			ids:  []string{"550e8400-e29b-41d4-a716-446655440000"},
			setupMock: func(mockRepo *repoMocks.MockAssetRepo) {
				mockRepo.On("DeleteAssets", mock.Anything, mock.MatchedBy(func(params domain.DeleteParams) bool {
					return params.UUID != nil && params.UUID.String() == "550e8400-e29b-41d4-a716-446655440000"
				})).Return(1, nil)
			},
			expectedError: nil,
			validateResult: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
		},
		{
			name: "successful multiple assets deletion",
			ids: []string{
				"550e8400-e29b-41d4-a716-446655440000",
				"550e8400-e29b-41d4-a716-446655440001",
			},
			setupMock: func(mockRepo *repoMocks.MockAssetRepo) {
				mockRepo.On("DeleteAssets", mock.Anything, mock.MatchedBy(func(params domain.DeleteParams) bool {
					return len(params.UUIDs) == 2
				})).Return(2, nil)
			},
			expectedError: nil,
			validateResult: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
		},
		{
			name:    "delete all assets",
			ids:     []string{"All"},
			exclude: false,
			setupMock: func(mockRepo *repoMocks.MockAssetRepo) {
				mockRepo.On("DeleteAssets", mock.Anything, mock.MatchedBy(func(params domain.DeleteParams) bool {
					return params.UUID == nil && len(params.UUIDs) == 0 && params.Filters == nil
				})).Return(10, nil)
			},
			expectedError: nil,
			validateResult: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
		},
		{
			name: "delete with filter",
			ids:  []string{"All"},
			filter: &domain.AssetFilters{
				Name: "test",
			},
			setupMock: func(mockRepo *repoMocks.MockAssetRepo) {
				mockRepo.On("DeleteAssets", mock.Anything, mock.MatchedBy(func(params domain.DeleteParams) bool {
					return params.Filters != nil && params.Filters.Name == "test"
				})).Return(5, nil)
			},
			expectedError: nil,
			validateResult: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
		},
		{
			name:    "delete all except specified IDs",
			ids:     []string{"550e8400-e29b-41d4-a716-446655440000"},
			exclude: true,
			setupMock: func(mockRepo *repoMocks.MockAssetRepo) {
				mockRepo.On("DeleteAssets", mock.Anything, mock.MatchedBy(func(params domain.DeleteParams) bool {
					return params.Exclude && len(params.UUIDs) == 1
				})).Return(8, nil)
			},
			expectedError: nil,
			validateResult: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
		},
		{
			name: "invalid UUID format",
			ids:  []string{"invalid-uuid"},
			setupMock: func(mockRepo *repoMocks.MockAssetRepo) {
				// No mock setup needed as UUID parsing should fail
			},
			expectedError: asset.ErrInvalidAssetUUID,
			validateResult: func(t *testing.T, err error) {
				assert.Error(t, err)
				assert.Equal(t, asset.ErrInvalidAssetUUID, err)
			},
		},
		{
			name: "no assets found for deletion",
			ids:  []string{"550e8400-e29b-41d4-a716-446655440000"},
			setupMock: func(mockRepo *repoMocks.MockAssetRepo) {
				mockRepo.On("DeleteAssets", mock.Anything, mock.AnythingOfType("domain.DeleteParams")).
					Return(0, nil)
			},
			expectedError: asset.ErrAssetNotFound,
			validateResult: func(t *testing.T, err error) {
				assert.Error(t, err)
				assert.Equal(t, asset.ErrAssetNotFound, err)
			},
		},
		{
			name: "repository error",
			ids:  []string{"550e8400-e29b-41d4-a716-446655440000"},
			setupMock: func(mockRepo *repoMocks.MockAssetRepo) {
				mockRepo.On("DeleteAssets", mock.Anything, mock.AnythingOfType("domain.DeleteParams")).
					Return(0, errors.New("database connection failed"))
			},
			expectedError: asset.ErrAssetDeleteFailed,
			validateResult: func(t *testing.T, err error) {
				assert.Error(t, err)
				assert.Equal(t, asset.ErrAssetDeleteFailed, err)
			},
		},
		{
			name: "empty IDs list should not delete anything",
			ids:  []string{},
			setupMock: func(mockRepo *repoMocks.MockAssetRepo) {
				// No mock setup needed as service should return early
			},
			expectedError: nil,
			validateResult: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
		},
		{
			name: "multiple invalid UUID formats in list",
			ids:  []string{"550e8400-e29b-41d4-a716-446655440000", "invalid-uuid", "another-invalid"},
			setupMock: func(mockRepo *repoMocks.MockAssetRepo) {
				// No mock setup needed as UUID parsing should fail on second ID
			},
			expectedError: asset.ErrInvalidAssetUUID,
			validateResult: func(t *testing.T, err error) {
				assert.Error(t, err)
				assert.Equal(t, asset.ErrInvalidAssetUUID, err)
			},
		},
		{
			name: "delete with filter and specific IDs (both conditions)",
			ids:  []string{"550e8400-e29b-41d4-a716-446655440000", "550e8400-e29b-41d4-a716-446655440001"},
			filter: &domain.AssetFilters{
				Name: "test-asset",
			},
			exclude: false,
			setupMock: func(mockRepo *repoMocks.MockAssetRepo) {
				mockRepo.On("DeleteAssets", mock.Anything, mock.MatchedBy(func(params domain.DeleteParams) bool {
					return len(params.UUIDs) == 2 &&
						params.Filters != nil &&
						params.Filters.Name == "test-asset" &&
						!params.Exclude
				})).Return(2, nil)
			},
			expectedError: nil,
			validateResult: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
		},
		{
			name: "delete with filter excluding specific IDs",
			ids:  []string{"550e8400-e29b-41d4-a716-446655440000", "550e8400-e29b-41d4-a716-446655440001"},
			filter: &domain.AssetFilters{
				Name: "test-asset",
			},
			exclude: true,
			setupMock: func(mockRepo *repoMocks.MockAssetRepo) {
				mockRepo.On("DeleteAssets", mock.Anything, mock.MatchedBy(func(params domain.DeleteParams) bool {
					return len(params.UUIDs) == 2 &&
						params.Filters != nil &&
						params.Filters.Name == "test-asset" &&
						params.Exclude
				})).Return(3, nil)
			},
			expectedError: nil,
			validateResult: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
		},
		{
			name:    "exclude with empty IDs list (delete all)",
			ids:     []string{},
			exclude: true,
			setupMock: func(mockRepo *repoMocks.MockAssetRepo) {
				mockRepo.On("DeleteAssets", mock.Anything, mock.MatchedBy(func(params domain.DeleteParams) bool {
					return params.UUID == nil &&
						len(params.UUIDs) == 0 &&
						params.Filters == nil &&
						!params.Exclude
				})).Return(15, nil)
			},
			expectedError: nil,
			validateResult: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
		},
		{
			name:    "invalid UUID in multiple IDs scenario with exclude",
			ids:     []string{"550e8400-e29b-41d4-a716-446655440000", "invalid-uuid"},
			exclude: true,
			setupMock: func(mockRepo *repoMocks.MockAssetRepo) {
				// No mock setup needed as UUID parsing should fail
			},
			expectedError: asset.ErrInvalidAssetUUID,
			validateResult: func(t *testing.T, err error) {
				assert.Error(t, err)
				assert.Equal(t, asset.ErrInvalidAssetUUID, err)
			},
		},
		{
			name: "delete with filter and invalid UUID",
			ids:  []string{"invalid-uuid"},
			filter: &domain.AssetFilters{
				Name: "test-asset",
			},
			exclude: false,
			setupMock: func(mockRepo *repoMocks.MockAssetRepo) {
				// No mock setup needed as UUID parsing should fail
			},
			expectedError: asset.ErrInvalidAssetUUID,
			validateResult: func(t *testing.T, err error) {
				assert.Error(t, err)
				assert.Equal(t, asset.ErrInvalidAssetUUID, err)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			mockRepo := new(repoMocks.MockAssetRepo)
			tt.setupMock(mockRepo)

			// Create service
			service := asset.NewAssetService(mockRepo)

			// Execute
			ctx := context.Background()
			err := service.DeleteAssets(ctx, tt.ids, tt.filter, tt.exclude)

			// Validate
			tt.validateResult(t, err)

			// Verify mock expectations
			mockRepo.AssertExpectations(t)
		})
	}
}

func TestAssetService_ExportAssets(t *testing.T) {
	tests := []struct {
		name            string
		assetIDs        []domain.AssetUUID
		exportType      domain.ExportType
		selectedColumns []string
		setupMock       func(*repoMocks.MockAssetRepo)
		expectedError   error
		validateResult  func(t *testing.T, result *domain.ExportData, err error)
	}{
		{
			name: "successful CSV export",
			assetIDs: []domain.AssetUUID{
				uuid.MustParse("550e8400-e29b-41d4-a716-446655440000"),
			},
			exportType:      domain.FullExport,
			selectedColumns: []string{"name", "hostname", "ip"},
			setupMock: func(mockRepo *repoMocks.MockAssetRepo) {
				exportData := &domain.ExportData{
					Assets: []map[string]interface{}{
						{"name": "Test Asset", "hostname": "test-host", "ip": "192.168.1.1"},
					},
					AssetIPs:  []map[string]interface{}{},
					VMwareVMs: []map[string]interface{}{},
				}
				mockRepo.On("ExportAssets", mock.Anything,
					mock.AnythingOfType("[]uuid.UUID"),
					domain.FullExport,
					[]string{"name", "hostname", "ip"}).
					Return(exportData, nil)
			},
			expectedError: nil,
			validateResult: func(t *testing.T, result *domain.ExportData, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, result)
				assert.Len(t, result.Assets, 1)
				assert.Equal(t, "Test Asset", result.Assets[0]["name"])
			},
		},
		{
			name:            "empty asset IDs list",
			assetIDs:        []domain.AssetUUID{},
			exportType:      domain.SelectedColumnsExport,
			selectedColumns: []string{"name"},
			setupMock: func(mockRepo *repoMocks.MockAssetRepo) {
				exportData := &domain.ExportData{
					Assets:    []map[string]interface{}{},
					AssetIPs:  []map[string]interface{}{},
					VMwareVMs: []map[string]interface{}{},
				}
				mockRepo.On("ExportAssets", mock.Anything,
					[]domain.AssetUUID{},
					domain.SelectedColumnsExport,
					[]string{"name"}).
					Return(exportData, nil)
			},
			expectedError: nil,
			validateResult: func(t *testing.T, result *domain.ExportData, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, result)
				assert.Len(t, result.Assets, 0)
			},
		},
		{
			name: "repository error",
			assetIDs: []domain.AssetUUID{
				uuid.MustParse("550e8400-e29b-41d4-a716-446655440000"),
			},
			exportType:      domain.FullExport,
			selectedColumns: []string{"name"},
			setupMock: func(mockRepo *repoMocks.MockAssetRepo) {
				mockRepo.On("ExportAssets", mock.Anything,
					mock.AnythingOfType("[]uuid.UUID"),
					domain.FullExport,
					[]string{"name"}).
					Return(nil, errors.New("database connection failed"))
			},
			expectedError: asset.ErrExportFailed,
			validateResult: func(t *testing.T, result *domain.ExportData, err error) {
				assert.Error(t, err)
				assert.Equal(t, asset.ErrExportFailed, err)
				assert.Nil(t, result)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			mockRepo := new(repoMocks.MockAssetRepo)
			tt.setupMock(mockRepo)

			// Create service
			service := asset.NewAssetService(mockRepo)

			// Execute
			ctx := context.Background()
			result, err := service.ExportAssets(ctx, tt.assetIDs, tt.exportType, tt.selectedColumns)

			// Validate
			tt.validateResult(t, result, err)

			// Verify mock expectations
			mockRepo.AssertExpectations(t)
		})
	}
}

func TestAssetService_GenerateCSV(t *testing.T) {
	tests := []struct {
		name           string
		exportData     *domain.ExportData
		expectedError  error
		validateResult func(t *testing.T, csvData []byte, err error)
	}{
		{
			name: "successful CSV generation",
			exportData: &domain.ExportData{
				Assets: []map[string]interface{}{
					{"name": "Test Asset 1", "hostname": "test-host-1", "ip": "192.168.1.1"},
					{"name": "Test Asset 2", "hostname": "test-host-2", "ip": "192.168.1.2"},
				},
				AssetIPs:  []map[string]interface{}{},
				VMwareVMs: []map[string]interface{}{},
			},
			expectedError: nil,
			validateResult: func(t *testing.T, csvData []byte, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, csvData)
				assert.Greater(t, len(csvData), 0)
				csvString := string(csvData)
				assert.Contains(t, csvString, "Test Asset 1")
				assert.Contains(t, csvString, "test-host-1")
			},
		},
		{
			name: "CSV generation with status field",
			exportData: &domain.ExportData{
				Assets: []map[string]interface{}{
					{"status": "active", "name": "Test Asset", "hostname": "test-host"},
				},
				AssetIPs:  []map[string]interface{}{},
				VMwareVMs: []map[string]interface{}{},
			},
			expectedError: nil,
			validateResult: func(t *testing.T, csvData []byte, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, csvData)
				csvString := string(csvData)
				assert.Contains(t, csvString, "status")
				assert.Contains(t, csvString, "active")
			},
		},
		{
			name:          "nil export data",
			exportData:    nil,
			expectedError: fmt.Errorf("export data is nil"),
			validateResult: func(t *testing.T, csvData []byte, err error) {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "export data is nil")
				assert.Nil(t, csvData)
			},
		},
		{
			name: "empty export data",
			exportData: &domain.ExportData{
				Assets:    []map[string]interface{}{},
				AssetIPs:  []map[string]interface{}{},
				VMwareVMs: []map[string]interface{}{},
			},
			expectedError: nil,
			validateResult: func(t *testing.T, csvData []byte, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, csvData)
				// Should contain at least headers
				assert.Greater(t, len(csvData), 0)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			mockRepo := new(repoMocks.MockAssetRepo)
			service := asset.NewAssetService(mockRepo)

			// Execute
			ctx := context.Background()
			csvData, err := service.GenerateCSV(ctx, tt.exportData)

			// Validate
			tt.validateResult(t, csvData, err)
		})
	}
}

func TestAssetService_GetDistinctOSNames(t *testing.T) {
	tests := []struct {
		name           string
		setupMock      func(*repoMocks.MockAssetRepo)
		expectedError  error
		validateResult func(t *testing.T, osNames []string, err error)
	}{
		{
			name: "successful OS names retrieval",
			setupMock: func(mockRepo *repoMocks.MockAssetRepo) {
				osNames := []string{"Ubuntu", "Windows Server", "CentOS", "Red Hat"}
				mockRepo.On("GetDistinctOSNames", mock.Anything).
					Return(osNames, nil)
			},
			expectedError: nil,
			validateResult: func(t *testing.T, osNames []string, err error) {
				assert.NoError(t, err)
				assert.Len(t, osNames, 4)
				assert.Contains(t, osNames, "Ubuntu")
				assert.Contains(t, osNames, "Windows Server")
				assert.Contains(t, osNames, "CentOS")
				assert.Contains(t, osNames, "Red Hat")
			},
		},
		{
			name: "empty OS names list",
			setupMock: func(mockRepo *repoMocks.MockAssetRepo) {
				mockRepo.On("GetDistinctOSNames", mock.Anything).
					Return([]string{}, nil)
			},
			expectedError: nil,
			validateResult: func(t *testing.T, osNames []string, err error) {
				assert.NoError(t, err)
				assert.Len(t, osNames, 0)
			},
		},
		{
			name: "repository error",
			setupMock: func(mockRepo *repoMocks.MockAssetRepo) {
				mockRepo.On("GetDistinctOSNames", mock.Anything).
					Return(nil, errors.New("database connection failed"))
			},
			expectedError: asset.ErrOSNamesFailed,
			validateResult: func(t *testing.T, osNames []string, err error) {
				assert.Error(t, err)
				assert.Equal(t, asset.ErrOSNamesFailed, err)
				assert.Nil(t, osNames)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			mockRepo := new(repoMocks.MockAssetRepo)
			tt.setupMock(mockRepo)

			// Create service
			service := asset.NewAssetService(mockRepo)

			// Execute
			ctx := context.Background()
			osNames, err := service.GetDistinctOSNames(ctx)

			// Validate
			tt.validateResult(t, osNames, err)

			// Verify mock expectations
			mockRepo.AssertExpectations(t)
		})
	}
}

func TestAssetService_GetByIDsWithSort(t *testing.T) {
	tests := []struct {
		name           string
		assetUUIDs     []domain.AssetUUID
		sortOptions    []domain.SortOption
		setupMock      func(*repoMocks.MockAssetRepo)
		expectedError  error
		validateResult func(t *testing.T, result []domain.AssetDomain, err error)
	}{
		{
			name: "successful sorted assets retrieval",
			assetUUIDs: []domain.AssetUUID{
				uuid.MustParse("550e8400-e29b-41d4-a716-446655440000"),
				uuid.MustParse("550e8400-e29b-41d4-a716-446655440001"),
			},
			sortOptions: []domain.SortOption{
				{Field: "name", Order: "asc"},
				{Field: "created_at", Order: "desc"},
			},
			setupMock: func(mockRepo *repoMocks.MockAssetRepo) {
				testAssets := []domain.AssetDomain{
					domainFixtures.NewTestAssetDomain(),
					domainFixtures.NewTestAssetDomain(),
				}
				testAssets[0].Name = "Asset A"
				testAssets[1].Name = "Asset B"
				mockRepo.On("GetByIDsWithSort", mock.Anything,
					mock.AnythingOfType("[]uuid.UUID"),
					mock.MatchedBy(func(sorts []domain.SortOption) bool {
						return len(sorts) == 2 &&
							sorts[0].Field == "name" && sorts[0].Order == "asc" &&
							sorts[1].Field == "created_at" && sorts[1].Order == "desc"
					})).Return(testAssets, nil)
			},
			expectedError: nil,
			validateResult: func(t *testing.T, result []domain.AssetDomain, err error) {
				assert.NoError(t, err)
				assert.Len(t, result, 2)
				assert.Equal(t, "Asset A", result[0].Name)
				assert.Equal(t, "Asset B", result[1].Name)
			},
		},
		{
			name:       "empty UUIDs with sort options",
			assetUUIDs: []domain.AssetUUID{},
			sortOptions: []domain.SortOption{
				{Field: "name", Order: "asc"},
			},
			setupMock: func(mockRepo *repoMocks.MockAssetRepo) {
				mockRepo.On("GetByIDsWithSort", mock.Anything,
					[]domain.AssetUUID{},
					mock.AnythingOfType("[]domain.SortOption")).
					Return([]domain.AssetDomain{}, nil)
			},
			expectedError: nil,
			validateResult: func(t *testing.T, result []domain.AssetDomain, err error) {
				assert.NoError(t, err)
				assert.Len(t, result, 0)
			},
		},
		{
			name: "repository error",
			assetUUIDs: []domain.AssetUUID{
				uuid.MustParse("550e8400-e29b-41d4-a716-446655440000"),
			},
			sortOptions: []domain.SortOption{}, setupMock: func(mockRepo *repoMocks.MockAssetRepo) {
				mockRepo.On("GetByIDsWithSort", mock.Anything,
					mock.AnythingOfType("[]uuid.UUID"),
					mock.AnythingOfType("[]domain.SortOption")).
					Return(nil, errors.New("database connection failed"))
			},
			expectedError: errors.New("database connection failed"),
			validateResult: func(t *testing.T, result []domain.AssetDomain, err error) {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "database connection failed")
				assert.Nil(t, result)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			mockRepo := new(repoMocks.MockAssetRepo)
			tt.setupMock(mockRepo)

			// Create service
			service := asset.NewAssetService(mockRepo)

			// Execute
			ctx := context.Background()
			result, err := service.GetByIDsWithSort(ctx, tt.assetUUIDs, tt.sortOptions...)

			// Validate
			tt.validateResult(t, result, err)

			// Verify mock expectations
			mockRepo.AssertExpectations(t)
		})
	}
}

func TestAssetService_GetByIDsWithSort_Success(t *testing.T) {
	// Arrange
	mockRepo := &repoMocks.MockAssetRepo{}
	service := asset.NewAssetService(mockRepo)

	assetUUIDs := []domain.AssetUUID{uuid.New(), uuid.New()}
	sortOptions := []domain.SortOption{
		{Field: "name", Order: "ASC"},
	}
	expectedAssets := []domain.AssetDomain{
		domainFixtures.NewTestAssetDomain(),
		domainFixtures.NewTestAssetDomain(),
	}

	mockRepo.On("GetByIDsWithSort", mock.Anything, assetUUIDs, mock.AnythingOfType("[]domain.SortOption")).
		Return(expectedAssets, nil)

	// Act
	result, err := service.GetByIDsWithSort(context.Background(), assetUUIDs, sortOptions...)

	// Assert
	assert.NoError(t, err)
	assert.Equal(t, expectedAssets, result)
	mockRepo.AssertExpectations(t)
}

func TestAssetService_GetByIDsWithSort_RepositoryError(t *testing.T) {
	// Arrange
	mockRepo := &repoMocks.MockAssetRepo{}
	service := asset.NewAssetService(mockRepo)

	assetUUIDs := []domain.AssetUUID{uuid.New()}
	expectedError := errors.New("repository error")

	mockRepo.On("GetByIDsWithSort", mock.Anything, assetUUIDs, mock.AnythingOfType("[]domain.SortOption")).
		Return(nil, expectedError)

	// Act
	result, err := service.GetByIDsWithSort(context.Background(), assetUUIDs, domain.SortOption{})

	// Assert
	assert.Error(t, err)
	assert.Equal(t, expectedError, err)
	assert.Nil(t, result)
	mockRepo.AssertExpectations(t)
}

func TestAssetService_Get_Success(t *testing.T) {
	// Arrange
	mockRepo := &repoMocks.MockAssetRepo{}
	service := asset.NewAssetService(mockRepo)

	filter := domain.AssetFilters{Name: "test"}
	limit, offset := 10, 0
	sortOptions := []domain.SortOption{{Field: "name", Order: "ASC"}}

	expectedAssets := []domain.AssetDomain{domainFixtures.NewTestAssetDomain()}
	expectedTotal := 1

	mockRepo.On("GetByFilter", mock.Anything, filter, limit, offset, mock.AnythingOfType("[]domain.SortOption")).
		Return(expectedAssets, expectedTotal, nil)

	// Act
	assets, total, err := service.Get(context.Background(), filter, limit, offset, sortOptions...)

	// Assert
	assert.NoError(t, err)
	assert.Equal(t, expectedAssets, assets)
	assert.Equal(t, expectedTotal, total)
	mockRepo.AssertExpectations(t)
}

func TestAssetService_Get_RepositoryError(t *testing.T) {
	// Arrange
	mockRepo := &repoMocks.MockAssetRepo{}
	service := asset.NewAssetService(mockRepo)

	filter := domain.AssetFilters{}
	expectedError := errors.New("repository error")

	mockRepo.On("GetByFilter", mock.Anything, filter, 0, 0, mock.AnythingOfType("[]domain.SortOption")).
		Return(nil, 0, expectedError)

	// Act
	assets, total, err := service.Get(context.Background(), filter, 0, 0)

	// Assert
	assert.Error(t, err)
	assert.Equal(t, expectedError, err)
	assert.Nil(t, assets)
	assert.Equal(t, 0, total)
	mockRepo.AssertExpectations(t)
}

func TestAssetService_UpdateAsset_Success(t *testing.T) {
	// Arrange
	mockRepo := &repoMocks.MockAssetRepo{}
	service := asset.NewAssetService(mockRepo)

	assetDomain := domainFixtures.NewTestAssetDomain()

	mockRepo.On("Update", mock.Anything, assetDomain).
		Return(nil)

	// Act
	err := service.UpdateAsset(context.Background(), assetDomain)

	// Assert
	assert.NoError(t, err)
	mockRepo.AssertExpectations(t)
}

func TestAssetService_UpdateAsset_IPAlreadyExistsError(t *testing.T) {
	// Arrange
	mockRepo := &repoMocks.MockAssetRepo{}
	service := asset.NewAssetService(mockRepo)

	assetDomain := domainFixtures.NewTestAssetDomain()

	mockRepo.On("Update", mock.Anything, assetDomain).
		Return(domain.ErrIPAlreadyExists)

	// Act
	err := service.UpdateAsset(context.Background(), assetDomain)

	// Assert
	assert.Error(t, err)
	assert.Equal(t, domain.ErrIPAlreadyExists, err)
	mockRepo.AssertExpectations(t)
}

func TestAssetService_UpdateAsset_GeneralError(t *testing.T) {
	// Arrange
	mockRepo := &repoMocks.MockAssetRepo{}
	service := asset.NewAssetService(mockRepo)

	assetDomain := domainFixtures.NewTestAssetDomain()
	repositoryError := errors.New("general repository error")

	mockRepo.On("Update", mock.Anything, assetDomain).
		Return(repositoryError)

	// Act
	err := service.UpdateAsset(context.Background(), assetDomain)

	// Assert
	assert.Error(t, err)
	assert.Equal(t, asset.ErrAssetUpdateFailed, err)
	mockRepo.AssertExpectations(t)
}

func TestAssetService_DeleteAssets_SingleAsset(t *testing.T) {
	// Arrange
	mockRepo := &repoMocks.MockAssetRepo{}
	service := asset.NewAssetService(mockRepo)

	assetID := uuid.New().String()
	ids := []string{assetID}

	mockRepo.On("DeleteAssets", mock.Anything, mock.MatchedBy(func(params domain.DeleteParams) bool {
		return params.UUID != nil && params.UUID.String() == assetID
	})).Return(1, nil)

	// Act
	err := service.DeleteAssets(context.Background(), ids, nil, false)

	// Assert
	assert.NoError(t, err)
	mockRepo.AssertExpectations(t)
}

func TestAssetService_DeleteAssets_InvalidUUID(t *testing.T) {
	// Arrange
	mockRepo := &repoMocks.MockAssetRepo{}
	service := asset.NewAssetService(mockRepo)

	ids := []string{"invalid-uuid"}

	// Act
	err := service.DeleteAssets(context.Background(), ids, nil, false)

	// Assert
	assert.Error(t, err)
	assert.Equal(t, asset.ErrInvalidAssetUUID, err)
	mockRepo.AssertExpectations(t)
}

func TestAssetService_DeleteAssets_AllWithFilters(t *testing.T) {
	// Arrange
	mockRepo := &repoMocks.MockAssetRepo{}
	service := asset.NewAssetService(mockRepo)

	ids := []string{"All"}
	filter := &domain.AssetFilters{Name: "test"}

	mockRepo.On("DeleteAssets", mock.Anything, mock.MatchedBy(func(params domain.DeleteParams) bool {
		return params.Filters != nil && params.Filters.Name == "test"
	})).Return(5, nil)

	// Act
	err := service.DeleteAssets(context.Background(), ids, filter, false)

	// Assert
	assert.NoError(t, err)
	mockRepo.AssertExpectations(t)
}

func TestAssetService_DeleteAssets_AllWithoutFilters(t *testing.T) {
	// Arrange
	mockRepo := &repoMocks.MockAssetRepo{}
	service := asset.NewAssetService(mockRepo)

	ids := []string{"All"}

	mockRepo.On("DeleteAssets", mock.Anything, mock.MatchedBy(func(params domain.DeleteParams) bool {
		return params.Filters == nil && params.UUIDs == nil && params.UUID == nil
	})).Return(10, nil)

	// Act
	err := service.DeleteAssets(context.Background(), ids, nil, false)

	// Assert
	assert.NoError(t, err)
	mockRepo.AssertExpectations(t)
}

func TestAssetService_DeleteAssets_MultipleUUIDsWithFilters(t *testing.T) {
	// Arrange
	mockRepo := &repoMocks.MockAssetRepo{}
	service := asset.NewAssetService(mockRepo)

	uuid1 := uuid.New()
	uuid2 := uuid.New()
	ids := []string{uuid1.String(), uuid2.String()}
	filter := &domain.AssetFilters{Name: "test"}

	mockRepo.On("DeleteAssets", mock.Anything, mock.MatchedBy(func(params domain.DeleteParams) bool {
		return params.Filters != nil && len(params.UUIDs) == 2 && !params.Exclude
	})).Return(2, nil)

	// Act
	err := service.DeleteAssets(context.Background(), ids, filter, false)

	// Assert
	assert.NoError(t, err)
	mockRepo.AssertExpectations(t)
}

func TestAssetService_DeleteAssets_ExcludeWithFilters(t *testing.T) {
	// Arrange
	mockRepo := &repoMocks.MockAssetRepo{}
	service := asset.NewAssetService(mockRepo)

	uuid1 := uuid.New()
	ids := []string{uuid1.String()}
	filter := &domain.AssetFilters{Name: "test"}

	mockRepo.On("DeleteAssets", mock.Anything, mock.MatchedBy(func(params domain.DeleteParams) bool {
		return params.Filters != nil && len(params.UUIDs) == 1 && params.Exclude
	})).Return(3, nil)

	// Act
	err := service.DeleteAssets(context.Background(), ids, filter, true)

	// Assert
	assert.NoError(t, err)
	mockRepo.AssertExpectations(t)
}

func TestAssetService_DeleteAssets_ExcludeAll(t *testing.T) {
	// Arrange
	mockRepo := &repoMocks.MockAssetRepo{}
	service := asset.NewAssetService(mockRepo)

	ids := []string{} // Empty IDs with exclude=true means delete all

	mockRepo.On("DeleteAssets", mock.Anything, mock.MatchedBy(func(params domain.DeleteParams) bool {
		return params.Filters == nil && params.UUIDs == nil && params.UUID == nil
	})).Return(10, nil)

	// Act
	err := service.DeleteAssets(context.Background(), ids, nil, true)

	// Assert
	assert.NoError(t, err)
	mockRepo.AssertExpectations(t)
}

func TestAssetService_DeleteAssets_ExcludeSpecificUUIDs(t *testing.T) {
	// Arrange
	mockRepo := &repoMocks.MockAssetRepo{}
	service := asset.NewAssetService(mockRepo)

	uuid1 := uuid.New()
	uuid2 := uuid.New()
	ids := []string{uuid1.String(), uuid2.String()}

	mockRepo.On("DeleteAssets", mock.Anything, mock.MatchedBy(func(params domain.DeleteParams) bool {
		return len(params.UUIDs) == 2 && params.Exclude
	})).Return(8, nil)

	// Act
	err := service.DeleteAssets(context.Background(), ids, nil, true)

	// Assert
	assert.NoError(t, err)
	mockRepo.AssertExpectations(t)
}

func TestAssetService_DeleteAssets_EmptyUUIDs(t *testing.T) {
	// Arrange
	mockRepo := &repoMocks.MockAssetRepo{}
	service := asset.NewAssetService(mockRepo)

	ids := []string{}

	// Act
	err := service.DeleteAssets(context.Background(), ids, nil, false)

	// Assert
	assert.NoError(t, err)
	mockRepo.AssertExpectations(t) // No repo calls should be made
}

func TestAssetService_ExportAssets_Success(t *testing.T) {
	// Arrange
	mockRepo := &repoMocks.MockAssetRepo{}
	service := asset.NewAssetService(mockRepo)

	assetIDs := []domain.AssetUUID{uuid.New()}
	exportType := domain.FullExport
	selectedColumns := []string{"name", "hostname"}

	expectedExportData := domainFixtures.NewTestExportData()

	mockRepo.On("ExportAssets", mock.Anything, assetIDs, exportType, selectedColumns).
		Return(expectedExportData, nil)

	// Act
	result, err := service.ExportAssets(context.Background(), assetIDs, exportType, selectedColumns)

	// Assert
	assert.NoError(t, err)
	assert.Equal(t, expectedExportData, result)
	mockRepo.AssertExpectations(t)
}

func TestAssetService_ExportAssets_RepositoryError(t *testing.T) {
	// Arrange
	mockRepo := &repoMocks.MockAssetRepo{}
	service := asset.NewAssetService(mockRepo)

	assetIDs := []domain.AssetUUID{uuid.New()}
	repositoryError := errors.New("repository error")

	mockRepo.On("ExportAssets", mock.Anything, assetIDs, domain.FullExport, []string(nil)).
		Return(nil, repositoryError)

	// Act
	result, err := service.ExportAssets(context.Background(), assetIDs, domain.FullExport, nil)

	// Assert
	assert.Error(t, err)
	assert.Equal(t, asset.ErrExportFailed, err)
	assert.Nil(t, result)
	mockRepo.AssertExpectations(t)
}

func TestAssetService_GenerateCSV_Success(t *testing.T) {
	// Arrange
	mockRepo := &repoMocks.MockAssetRepo{}
	service := asset.NewAssetService(mockRepo)

	exportData := domainFixtures.NewTestExportData()

	// Act
	result, err := service.GenerateCSV(context.Background(), exportData)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Greater(t, len(result), 0)

	// Verify CSV contains headers
	csvContent := string(result)
	assert.Contains(t, csvContent, "id")
	assert.Contains(t, csvContent, "name")
}

func TestAssetService_GenerateCSV_NilExportData(t *testing.T) {
	// Arrange
	mockRepo := &repoMocks.MockAssetRepo{}
	service := asset.NewAssetService(mockRepo)

	// Act
	result, err := service.GenerateCSV(context.Background(), nil)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "export data is nil")
}

func TestAssetService_GenerateCSV_EmptyExportData(t *testing.T) {
	// Arrange
	mockRepo := &repoMocks.MockAssetRepo{}
	service := asset.NewAssetService(mockRepo)

	exportData := &domain.ExportData{
		Assets:    []map[string]interface{}{},
		Ports:     []map[string]interface{}{},
		VMwareVMs: []map[string]interface{}{},
		AssetIPs:  []map[string]interface{}{},
	}

	// Act
	result, err := service.GenerateCSV(context.Background(), exportData)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, result)
	// Should contain at least headers even with empty data
	csvContent := string(result)
	assert.NotEmpty(t, csvContent)
}

// Test error handling in delete assets
func TestAssetService_DeleteAssets_RepositoryError(t *testing.T) {
	// Arrange
	mockRepo := &repoMocks.MockAssetRepo{}
	service := asset.NewAssetService(mockRepo)

	assetID := uuid.New().String()
	ids := []string{assetID}
	repositoryError := errors.New("repository error")

	mockRepo.On("DeleteAssets", mock.Anything, mock.Anything).
		Return(0, repositoryError)

	// Act
	err := service.DeleteAssets(context.Background(), ids, nil, false)

	// Assert
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to delete asset")
	mockRepo.AssertExpectations(t)
}

// Test complex CSV generation scenarios
func TestAssetService_GenerateCSV_WithIPsAndVMs(t *testing.T) {
	// Arrange
	mockRepo := &repoMocks.MockAssetRepo{}
	service := asset.NewAssetService(mockRepo)

	assetID := uuid.New().String()
	exportData := &domain.ExportData{
		Assets: []map[string]interface{}{
			{
				"id":       assetID,
				"name":     "Test Asset",
				"hostname": "test-host",
			},
		},
		AssetIPs: []map[string]interface{}{
			{
				"id":         uuid.New().String(),
				"asset_id":   assetID,
				"ip_address": "192.168.1.100",
			},
		},
		VMwareVMs: []map[string]interface{}{
			{
				"vm_id":    "vm-123",
				"asset_id": assetID,
				"vm_name":  "Test VM",
			},
		},
		Ports: []map[string]interface{}{},
	}

	// Act
	result, err := service.GenerateCSV(context.Background(), exportData)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, result)

	csvContent := string(result)
	// Should contain asset data
	assert.Contains(t, csvContent, "Test Asset")
	assert.Contains(t, csvContent, "192.168.1.100")
	assert.Contains(t, csvContent, "Test VM")
}

// Dashboard-related tests

func TestAssetService_GetDashboardAssetCount(t *testing.T) {
	mockRepo := &repoMocks.MockAssetRepo{}
	service := asset.NewAssetService(mockRepo)

	mockRepo.On("GetAssetCount", mock.Anything).Return(123, nil)
	ctx := context.Background()
	result, err := service.GetDashboardAssetCount(ctx)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 123, result.Count)
	assert.Len(t, result.Contents, 2)
	assert.Equal(t, "offline", result.Contents[0].Source)
	assert.Equal(t, 100, result.Contents[0].Percent)
	assert.Equal(t, "online", result.Contents[1].Source)
	assert.Equal(t, 0, result.Contents[1].Percent)
	mockRepo.AssertExpectations(t)

	mockRepo2 := &repoMocks.MockAssetRepo{}
	service2 := asset.NewAssetService(mockRepo2)
	dbErr := errors.New("db error")
	mockRepo2.On("GetAssetCount", mock.Anything).Return(0, dbErr)
	_, err = service2.GetDashboardAssetCount(ctx)
	assert.Error(t, err)
	assert.Equal(t, dbErr, err)
}

func TestAssetService_GetDashboardAssetPerScanner(t *testing.T) {
	mockRepo := &repoMocks.MockAssetRepo{}
	service := asset.NewAssetService(mockRepo)
	scannerCounts := []domain.ScannerTypeCount{{Source: "nmap", Count: 10}, {Source: "nessus", Count: 5}}
	mockRepo.On("GetAssetCountByScanner", mock.Anything).Return(scannerCounts, nil)
	ctx := context.Background()
	result, err := service.GetDashboardAssetPerScanner(ctx)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Len(t, result.Contents, 2)
	assert.Equal(t, "nmap", result.Contents[0].Source)
	assert.Equal(t, 10, result.Contents[0].Count)
	assert.Equal(t, "nessus", result.Contents[1].Source)
	assert.Equal(t, 5, result.Contents[1].Count)
	mockRepo.AssertExpectations(t)

	mockRepo2 := &repoMocks.MockAssetRepo{}
	service2 := asset.NewAssetService(mockRepo2)
	dbErr := errors.New("repo error")
	mockRepo2.On("GetAssetCountByScanner", mock.Anything).Return(nil, dbErr)
	_, err = service2.GetDashboardAssetPerScanner(ctx)
	assert.Error(t, err)
	assert.Equal(t, dbErr, err)
}

func TestAssetService_GetDashboardLoggingCompleted(t *testing.T) {
	mockRepo := &repoMocks.MockAssetRepo{}
	service := asset.NewAssetService(mockRepo)
	osStats := []domain.OSLoggingStats{{Source: "Linux", Count: 7, Total: 10}, {Source: "Windows", Count: 3, Total: 5}}
	mockRepo.On("GetLoggingCompletedByOS", mock.Anything).Return(osStats, nil)
	ctx := context.Background()
	result, err := service.GetDashboardLoggingCompleted(ctx)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Len(t, result.Contents, 2)
	assert.Equal(t, "Linux", result.Contents[0].Source)
	assert.Equal(t, 7, result.Contents[0].Count)
	assert.Equal(t, 10, result.Contents[0].Total)
	assert.Equal(t, "Windows", result.Contents[1].Source)
	assert.Equal(t, 3, result.Contents[1].Count)
	assert.Equal(t, 5, result.Contents[1].Total)
	mockRepo.AssertExpectations(t)

	mockRepo2 := &repoMocks.MockAssetRepo{}
	service2 := asset.NewAssetService(mockRepo2)
	dbErr := errors.New("os error")
	mockRepo2.On("GetLoggingCompletedByOS", mock.Anything).Return(nil, dbErr)
	_, err = service2.GetDashboardLoggingCompleted(ctx)
	assert.Error(t, err)
	assert.Equal(t, dbErr, err)
}

func TestAssetService_GetDashboardAssetsPerSource(t *testing.T) {
	mockRepo := &repoMocks.MockAssetRepo{}
	service := asset.NewAssetService(mockRepo)
	sourceStats := []domain.AssetSourceStats{{Source: "Linux", Percent: 60}, {Source: "Windows", Percent: 40}}
	mockRepo.On("GetAssetsPerSource", mock.Anything).Return(sourceStats, 100, nil)
	ctx := context.Background()
	result, err := service.GetDashboardAssetsPerSource(ctx)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 100, result.Count)
	assert.Len(t, result.Contents, 2)
	assert.Equal(t, "Linux", result.Contents[0].Source)
	assert.Equal(t, 60, result.Contents[0].Percent)
	assert.Equal(t, "Windows", result.Contents[1].Source)
	assert.Equal(t, 40, result.Contents[1].Percent)
	mockRepo.AssertExpectations(t)

	mockRepo2 := &repoMocks.MockAssetRepo{}
	service2 := asset.NewAssetService(mockRepo2)
	dbErr := errors.New("source error")
	mockRepo2.On("GetAssetsPerSource", mock.Anything).Return(nil, 0, dbErr)
	_, err = service2.GetDashboardAssetsPerSource(ctx)
	assert.Error(t, err)
	assert.Equal(t, dbErr, err)
}
