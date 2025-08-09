package service_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"gitlab.apk-group.net/siem/backend/asset-discovery/api/pb"
	"gitlab.apk-group.net/siem/backend/asset-discovery/api/service"
	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/domain"
	apiFixtures "gitlab.apk-group.net/siem/backend/asset-discovery/tests/fixtures/api"
	serviceMocks "gitlab.apk-group.net/siem/backend/asset-discovery/tests/mocks/service"
)

func TestAssetService_CreateAsset(t *testing.T) {
	tests := []struct {
		name             string
		request          *pb.CreateAssetRequest
		setupMock        func(*serviceMocks.MockAssetService)
		expectedError    error
		validateResponse func(t *testing.T, response *pb.CreateAssetResponse)
	}{
		{
			name:    "successful asset creation",
			request: apiFixtures.NewTestCreateAssetRequest(),
			setupMock: func(mockService *serviceMocks.MockAssetService) {
				expectedID := uuid.New()
				mockService.On("CreateAsset", mock.Anything, mock.AnythingOfType("domain.AssetDomain"), []string(nil)).
					Return(expectedID, nil)
			},
			expectedError: nil,
			validateResponse: func(t *testing.T, response *pb.CreateAssetResponse) {
				assert.NotNil(t, response)
				assert.NotEmpty(t, response.Id)
				// Validate UUID format
				_, err := uuid.Parse(response.Id)
				assert.NoError(t, err)
			},
		},
		{
			name:    "asset creation with ports",
			request: apiFixtures.NewTestCreateAssetRequestWithPorts(3),
			setupMock: func(mockService *serviceMocks.MockAssetService) {
				expectedID := uuid.New()
				mockService.On("CreateAsset", mock.Anything, mock.MatchedBy(func(asset domain.AssetDomain) bool {
					// Verify that ports were correctly transformed
					return len(asset.Ports) == 3 &&
						asset.Ports[0].Protocol == "tcp" &&
						asset.Ports[0].State == "open"
				}), []string(nil)).Return(expectedID, nil)
			},
			expectedError: nil,
			validateResponse: func(t *testing.T, response *pb.CreateAssetResponse) {
				assert.NotNil(t, response)
				assert.NotEmpty(t, response.Id)
			},
		},
		{
			name:    "asset creation with IPs",
			request: apiFixtures.NewTestCreateAssetRequestWithIPs([]string{"192.168.1.1", "10.0.0.1"}),
			setupMock: func(mockService *serviceMocks.MockAssetService) {
				expectedID := uuid.New()
				mockService.On("CreateAsset", mock.Anything, mock.MatchedBy(func(asset domain.AssetDomain) bool {
					// Verify that IPs were correctly transformed
					return len(asset.AssetIPs) == 2 &&
						asset.AssetIPs[0].IP == "192.168.1.1" &&
						asset.AssetIPs[1].IP == "10.0.0.1"
				}), []string(nil)).Return(expectedID, nil)
			},
			expectedError: nil,
			validateResponse: func(t *testing.T, response *pb.CreateAssetResponse) {
				assert.NotNil(t, response)
				assert.NotEmpty(t, response.Id)
			},
		},
		{
			name:    "IP already exists error",
			request: apiFixtures.NewTestCreateAssetRequestWithIP("192.168.1.100"),
			setupMock: func(mockService *serviceMocks.MockAssetService) {
				mockService.On("CreateAsset", mock.Anything, mock.AnythingOfType("domain.AssetDomain"), []string(nil)).
					Return(uuid.Nil, service.ErrIPAlreadyExists)
			},
			expectedError: service.ErrIPAlreadyExists,
			validateResponse: func(t *testing.T, response *pb.CreateAssetResponse) {
				assert.Nil(t, response)
			},
		},
		{
			name:    "hostname already exists error",
			request: apiFixtures.NewTestCreateAssetRequestWithHostname("existing-host"),
			setupMock: func(mockService *serviceMocks.MockAssetService) {
				mockService.On("CreateAsset", mock.Anything, mock.AnythingOfType("domain.AssetDomain"), []string(nil)).
					Return(uuid.Nil, service.ErrHostnameAlreadyExists)
			},
			expectedError: service.ErrHostnameAlreadyExists,
			validateResponse: func(t *testing.T, response *pb.CreateAssetResponse) {
				assert.Nil(t, response)
			},
		},
		{
			name:    "internal service error",
			request: apiFixtures.NewTestCreateAssetRequest(),
			setupMock: func(mockService *serviceMocks.MockAssetService) {
				mockService.On("CreateAsset", mock.Anything, mock.AnythingOfType("domain.AssetDomain"), []string(nil)).
					Return(uuid.Nil, errors.New("database connection failed"))
			},
			expectedError: errors.New("database connection failed"),
			validateResponse: func(t *testing.T, response *pb.CreateAssetResponse) {
				assert.Nil(t, response)
			},
		},
		{
			name:    "minimal valid request",
			request: apiFixtures.NewTestCreateAssetRequestMinimal(),
			setupMock: func(mockService *serviceMocks.MockAssetService) {
				expectedID := uuid.New()
				mockService.On("CreateAsset", mock.Anything, mock.MatchedBy(func(asset domain.AssetDomain) bool {
					// Verify minimal required fields are set
					return asset.Hostname == "minimal-host" &&
						asset.Type == "Unknown" &&
						asset.DiscoveredBy == "System User" &&
						len(asset.Ports) == 0 &&
						len(asset.AssetIPs) == 0
				}), []string(nil)).Return(expectedID, nil)
			},
			expectedError: nil,
			validateResponse: func(t *testing.T, response *pb.CreateAssetResponse) {
				assert.NotNil(t, response)
				assert.NotEmpty(t, response.Id)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup - Create mock internal service and real API service
			mockInternalService := new(serviceMocks.MockAssetService)
			tt.setupMock(mockInternalService)

			// Create real API service with mocked internal service
			apiService := service.NewAssetService(mockInternalService)

			// Execute the actual service method
			ctx := context.Background()
			response, err := apiService.CreateAsset(ctx, tt.request)

			// Assertions
			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedError.Error(), err.Error())
				assert.Nil(t, response)
			} else {
				assert.NoError(t, err)
				tt.validateResponse(t, response)
			}

			// Verify mock expectations
			mockInternalService.AssertExpectations(t)
		})
	}
}

func TestAssetService_CreateAsset_RequestTransformation(t *testing.T) {
	tests := []struct {
		name           string
		request        *pb.CreateAssetRequest
		validateDomain func(t *testing.T, domain domain.AssetDomain)
	}{
		{
			name:    "request with all fields populated",
			request: apiFixtures.NewTestCreateAssetRequest(),
			validateDomain: func(t *testing.T, domain domain.AssetDomain) {
				assert.Equal(t, "Test Asset", domain.Name)
				assert.Equal(t, "test.local", domain.Domain)
				assert.Equal(t, "test-host", domain.Hostname)
				assert.Equal(t, "Ubuntu", domain.OSName)
				assert.Equal(t, "20.04", domain.OSVersion)
				assert.Equal(t, "Server", domain.Type)
				assert.Equal(t, "Test asset for unit tests", domain.Description)
				assert.Equal(t, 1, domain.Risk)
				assert.Equal(t, false, domain.LoggingCompleted)
				assert.Equal(t, 100, domain.AssetValue)
				assert.NotZero(t, domain.CreatedAt)
			},
		},
		{
			name: "request with optional fields empty",
			request: &pb.CreateAssetRequest{
				Hostname: "minimal-host",
				Type:     "Server",
			},
			validateDomain: func(t *testing.T, domain domain.AssetDomain) {
				assert.Equal(t, "", domain.Name)
				assert.Equal(t, "", domain.Domain)
				assert.Equal(t, "minimal-host", domain.Hostname)
				assert.Equal(t, "", domain.OSName)
				assert.Equal(t, "", domain.OSVersion)
				assert.Equal(t, "Server", domain.Type)
				assert.Equal(t, "", domain.Description)
				assert.Equal(t, 0, domain.Risk)
				assert.Equal(t, false, domain.LoggingCompleted)
				assert.Equal(t, 0, domain.AssetValue)
			},
		},
		{
			name:    "request with complex ports",
			request: apiFixtures.NewTestCreateAssetRequestWithPorts(2),
			validateDomain: func(t *testing.T, domain domain.AssetDomain) {
				assert.Len(t, domain.Ports, 2)
				assert.Equal(t, 80, domain.Ports[0].PortNumber)
				assert.Equal(t, 81, domain.Ports[1].PortNumber)
				assert.Equal(t, "tcp", domain.Ports[0].Protocol)
				assert.Equal(t, "open", domain.Ports[0].State)
				assert.Equal(t, "http", domain.Ports[0].ServiceName)
				assert.Equal(t, domain.ID.String(), domain.Ports[0].AssetID)
			},
		},
		{
			name:    "request with multiple IPs",
			request: apiFixtures.NewTestCreateAssetRequestWithIPs([]string{"192.168.1.1", "10.0.0.1"}),
			validateDomain: func(t *testing.T, domain domain.AssetDomain) {
				assert.Len(t, domain.AssetIPs, 2)
				assert.Equal(t, "192.168.1.1", domain.AssetIPs[0].IP)
				assert.Equal(t, "10.0.0.1", domain.AssetIPs[1].IP)
				assert.Equal(t, domain.ID.String(), domain.AssetIPs[0].AssetID)
				assert.NotEmpty(t, domain.AssetIPs[0].MACAddress)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id := uuid.New()
			now := time.Now()

			// Transform ports (same logic as in CreateAsset)
			ports := make([]domain.Port, 0, len(tt.request.GetPorts()))
			for _, p := range tt.request.GetPorts() {
				ports = append(ports, domain.Port{
					ID:             uuid.New().String(),
					AssetID:        id.String(),
					PortNumber:     int(p.GetPortNumber()),
					Protocol:       p.GetProtocol(),
					State:          p.GetState(),
					ServiceName:    p.GetServiceName(),
					ServiceVersion: p.GetServiceVersion(),
					Description:    p.GetDescription(),
					DiscoveredAt:   now,
				})
			}

			// Transform IPs (same logic as in CreateAsset)
			ips := make([]domain.AssetIP, 0, len(tt.request.GetAssetIps()))
			for _, ip := range tt.request.GetAssetIps() {
				ips = append(ips, domain.AssetIP{
					AssetID:    id.String(),
					IP:         ip.GetIp(),
					MACAddress: ip.GetMacAddress(),
				})
			}

			// Create domain object
			assetDomain := domain.AssetDomain{
				ID:               id,
				Name:             tt.request.GetName(),
				Domain:           tt.request.GetDomain(),
				Hostname:         tt.request.GetHostname(),
				OSName:           tt.request.GetOsName(),
				OSVersion:        tt.request.GetOsVersion(),
				Type:             tt.request.GetType(),
				Description:      tt.request.GetDescription(),
				Risk:             int(tt.request.GetRisk()),
				LoggingCompleted: tt.request.GetLoggingCompleted(),
				AssetValue:       int(tt.request.GetAssetValue()),
				CreatedAt:        now,
				Ports:            ports,
				AssetIPs:         ips,
			}

			// Validate transformation
			tt.validateDomain(t, assetDomain)
		})
	}
}

func TestAssetService_CreateAsset_ErrorHandling(t *testing.T) {
	tests := []struct {
		name          string
		serviceError  error
		expectedError error
	}{
		{
			name:          "IP already exists",
			serviceError:  service.ErrIPAlreadyExists,
			expectedError: service.ErrIPAlreadyExists,
		},
		{
			name:          "hostname already exists",
			serviceError:  service.ErrHostnameAlreadyExists,
			expectedError: service.ErrHostnameAlreadyExists,
		},
		{
			name:          "asset creation failed",
			serviceError:  service.ErrAssetCreateFailed,
			expectedError: service.ErrAssetCreateFailed,
		},
		{
			name:          "generic error",
			serviceError:  errors.New("unexpected error"),
			expectedError: errors.New("unexpected error"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mock internal service and real API service
			mockInternalService := new(serviceMocks.MockAssetService)
			mockInternalService.On("CreateAsset", mock.Anything, mock.AnythingOfType("domain.AssetDomain"), []string(nil)).
				Return(uuid.Nil, tt.serviceError)

			// Create real API service with mocked internal service
			apiService := service.NewAssetService(mockInternalService)

			// Test error propagation by calling the actual service
			ctx := context.Background()
			request := apiFixtures.NewTestCreateAssetRequest()

			_, err := apiService.CreateAsset(ctx, request)

			assert.Error(t, err)
			assert.Equal(t, tt.expectedError.Error(), err.Error())

			mockInternalService.AssertExpectations(t)
		})
	}
}

func TestAssetService_GetAsset(t *testing.T) {
	tests := []struct {
		name             string
		request          *pb.GetAssetByIDRequest
		setupMock        func(*serviceMocks.MockAssetService)
		expectedError    error
		validateResponse func(t *testing.T, response *pb.GetAssetResponse)
	}{
		{
			name:    "successful asset retrieval",
			request: &pb.GetAssetByIDRequest{Id: "550e8400-e29b-41d4-a716-446655440000"},
			setupMock: func(mockService *serviceMocks.MockAssetService) {
				testUUID := uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")
				testAsset := domain.AssetDomain{
					ID:       testUUID,
					Name:     "Test Asset",
					Hostname: "test-host",
					Type:     "Server",
				}
				mockService.On("GetByID", mock.Anything, testUUID).
					Return(&testAsset, nil)
			},
			expectedError: nil,
			validateResponse: func(t *testing.T, response *pb.GetAssetResponse) {
				assert.NotNil(t, response)
				assert.NotNil(t, response.Asset)
				assert.Equal(t, "550e8400-e29b-41d4-a716-446655440000", response.Asset.Id)
				assert.Equal(t, "Test Asset", response.Asset.Name)
				assert.Equal(t, "test-host", response.Asset.Hostname)
			},
		},
		{
			name:    "invalid asset UUID",
			request: &pb.GetAssetByIDRequest{Id: "invalid-uuid"},
			setupMock: func(mockService *serviceMocks.MockAssetService) {
				// No mock setup needed as UUID parsing should fail
			},
			expectedError: service.ErrInvalidAssetUUID,
			validateResponse: func(t *testing.T, response *pb.GetAssetResponse) {
				assert.Nil(t, response)
			},
		},
		{
			name:    "asset not found",
			request: &pb.GetAssetByIDRequest{Id: "550e8400-e29b-41d4-a716-446655440000"},
			setupMock: func(mockService *serviceMocks.MockAssetService) {
				testUUID := uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")
				mockService.On("GetByID", mock.Anything, testUUID).
					Return((*domain.AssetDomain)(nil), service.ErrAssetNotFound)
			},
			expectedError: nil,
			validateResponse: func(t *testing.T, response *pb.GetAssetResponse) {
				assert.NotNil(t, response)
				assert.Nil(t, response.Asset)
			},
		},
		{
			name:    "internal service error",
			request: &pb.GetAssetByIDRequest{Id: "550e8400-e29b-41d4-a716-446655440000"},
			setupMock: func(mockService *serviceMocks.MockAssetService) {
				testUUID := uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")
				mockService.On("GetByID", mock.Anything, testUUID).
					Return((*domain.AssetDomain)(nil), errors.New("database connection failed"))
			},
			expectedError: errors.New("database connection failed"),
			validateResponse: func(t *testing.T, response *pb.GetAssetResponse) {
				assert.Nil(t, response)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup - Create mock internal service and real API service
			mockInternalService := new(serviceMocks.MockAssetService)
			tt.setupMock(mockInternalService)

			// Create real API service with mocked internal service
			apiService := service.NewAssetService(mockInternalService)

			// Execute the actual service method
			ctx := context.Background()
			response, err := apiService.GetAsset(ctx, tt.request)

			// Assertions
			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedError.Error(), err.Error())
				assert.Nil(t, response)
			} else {
				assert.NoError(t, err)
				tt.validateResponse(t, response)
			}

			// Verify mock expectations
			mockInternalService.AssertExpectations(t)
		})
	}
}

func TestAssetService_GetAssets(t *testing.T) {
	tests := []struct {
		name             string
		request          *pb.GetAssetsRequest
		setupMock        func(*serviceMocks.MockAssetService)
		expectedError    error
		validateResponse func(t *testing.T, response *pb.GetAssetsResponse)
	}{
		{
			name: "successful assets retrieval",
			request: &pb.GetAssetsRequest{
				Limit: 10,
				Page:  0,
				Filter: &pb.Filter{
					Name: "test",
				},
			},
			setupMock: func(mockService *serviceMocks.MockAssetService) {
				testAssets := []domain.AssetDomain{
					{
						ID:       uuid.New(),
						Name:     "Test Asset 1",
						Hostname: "test-host-1",
						Type:     "Server",
					},
					{
						ID:       uuid.New(),
						Name:     "Test Asset 2",
						Hostname: "test-host-2",
						Type:     "Server",
					},
				}
				mockService.On("Get", mock.Anything,
					mock.MatchedBy(func(filter domain.AssetFilters) bool {
						return filter.Name == "test"
					}),
					10, 0, mock.AnythingOfType("[]domain.SortOption")).
					Return(testAssets, 2, nil)
			},
			expectedError: nil,
			validateResponse: func(t *testing.T, response *pb.GetAssetsResponse) {
				assert.NotNil(t, response)
				assert.Len(t, response.Contents, 2)
				assert.Equal(t, int32(2), response.Count)
				assert.Equal(t, "Test Asset 1", response.Contents[0].Name)
				assert.Equal(t, "Test Asset 2", response.Contents[1].Name)
			},
		},
		{
			name: "assets retrieval with pagination",
			request: &pb.GetAssetsRequest{
				Limit: 5,
				Page:  2,
			},
			setupMock: func(mockService *serviceMocks.MockAssetService) {
				testAssets := []domain.AssetDomain{
					{
						ID:       uuid.New(),
						Name:     "Test Asset 11",
						Hostname: "test-host-11",
						Type:     "Server",
					},
				}
				mockService.On("Get", mock.Anything,
					mock.AnythingOfType("domain.AssetFilters"),
					5, 10, mock.AnythingOfType("[]domain.SortOption")).
					Return(testAssets, 15, nil)
			},
			expectedError: nil,
			validateResponse: func(t *testing.T, response *pb.GetAssetsResponse) {
				assert.NotNil(t, response)
				assert.Len(t, response.Contents, 1)
				assert.Equal(t, int32(15), response.Count)
				assert.Equal(t, "Test Asset 11", response.Contents[0].Name)
			},
		},
		{
			name: "assets retrieval with sorting",
			request: &pb.GetAssetsRequest{
				Limit: 10,
				Page:  0,
				Sort: []*pb.SortField{
					{Field: "name", Order: "asc"},
					{Field: "created_at", Order: "desc"},
				},
			},
			setupMock: func(mockService *serviceMocks.MockAssetService) {
				testAssets := []domain.AssetDomain{}
				mockService.On("Get", mock.Anything,
					mock.AnythingOfType("domain.AssetFilters"),
					10, 0,
					mock.MatchedBy(func(sorts []domain.SortOption) bool {
						return len(sorts) == 2 &&
							sorts[0].Field == "name" && sorts[0].Order == "asc" &&
							sorts[1].Field == "created_at" && sorts[1].Order == "desc"
					})).
					Return(testAssets, 0, nil)
			},
			expectedError: nil,
			validateResponse: func(t *testing.T, response *pb.GetAssetsResponse) {
				assert.NotNil(t, response)
				assert.Len(t, response.Contents, 0)
				assert.Equal(t, int32(0), response.Count)
			},
		},
		{
			name: "negative limit should be corrected to 0",
			request: &pb.GetAssetsRequest{
				Limit: -5,
				Page:  0,
			},
			setupMock: func(mockService *serviceMocks.MockAssetService) {
				testAssets := []domain.AssetDomain{
					{
						ID:       uuid.New(),
						Name:     "Test Asset",
						Hostname: "test-host",
						Type:     "Server",
					},
				}
				mockService.On("Get", mock.Anything,
					mock.AnythingOfType("domain.AssetFilters"),
					0, 0, mock.AnythingOfType("[]domain.SortOption")).
					Return(testAssets, 1, nil)
			},
			expectedError: nil,
			validateResponse: func(t *testing.T, response *pb.GetAssetsResponse) {
				assert.NotNil(t, response)
				assert.Len(t, response.Contents, 1)
				assert.Equal(t, int32(1), response.Count)
			},
		},
		{
			name: "negative page should be corrected to 0 offset",
			request: &pb.GetAssetsRequest{
				Limit: 10,
				Page:  -2,
			},
			setupMock: func(mockService *serviceMocks.MockAssetService) {
				testAssets := []domain.AssetDomain{
					{
						ID:       uuid.New(),
						Name:     "Test Asset",
						Hostname: "test-host",
						Type:     "Server",
					},
				}
				mockService.On("Get", mock.Anything,
					mock.AnythingOfType("domain.AssetFilters"),
					10, 0, mock.AnythingOfType("[]domain.SortOption")).
					Return(testAssets, 1, nil)
			},
			expectedError: nil,
			validateResponse: func(t *testing.T, response *pb.GetAssetsResponse) {
				assert.NotNil(t, response)
				assert.Len(t, response.Contents, 1)
				assert.Equal(t, int32(1), response.Count)
			},
		},
		{
			name: "internal service error",
			request: &pb.GetAssetsRequest{
				Limit: 10,
				Page:  0,
			},
			setupMock: func(mockService *serviceMocks.MockAssetService) {
				mockService.On("Get", mock.Anything,
					mock.AnythingOfType("domain.AssetFilters"),
					10, 0, mock.AnythingOfType("[]domain.SortOption")).
					Return([]domain.AssetDomain{}, 0, errors.New("database connection failed"))
			},
			expectedError: errors.New("database connection failed"),
			validateResponse: func(t *testing.T, response *pb.GetAssetsResponse) {
				assert.Nil(t, response)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup - Create mock internal service and real API service
			mockInternalService := new(serviceMocks.MockAssetService)
			tt.setupMock(mockInternalService)

			// Create real API service with mocked internal service
			apiService := service.NewAssetService(mockInternalService)

			// Execute the actual service method
			ctx := context.Background()
			response, err := apiService.GetAssets(ctx, tt.request)

			// Assertions
			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedError.Error(), err.Error())
				assert.Nil(t, response)
			} else {
				assert.NoError(t, err)
				tt.validateResponse(t, response)
			}

			// Verify mock expectations
			mockInternalService.AssertExpectations(t)
		})
	}
}

func TestAssetService_UpdateAsset(t *testing.T) {
	tests := []struct {
		name             string
		request          *pb.UpdateAssetRequest
		setupMock        func(*serviceMocks.MockAssetService)
		expectedError    error
		validateResponse func(t *testing.T, response *pb.UpdateAssetResponse)
	}{
		{
			name: "successful asset update",
			request: &pb.UpdateAssetRequest{
				Id:       "550e8400-e29b-41d4-a716-446655440000",
				Name:     "Updated Asset",
				Hostname: "updated-host",
				Type:     "Server",
			},
			setupMock: func(mockService *serviceMocks.MockAssetService) {
				mockService.On("UpdateAsset", mock.Anything, mock.MatchedBy(func(asset domain.AssetDomain) bool {
					return asset.ID.String() == "550e8400-e29b-41d4-a716-446655440000" &&
						asset.Name == "Updated Asset" &&
						asset.Hostname == "updated-host"
				})).Return(nil)
			},
			expectedError: nil,
			validateResponse: func(t *testing.T, response *pb.UpdateAssetResponse) {
				assert.NotNil(t, response)
			},
		},
		{
			name: "asset update with ports and IPs",
			request: &pb.UpdateAssetRequest{
				Id:       "550e8400-e29b-41d4-a716-446655440000",
				Name:     "Updated Asset",
				Hostname: "updated-host",
				Type:     "Server",
				Ports: []*pb.Port{
					{
						Id:          uuid.New().String(),
						PortNumber:  80,
						Protocol:    "tcp",
						State:       "open",
						ServiceName: "http",
					},
				},
				AssetIps: []*pb.AssetIP{
					{
						Ip:         "192.168.1.100",
						MacAddress: "00:11:22:33:44:55",
					},
				},
			},
			setupMock: func(mockService *serviceMocks.MockAssetService) {
				mockService.On("UpdateAsset", mock.Anything, mock.MatchedBy(func(asset domain.AssetDomain) bool {
					return len(asset.Ports) == 1 && len(asset.AssetIPs) == 1 &&
						asset.Ports[0].PortNumber == 80 &&
						asset.AssetIPs[0].IP == "192.168.1.100"
				})).Return(nil)
			},
			expectedError: nil,
			validateResponse: func(t *testing.T, response *pb.UpdateAssetResponse) {
				assert.NotNil(t, response)
			},
		},
		{
			name: "invalid asset UUID",
			request: &pb.UpdateAssetRequest{
				Id:       "invalid-uuid",
				Name:     "Updated Asset",
				Hostname: "updated-host",
			},
			setupMock: func(mockService *serviceMocks.MockAssetService) {
				// No mock setup needed as UUID parsing should fail
			},
			expectedError: service.ErrInvalidAssetUUID,
			validateResponse: func(t *testing.T, response *pb.UpdateAssetResponse) {
				assert.Nil(t, response)
			},
		},
		{
			name: "IP already exists error",
			request: &pb.UpdateAssetRequest{
				Id:       "550e8400-e29b-41d4-a716-446655440000",
				Name:     "Updated Asset",
				Hostname: "updated-host",
				AssetIps: []*pb.AssetIP{
					{
						Ip:         "192.168.1.100",
						MacAddress: "00:11:22:33:44:55",
					},
				},
			},
			setupMock: func(mockService *serviceMocks.MockAssetService) {
				mockService.On("UpdateAsset", mock.Anything, mock.AnythingOfType("domain.AssetDomain")).
					Return(service.ErrIPAlreadyExists)
			},
			expectedError: service.ErrIPAlreadyExists,
			validateResponse: func(t *testing.T, response *pb.UpdateAssetResponse) {
				assert.Nil(t, response)
			},
		},
		{
			name: "hostname already exists error",
			request: &pb.UpdateAssetRequest{
				Id:       "550e8400-e29b-41d4-a716-446655440000",
				Name:     "Updated Asset",
				Hostname: "existing-host",
			},
			setupMock: func(mockService *serviceMocks.MockAssetService) {
				mockService.On("UpdateAsset", mock.Anything, mock.AnythingOfType("domain.AssetDomain")).
					Return(service.ErrHostnameAlreadyExists)
			},
			expectedError: service.ErrHostnameAlreadyExists,
			validateResponse: func(t *testing.T, response *pb.UpdateAssetResponse) {
				assert.Nil(t, response)
			},
		},
		{
			name: "internal service error",
			request: &pb.UpdateAssetRequest{
				Id:       "550e8400-e29b-41d4-a716-446655440000",
				Name:     "Updated Asset",
				Hostname: "updated-host",
			},
			setupMock: func(mockService *serviceMocks.MockAssetService) {
				mockService.On("UpdateAsset", mock.Anything, mock.AnythingOfType("domain.AssetDomain")).
					Return(errors.New("database connection failed"))
			},
			expectedError: errors.New("database connection failed"),
			validateResponse: func(t *testing.T, response *pb.UpdateAssetResponse) {
				assert.Nil(t, response)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup - Create mock internal service and real API service
			mockInternalService := new(serviceMocks.MockAssetService)
			tt.setupMock(mockInternalService)

			// Create real API service with mocked internal service
			apiService := service.NewAssetService(mockInternalService)

			// Execute the actual service method
			ctx := context.Background()
			response, err := apiService.UpdateAsset(ctx, tt.request)

			// Assertions
			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedError.Error(), err.Error())
				assert.Nil(t, response)
			} else {
				assert.NoError(t, err)
				tt.validateResponse(t, response)
			}

			// Verify mock expectations
			mockInternalService.AssertExpectations(t)
		})
	}
}

func TestAssetService_DeleteAssets(t *testing.T) {
	tests := []struct {
		name             string
		request          *pb.DeleteAssetsRequest
		setupMock        func(*serviceMocks.MockAssetService)
		expectedError    error
		validateResponse func(t *testing.T, response *pb.DeleteAssetsResponse)
	}{
		{
			name: "successful assets deletion by IDs",
			request: &pb.DeleteAssetsRequest{
				Ids: []string{
					"550e8400-e29b-41d4-a716-446655440000",
					"550e8400-e29b-41d4-a716-446655440001",
				},
			},
			setupMock: func(mockService *serviceMocks.MockAssetService) {
				mockService.On("DeleteAssets", mock.Anything,
					[]string{
						"550e8400-e29b-41d4-a716-446655440000",
						"550e8400-e29b-41d4-a716-446655440001",
					},
					(*domain.AssetFilters)(nil), false).
					Return(nil)
			},
			expectedError: nil,
			validateResponse: func(t *testing.T, response *pb.DeleteAssetsResponse) {
				assert.NotNil(t, response)
				assert.True(t, response.Success)
			},
		},
		{
			name: "assets deletion with filter",
			request: &pb.DeleteAssetsRequest{
				Ids: []string{"550e8400-e29b-41d4-a716-446655440000"},
				Filter: &pb.Filter{
					Name:   "test",
					Domain: "test.local",
				},
				Exclude: true,
			},
			setupMock: func(mockService *serviceMocks.MockAssetService) {
				mockService.On("DeleteAssets", mock.Anything,
					[]string{"550e8400-e29b-41d4-a716-446655440000"},
					mock.MatchedBy(func(filter *domain.AssetFilters) bool {
						return filter != nil && filter.Name == "test" && filter.Domain == "test.local"
					}), true).
					Return(nil)
			},
			expectedError: nil,
			validateResponse: func(t *testing.T, response *pb.DeleteAssetsResponse) {
				assert.NotNil(t, response)
				assert.True(t, response.Success)
			},
		},
		{
			name: "asset not found error",
			request: &pb.DeleteAssetsRequest{
				Ids: []string{"550e8400-e29b-41d4-a716-446655440000"},
			},
			setupMock: func(mockService *serviceMocks.MockAssetService) {
				mockService.On("DeleteAssets", mock.Anything,
					[]string{"550e8400-e29b-41d4-a716-446655440000"},
					(*domain.AssetFilters)(nil), false).
					Return(service.ErrAssetNotFound)
			},
			expectedError: service.ErrAssetNotFound,
			validateResponse: func(t *testing.T, response *pb.DeleteAssetsResponse) {
				assert.Nil(t, response)
			},
		},
		{
			name: "internal service error",
			request: &pb.DeleteAssetsRequest{
				Ids: []string{"550e8400-e29b-41d4-a716-446655440000"},
			},
			setupMock: func(mockService *serviceMocks.MockAssetService) {
				mockService.On("DeleteAssets", mock.Anything,
					[]string{"550e8400-e29b-41d4-a716-446655440000"},
					(*domain.AssetFilters)(nil), false).
					Return(errors.New("database connection failed"))
			},
			expectedError: errors.New("database connection failed"),
			validateResponse: func(t *testing.T, response *pb.DeleteAssetsResponse) {
				assert.Nil(t, response)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup - Create mock internal service and real API service
			mockInternalService := new(serviceMocks.MockAssetService)
			tt.setupMock(mockInternalService)

			// Create real API service with mocked internal service
			apiService := service.NewAssetService(mockInternalService)

			// Execute the actual service method
			ctx := context.Background()
			response, err := apiService.DeleteAssets(ctx, tt.request)

			// Assertions
			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedError.Error(), err.Error())
				assert.Nil(t, response)
			} else {
				assert.NoError(t, err)
				tt.validateResponse(t, response)
			}

			// Verify mock expectations
			mockInternalService.AssertExpectations(t)
		})
	}
}

func TestAssetService_ExportAssets(t *testing.T) {
	tests := []struct {
		name           string
		request        *pb.ExportAssetsRequest
		setupMock      func(*serviceMocks.MockAssetService)
		expectedError  error
		validateResult func(t *testing.T, csvData []byte)
	}{
		{
			name: "successful full export",
			request: &pb.ExportAssetsRequest{
				AssetIds: []string{
					"550e8400-e29b-41d4-a716-446655440000",
					"550e8400-e29b-41d4-a716-446655440001",
				},
				ExportType: pb.ExportType_FULL_EXPORT,
			},
			setupMock: func(mockService *serviceMocks.MockAssetService) {
				expectedAssetUUIDs := []domain.AssetUUID{
					uuid.MustParse("550e8400-e29b-41d4-a716-446655440000"),
					uuid.MustParse("550e8400-e29b-41d4-a716-446655440001"),
				}
				mockExportData := &domain.ExportData{
					Assets: []map[string]interface{}{
						{"id": "550e8400-e29b-41d4-a716-446655440000", "name": "Asset 1"},
						{"id": "550e8400-e29b-41d4-a716-446655440001", "name": "Asset 2"},
					},
					Ports:     []map[string]interface{}{},
					VMwareVMs: []map[string]interface{}{},
					AssetIPs:  []map[string]interface{}{},
				}
				mockService.On("ExportAssets", mock.Anything, expectedAssetUUIDs, domain.FullExport, []string(nil)).
					Return(mockExportData, nil)
				mockService.On("GenerateCSV", mock.Anything, mockExportData).
					Return([]byte("id,name\n550e8400-e29b-41d4-a716-446655440000,Asset 1\n550e8400-e29b-41d4-a716-446655440001,Asset 2\n"), nil)
			},
			expectedError: nil,
			validateResult: func(t *testing.T, csvData []byte) {
				assert.NotNil(t, csvData)
				assert.Contains(t, string(csvData), "Asset 1")
				assert.Contains(t, string(csvData), "Asset 2")
			},
		},
		{
			name: "successful selected columns export",
			request: &pb.ExportAssetsRequest{
				AssetIds:        []string{"550e8400-e29b-41d4-a716-446655440000"},
				ExportType:      pb.ExportType_SELECTED_COLUMNS,
				SelectedColumns: []string{"assets.name", "assets.hostname"},
			},
			setupMock: func(mockService *serviceMocks.MockAssetService) {
				expectedAssetUUIDs := []domain.AssetUUID{
					uuid.MustParse("550e8400-e29b-41d4-a716-446655440000"),
				}
				mockExportData := &domain.ExportData{
					Assets: []map[string]interface{}{
						{"name": "Asset 1", "hostname": "test-host"},
					},
					Ports:     []map[string]interface{}{},
					VMwareVMs: []map[string]interface{}{},
					AssetIPs:  []map[string]interface{}{},
				}
				mockService.On("ExportAssets", mock.Anything, expectedAssetUUIDs, domain.SelectedColumnsExport,
					[]string{"assets.name", "assets.hostname"}).
					Return(mockExportData, nil)
				mockService.On("GenerateCSV", mock.Anything, mockExportData).
					Return([]byte("name,hostname\nAsset 1,test-host\n"), nil)
			},
			expectedError: nil,
			validateResult: func(t *testing.T, csvData []byte) {
				assert.NotNil(t, csvData)
				assert.Contains(t, string(csvData), "Asset 1")
				assert.Contains(t, string(csvData), "test-host")
			},
		},
		{
			name: "export all assets",
			request: &pb.ExportAssetsRequest{
				AssetIds:   []string{"All"},
				ExportType: pb.ExportType_FULL_EXPORT,
			},
			setupMock: func(mockService *serviceMocks.MockAssetService) {
				mockExportData := &domain.ExportData{
					Assets: []map[string]interface{}{
						{"id": "asset1", "name": "All Asset 1"},
						{"id": "asset2", "name": "All Asset 2"},
					},
					Ports:     []map[string]interface{}{},
					VMwareVMs: []map[string]interface{}{},
					AssetIPs:  []map[string]interface{}{},
				}
				mockService.On("ExportAssets", mock.Anything, []domain.AssetUUID{}, domain.FullExport, []string(nil)).
					Return(mockExportData, nil)
				mockService.On("GenerateCSV", mock.Anything, mockExportData).
					Return([]byte("id,name\nasset1,All Asset 1\nasset2,All Asset 2\n"), nil)
			},
			expectedError: nil,
			validateResult: func(t *testing.T, csvData []byte) {
				assert.NotNil(t, csvData)
				assert.Contains(t, string(csvData), "All Asset 1")
				assert.Contains(t, string(csvData), "All Asset 2")
			},
		},
		{
			name: "invalid asset UUID",
			request: &pb.ExportAssetsRequest{
				AssetIds:   []string{"invalid-uuid"},
				ExportType: pb.ExportType_FULL_EXPORT,
			},
			setupMock: func(mockService *serviceMocks.MockAssetService) {
				// No mock setup needed as UUID parsing should fail
			},
			expectedError: service.ErrInvalidAssetUUID,
			validateResult: func(t *testing.T, csvData []byte) {
				assert.Nil(t, csvData)
			},
		},
		{
			name: "export assets service error",
			request: &pb.ExportAssetsRequest{
				AssetIds:   []string{"550e8400-e29b-41d4-a716-446655440000"},
				ExportType: pb.ExportType_FULL_EXPORT,
			},
			setupMock: func(mockService *serviceMocks.MockAssetService) {
				expectedAssetUUIDs := []domain.AssetUUID{
					uuid.MustParse("550e8400-e29b-41d4-a716-446655440000"),
				}
				mockService.On("ExportAssets", mock.Anything, expectedAssetUUIDs, domain.FullExport, []string(nil)).
					Return((*domain.ExportData)(nil), errors.New("export failed"))
			},
			expectedError: errors.New("export failed"),
			validateResult: func(t *testing.T, csvData []byte) {
				assert.Nil(t, csvData)
			},
		},
		{
			name: "default export type when invalid type provided",
			request: &pb.ExportAssetsRequest{
				AssetIds:   []string{"550e8400-e29b-41d4-a716-446655440000"},
				ExportType: pb.ExportType(999), // Invalid enum value to trigger default case
			},
			setupMock: func(mockService *serviceMocks.MockAssetService) {
				expectedAssetUUIDs := []domain.AssetUUID{
					uuid.MustParse("550e8400-e29b-41d4-a716-446655440000"),
				}
				mockExportData := &domain.ExportData{
					Assets: []map[string]interface{}{
						{"id": "550e8400-e29b-41d4-a716-446655440000", "name": "Asset 1"},
					},
					Ports:     []map[string]interface{}{},
					VMwareVMs: []map[string]interface{}{},
					AssetIPs:  []map[string]interface{}{},
				}
				// Should default to FullExport when invalid export type is provided
				mockService.On("ExportAssets", mock.Anything, expectedAssetUUIDs, domain.FullExport, []string(nil)).
					Return(mockExportData, nil)
				mockService.On("GenerateCSV", mock.Anything, mockExportData).
					Return([]byte("id,name\n550e8400-e29b-41d4-a716-446655440000,Asset 1\n"), nil)
			},
			expectedError: nil,
			validateResult: func(t *testing.T, csvData []byte) {
				assert.NotNil(t, csvData)
				assert.Contains(t, string(csvData), "Asset 1")
			},
		},
		{
			name: "generate CSV service error",
			request: &pb.ExportAssetsRequest{
				AssetIds:   []string{"550e8400-e29b-41d4-a716-446655440000"},
				ExportType: pb.ExportType_FULL_EXPORT,
			},
			setupMock: func(mockService *serviceMocks.MockAssetService) {
				expectedAssetUUIDs := []domain.AssetUUID{
					uuid.MustParse("550e8400-e29b-41d4-a716-446655440000"),
				}
				mockExportData := &domain.ExportData{
					Assets: []map[string]interface{}{
						{"id": "550e8400-e29b-41d4-a716-446655440000", "name": "Asset 1"},
					},
					Ports:     []map[string]interface{}{},
					VMwareVMs: []map[string]interface{}{},
					AssetIPs:  []map[string]interface{}{},
				}
				mockService.On("ExportAssets", mock.Anything, expectedAssetUUIDs, domain.FullExport, []string(nil)).
					Return(mockExportData, nil)
				mockService.On("GenerateCSV", mock.Anything, mockExportData).
					Return([]byte{}, errors.New("CSV generation failed"))
			},
			expectedError: errors.New("CSV generation failed"),
			validateResult: func(t *testing.T, csvData []byte) {
				assert.Nil(t, csvData)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup - Create mock internal service and real API service
			mockInternalService := new(serviceMocks.MockAssetService)
			tt.setupMock(mockInternalService)

			// Create real API service with mocked internal service
			apiService := service.NewAssetService(mockInternalService)

			// Execute the actual service method
			ctx := context.Background()
			csvData, err := apiService.ExportAssets(ctx, tt.request)

			// Assertions
			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedError.Error(), err.Error())
				assert.Nil(t, csvData)
			} else {
				assert.NoError(t, err)
				tt.validateResult(t, csvData)
			}

			// Verify mock expectations
			mockInternalService.AssertExpectations(t)
		})
	}
}

func TestAssetService_GetDistinctOSNames(t *testing.T) {
	tests := []struct {
		name             string
		request          *pb.GetDistinctOSNamesRequest
		setupMock        func(*serviceMocks.MockAssetService)
		expectedError    error
		validateResponse func(t *testing.T, response *pb.GetDistinctOSNamesResponse)
	}{
		{
			name:    "successful OS names retrieval",
			request: &pb.GetDistinctOSNamesRequest{},
			setupMock: func(mockService *serviceMocks.MockAssetService) {
				osNames := []string{"Ubuntu", "CentOS", "Windows Server 2019", "RHEL"}
				mockService.On("GetDistinctOSNames", mock.Anything).
					Return(osNames, nil)
			},
			expectedError: nil,
			validateResponse: func(t *testing.T, response *pb.GetDistinctOSNamesResponse) {
				assert.NotNil(t, response)
				assert.Len(t, response.OsNames, 4)
				assert.Contains(t, response.OsNames, "Ubuntu")
				assert.Contains(t, response.OsNames, "CentOS")
				assert.Contains(t, response.OsNames, "Windows Server 2019")
				assert.Contains(t, response.OsNames, "RHEL")
			},
		},
		{
			name:    "empty OS names list",
			request: &pb.GetDistinctOSNamesRequest{},
			setupMock: func(mockService *serviceMocks.MockAssetService) {
				osNames := []string{}
				mockService.On("GetDistinctOSNames", mock.Anything).
					Return(osNames, nil)
			},
			expectedError: nil,
			validateResponse: func(t *testing.T, response *pb.GetDistinctOSNamesResponse) {
				assert.NotNil(t, response)
				assert.Len(t, response.OsNames, 0)
			},
		},
		{
			name:    "internal service error",
			request: &pb.GetDistinctOSNamesRequest{},
			setupMock: func(mockService *serviceMocks.MockAssetService) {
				mockService.On("GetDistinctOSNames", mock.Anything).
					Return([]string{}, errors.New("database connection failed"))
			},
			expectedError: errors.New("database connection failed"),
			validateResponse: func(t *testing.T, response *pb.GetDistinctOSNamesResponse) {
				assert.Nil(t, response)
			},
		},
		{
			name:    "single OS name",
			request: &pb.GetDistinctOSNamesRequest{},
			setupMock: func(mockService *serviceMocks.MockAssetService) {
				osNames := []string{"Ubuntu 20.04"}
				mockService.On("GetDistinctOSNames", mock.Anything).
					Return(osNames, nil)
			},
			expectedError: nil,
			validateResponse: func(t *testing.T, response *pb.GetDistinctOSNamesResponse) {
				assert.NotNil(t, response)
				assert.Len(t, response.OsNames, 1)
				assert.Equal(t, "Ubuntu 20.04", response.OsNames[0])
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup - Create mock internal service and real API service
			mockInternalService := new(serviceMocks.MockAssetService)
			tt.setupMock(mockInternalService)

			// Create real API service with mocked internal service
			apiService := service.NewAssetService(mockInternalService)

			// Execute the actual service method
			ctx := context.Background()
			response, err := apiService.GetDistinctOSNames(ctx, tt.request)

			// Assertions
			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedError.Error(), err.Error())
				assert.Nil(t, response)
			} else {
				assert.NoError(t, err)
				tt.validateResponse(t, response)
			}

			// Verify mock expectations
			mockInternalService.AssertExpectations(t)
		})
	}
}

// Dashboard API tests

func TestAssetService_GetDashboardAssetCount(t *testing.T) {
	tests := []struct {
		name             string
		request          *pb.GetDashboardAssetCountRequest
		setupMock        func(*serviceMocks.MockAssetService)
		expectedError    error
		validateResponse func(t *testing.T, response *pb.GetDashboardAssetCountResponse)
	}{
		{
			name:    "successful dashboard asset count retrieval",
			request: &pb.GetDashboardAssetCountRequest{},
			setupMock: func(mockService *serviceMocks.MockAssetService) {
				expectedData := &domain.AssetCountData{
					Count: 150,
					Contents: []domain.AssetStatusCount{
						{Source: "offline", Percent: 70},
						{Source: "online", Percent: 30},
					},
				}
				mockService.On("GetDashboardAssetCount", mock.Anything).Return(expectedData, nil)
			},
			expectedError: nil,
			validateResponse: func(t *testing.T, response *pb.GetDashboardAssetCountResponse) {
				assert.NotNil(t, response)
				assert.Equal(t, int32(150), response.Count)
				assert.Len(t, response.Contents, 2)
				assert.Equal(t, "offline", response.Contents[0].Source)
				assert.Equal(t, int32(70), response.Contents[0].Percent)
				assert.Equal(t, "online", response.Contents[1].Source)
				assert.Equal(t, int32(30), response.Contents[1].Percent)
			},
		},
		{
			name:    "internal service error",
			request: &pb.GetDashboardAssetCountRequest{},
			setupMock: func(mockService *serviceMocks.MockAssetService) {
				mockService.On("GetDashboardAssetCount", mock.Anything).Return(nil, errors.New("database error"))
			},
			expectedError: errors.New("database error"),
			validateResponse: func(t *testing.T, response *pb.GetDashboardAssetCountResponse) {
				assert.Nil(t, response)
			},
		},
		{
			name:    "empty contents",
			request: &pb.GetDashboardAssetCountRequest{},
			setupMock: func(mockService *serviceMocks.MockAssetService) {
				expectedData := &domain.AssetCountData{
					Count:    0,
					Contents: []domain.AssetStatusCount{},
				}
				mockService.On("GetDashboardAssetCount", mock.Anything).Return(expectedData, nil)
			},
			expectedError: nil,
			validateResponse: func(t *testing.T, response *pb.GetDashboardAssetCountResponse) {
				assert.NotNil(t, response)
				assert.Equal(t, int32(0), response.Count)
				assert.Len(t, response.Contents, 0)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			mockInternalService := &serviceMocks.MockAssetService{}
			apiService := service.NewAssetService(mockInternalService)
			ctx := context.Background()

			// Configure mock
			tt.setupMock(mockInternalService)

			// Execute
			response, err := apiService.GetDashboardAssetCount(ctx, tt.request)

			// Verify
			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedError.Error(), err.Error())
				assert.Nil(t, response)
			} else {
				assert.NoError(t, err)
				tt.validateResponse(t, response)
			}

			// Verify mock expectations
			mockInternalService.AssertExpectations(t)
		})
	}
}

func TestAssetService_GetDashboardAssetPerScanner(t *testing.T) {
	tests := []struct {
		name             string
		request          *pb.GetDashboardAssetPerScannerRequest
		setupMock        func(*serviceMocks.MockAssetService)
		expectedError    error
		validateResponse func(t *testing.T, response *pb.GetDashboardAssetPerScannerResponse)
	}{
		{
			name:    "successful dashboard asset per scanner retrieval",
			request: &pb.GetDashboardAssetPerScannerRequest{},
			setupMock: func(mockService *serviceMocks.MockAssetService) {
				expectedData := &domain.AssetPerScannerData{
					Contents: []domain.ScannerTypeCount{
						{Source: "nmap", Count: 50},
						{Source: "nessus", Count: 30},
						{Source: "firewall", Count: 20},
					},
				}
				mockService.On("GetDashboardAssetPerScanner", mock.Anything).Return(expectedData, nil)
			},
			expectedError: nil,
			validateResponse: func(t *testing.T, response *pb.GetDashboardAssetPerScannerResponse) {
				assert.NotNil(t, response)
				assert.Len(t, response.Contents, 3)
				assert.Equal(t, "nmap", response.Contents[0].Source)
				assert.Equal(t, int32(50), response.Contents[0].Count)
				assert.Equal(t, "nessus", response.Contents[1].Source)
				assert.Equal(t, int32(30), response.Contents[1].Count)
				assert.Equal(t, "firewall", response.Contents[2].Source)
				assert.Equal(t, int32(20), response.Contents[2].Count)
			},
		},
		{
			name:    "internal service error",
			request: &pb.GetDashboardAssetPerScannerRequest{},
			setupMock: func(mockService *serviceMocks.MockAssetService) {
				mockService.On("GetDashboardAssetPerScanner", mock.Anything).Return(nil, errors.New("repository error"))
			},
			expectedError: errors.New("repository error"),
			validateResponse: func(t *testing.T, response *pb.GetDashboardAssetPerScannerResponse) {
				assert.Nil(t, response)
			},
		},
		{
			name:    "empty scanner types",
			request: &pb.GetDashboardAssetPerScannerRequest{},
			setupMock: func(mockService *serviceMocks.MockAssetService) {
				expectedData := &domain.AssetPerScannerData{
					Contents: []domain.ScannerTypeCount{},
				}
				mockService.On("GetDashboardAssetPerScanner", mock.Anything).Return(expectedData, nil)
			},
			expectedError: nil,
			validateResponse: func(t *testing.T, response *pb.GetDashboardAssetPerScannerResponse) {
				assert.NotNil(t, response)
				assert.Len(t, response.Contents, 0)
			},
		},
		{
			name:    "single scanner type",
			request: &pb.GetDashboardAssetPerScannerRequest{},
			setupMock: func(mockService *serviceMocks.MockAssetService) {
				expectedData := &domain.AssetPerScannerData{
					Contents: []domain.ScannerTypeCount{
						{Source: "Unknown", Count: 100},
					},
				}
				mockService.On("GetDashboardAssetPerScanner", mock.Anything).Return(expectedData, nil)
			},
			expectedError: nil,
			validateResponse: func(t *testing.T, response *pb.GetDashboardAssetPerScannerResponse) {
				assert.NotNil(t, response)
				assert.Len(t, response.Contents, 1)
				assert.Equal(t, "Unknown", response.Contents[0].Source)
				assert.Equal(t, int32(100), response.Contents[0].Count)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			mockInternalService := &serviceMocks.MockAssetService{}
			apiService := service.NewAssetService(mockInternalService)
			ctx := context.Background()

			// Configure mock
			tt.setupMock(mockInternalService)

			// Execute
			response, err := apiService.GetDashboardAssetPerScanner(ctx, tt.request)

			// Verify
			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedError.Error(), err.Error())
				assert.Nil(t, response)
			} else {
				assert.NoError(t, err)
				tt.validateResponse(t, response)
			}

			// Verify mock expectations
			mockInternalService.AssertExpectations(t)
		})
	}
}

func TestAssetService_GetDashboardLoggingCompleted(t *testing.T) {
	tests := []struct {
		name             string
		request          *pb.GetDashboardLoggingCompletedRequest
		setupMock        func(*serviceMocks.MockAssetService)
		expectedError    error
		validateResponse func(t *testing.T, response *pb.GetDashboardLoggingCompletedResponse)
	}{
		{
			name:    "successful dashboard logging completed retrieval",
			request: &pb.GetDashboardLoggingCompletedRequest{},
			setupMock: func(mockService *serviceMocks.MockAssetService) {
				expectedData := &domain.LoggingCompletedData{
					Contents: []domain.OSLoggingStats{
						{Source: "Windows", Count: 25, Total: 50},
						{Source: "Linux", Count: 40, Total: 60},
						{Source: "Unknown", Count: 5, Total: 10},
					},
				}
				mockService.On("GetDashboardLoggingCompleted", mock.Anything).Return(expectedData, nil)
			},
			expectedError: nil,
			validateResponse: func(t *testing.T, response *pb.GetDashboardLoggingCompletedResponse) {
				assert.NotNil(t, response)
				assert.Len(t, response.Contents, 3)
				assert.Equal(t, "Windows", response.Contents[0].Source)
				assert.Equal(t, int32(25), response.Contents[0].Count)
				assert.Equal(t, int32(50), response.Contents[0].Total)
				assert.Equal(t, "Linux", response.Contents[1].Source)
				assert.Equal(t, int32(40), response.Contents[1].Count)
				assert.Equal(t, int32(60), response.Contents[1].Total)
				assert.Equal(t, "Unknown", response.Contents[2].Source)
				assert.Equal(t, int32(5), response.Contents[2].Count)
				assert.Equal(t, int32(10), response.Contents[2].Total)
			},
		},
		{
			name:    "internal service error",
			request: &pb.GetDashboardLoggingCompletedRequest{},
			setupMock: func(mockService *serviceMocks.MockAssetService) {
				mockService.On("GetDashboardLoggingCompleted", mock.Anything).Return(nil, errors.New("database connection failed"))
			},
			expectedError: errors.New("database connection failed"),
			validateResponse: func(t *testing.T, response *pb.GetDashboardLoggingCompletedResponse) {
				assert.Nil(t, response)
			},
		},
		{
			name:    "empty OS statistics",
			request: &pb.GetDashboardLoggingCompletedRequest{},
			setupMock: func(mockService *serviceMocks.MockAssetService) {
				expectedData := &domain.LoggingCompletedData{
					Contents: []domain.OSLoggingStats{},
				}
				mockService.On("GetDashboardLoggingCompleted", mock.Anything).Return(expectedData, nil)
			},
			expectedError: nil,
			validateResponse: func(t *testing.T, response *pb.GetDashboardLoggingCompletedResponse) {
				assert.NotNil(t, response)
				assert.Len(t, response.Contents, 0)
			},
		},
		{
			name:    "zero logging completion",
			request: &pb.GetDashboardLoggingCompletedRequest{},
			setupMock: func(mockService *serviceMocks.MockAssetService) {
				expectedData := &domain.LoggingCompletedData{
					Contents: []domain.OSLoggingStats{
						{Source: "MacOS", Count: 0, Total: 15},
					},
				}
				mockService.On("GetDashboardLoggingCompleted", mock.Anything).Return(expectedData, nil)
			},
			expectedError: nil,
			validateResponse: func(t *testing.T, response *pb.GetDashboardLoggingCompletedResponse) {
				assert.NotNil(t, response)
				assert.Len(t, response.Contents, 1)
				assert.Equal(t, "MacOS", response.Contents[0].Source)
				assert.Equal(t, int32(0), response.Contents[0].Count)
				assert.Equal(t, int32(15), response.Contents[0].Total)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			mockInternalService := &serviceMocks.MockAssetService{}
			apiService := service.NewAssetService(mockInternalService)
			ctx := context.Background()

			// Configure mock
			tt.setupMock(mockInternalService)

			// Execute
			response, err := apiService.GetDashboardLoggingCompleted(ctx, tt.request)

			// Verify
			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedError.Error(), err.Error())
				assert.Nil(t, response)
			} else {
				assert.NoError(t, err)
				tt.validateResponse(t, response)
			}

			// Verify mock expectations
			mockInternalService.AssertExpectations(t)
		})
	}
}

func TestAssetService_GetDashboardAssetsPerSource(t *testing.T) {
	tests := []struct {
		name             string
		request          *pb.GetDashboardAssetsPerSourceRequest
		setupMock        func(*serviceMocks.MockAssetService)
		expectedError    error
		validateResponse func(t *testing.T, response *pb.GetDashboardAssetsPerSourceResponse)
	}{
		{
			name:    "successful dashboard assets per source retrieval",
			request: &pb.GetDashboardAssetsPerSourceRequest{},
			setupMock: func(mockService *serviceMocks.MockAssetService) {
				expectedData := &domain.AssetsPerSourceData{
					Count: 200,
					Contents: []domain.AssetSourceStats{
						{Source: "Windows", Percent: 45},
						{Source: "Linux", Percent: 35},
						{Source: "MacOS", Percent: 15},
						{Source: "Unknown", Percent: 5},
					},
				}
				mockService.On("GetDashboardAssetsPerSource", mock.Anything).Return(expectedData, nil)
			},
			expectedError: nil,
			validateResponse: func(t *testing.T, response *pb.GetDashboardAssetsPerSourceResponse) {
				assert.NotNil(t, response)
				assert.Equal(t, int32(200), response.Count)
				assert.Len(t, response.Contents, 4)
				assert.Equal(t, "Windows", response.Contents[0].Source)
				assert.Equal(t, int32(45), response.Contents[0].Percent)
				assert.Equal(t, "Linux", response.Contents[1].Source)
				assert.Equal(t, int32(35), response.Contents[1].Percent)
				assert.Equal(t, "MacOS", response.Contents[2].Source)
				assert.Equal(t, int32(15), response.Contents[2].Percent)
				assert.Equal(t, "Unknown", response.Contents[3].Source)
				assert.Equal(t, int32(5), response.Contents[3].Percent)
			},
		},
		{
			name:    "internal service error",
			request: &pb.GetDashboardAssetsPerSourceRequest{},
			setupMock: func(mockService *serviceMocks.MockAssetService) {
				mockService.On("GetDashboardAssetsPerSource", mock.Anything).Return(nil, errors.New("query execution failed"))
			},
			expectedError: errors.New("query execution failed"),
			validateResponse: func(t *testing.T, response *pb.GetDashboardAssetsPerSourceResponse) {
				assert.Nil(t, response)
			},
		},
		{
			name:    "empty sources",
			request: &pb.GetDashboardAssetsPerSourceRequest{},
			setupMock: func(mockService *serviceMocks.MockAssetService) {
				expectedData := &domain.AssetsPerSourceData{
					Count:    0,
					Contents: []domain.AssetSourceStats{},
				}
				mockService.On("GetDashboardAssetsPerSource", mock.Anything).Return(expectedData, nil)
			},
			expectedError: nil,
			validateResponse: func(t *testing.T, response *pb.GetDashboardAssetsPerSourceResponse) {
				assert.NotNil(t, response)
				assert.Equal(t, int32(0), response.Count)
				assert.Len(t, response.Contents, 0)
			},
		},
		{
			name:    "single source with 100% distribution",
			request: &pb.GetDashboardAssetsPerSourceRequest{},
			setupMock: func(mockService *serviceMocks.MockAssetService) {
				expectedData := &domain.AssetsPerSourceData{
					Count: 75,
					Contents: []domain.AssetSourceStats{
						{Source: "Ubuntu", Percent: 100},
					},
				}
				mockService.On("GetDashboardAssetsPerSource", mock.Anything).Return(expectedData, nil)
			},
			expectedError: nil,
			validateResponse: func(t *testing.T, response *pb.GetDashboardAssetsPerSourceResponse) {
				assert.NotNil(t, response)
				assert.Equal(t, int32(75), response.Count)
				assert.Len(t, response.Contents, 1)
				assert.Equal(t, "Ubuntu", response.Contents[0].Source)
				assert.Equal(t, int32(100), response.Contents[0].Percent)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			mockInternalService := &serviceMocks.MockAssetService{}
			apiService := service.NewAssetService(mockInternalService)
			ctx := context.Background()

			// Configure mock
			tt.setupMock(mockInternalService)

			// Execute
			response, err := apiService.GetDashboardAssetsPerSource(ctx, tt.request)

			// Verify
			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedError.Error(), err.Error())
				assert.Nil(t, response)
			} else {
				assert.NoError(t, err)
				tt.validateResponse(t, response)
			}

			// Verify mock expectations
			mockInternalService.AssertExpectations(t)
		})
	}
}
