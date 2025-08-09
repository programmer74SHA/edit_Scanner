package handlers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	httpHandlers "gitlab.apk-group.net/siem/backend/asset-discovery/api/handlers/http"
	"gitlab.apk-group.net/siem/backend/asset-discovery/api/service"
	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/domain"
	apiFixtures "gitlab.apk-group.net/siem/backend/asset-discovery/tests/fixtures/api"
	internalMocks "gitlab.apk-group.net/siem/backend/asset-discovery/tests/mocks/service"
)

// TestCreateAsset_Handler tests the HTTP handler layer integration
// This test focuses on HTTP request/response handling and uses the actual API service layer
func TestCreateAsset_Handler(t *testing.T) {
	tests := []struct {
		name           string
		requestBody    interface{}
		setupMock      func(*internalMocks.MockAssetService)
		expectedStatus int
		validateBody   func(t *testing.T, body string)
	}{
		{
			name:        "successful asset creation",
			requestBody: apiFixtures.NewTestCreateAssetRequest(),
			setupMock: func(mockService *internalMocks.MockAssetService) {
				testUUID := uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")
				mockService.On("CreateAsset", mock.Anything, mock.AnythingOfType("domain.AssetDomain"), []string(nil)).
					Return(testUUID, nil)
			},
			expectedStatus: fiber.StatusOK,
			validateBody: func(t *testing.T, body string) {
				var response map[string]interface{}
				err := json.Unmarshal([]byte(body), &response)
				assert.NoError(t, err)
				assert.Contains(t, response, "id")
			},
		},
		{
			name:        "IP already exists error",
			requestBody: apiFixtures.NewTestCreateAssetRequest(),
			setupMock: func(mockService *internalMocks.MockAssetService) {
				mockService.On("CreateAsset", mock.Anything, mock.AnythingOfType("domain.AssetDomain"), []string(nil)).
					Return(uuid.UUID{}, service.ErrIPAlreadyExists)
			},
			expectedStatus: fiber.StatusConflict,
			validateBody: func(t *testing.T, body string) {
				assert.Contains(t, body, "IP address already exists")
			},
		},
		{
			name:        "hostname already exists error",
			requestBody: apiFixtures.NewTestCreateAssetRequest(),
			setupMock: func(mockService *internalMocks.MockAssetService) {
				mockService.On("CreateAsset", mock.Anything, mock.AnythingOfType("domain.AssetDomain"), []string(nil)).
					Return(uuid.UUID{}, service.ErrHostnameAlreadyExists)
			},
			expectedStatus: fiber.StatusConflict,
			validateBody: func(t *testing.T, body string) {
				assert.Contains(t, body, "Hostname already exists")
			},
		},
		{
			name:        "invalid JSON request body",
			requestBody: "invalid json",
			setupMock: func(mockService *internalMocks.MockAssetService) {
				// No mock setup needed as request parsing should fail
			},
			expectedStatus: fiber.StatusBadRequest,
			validateBody: func(t *testing.T, body string) {
				assert.Contains(t, body, "Bad Request")
			},
		},
		{
			name:        "internal server error",
			requestBody: apiFixtures.NewTestCreateAssetRequest(),
			setupMock: func(mockService *internalMocks.MockAssetService) {
				mockService.On("CreateAsset", mock.Anything, mock.AnythingOfType("domain.AssetDomain"), []string(nil)).
					Return(uuid.UUID{}, errors.New("database connection failed"))
			},
			expectedStatus: fiber.StatusInternalServerError,
			validateBody: func(t *testing.T, body string) {
				assert.Contains(t, body, "database connection failed")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup - Create mock internal service and real API service
			mockInternalService := new(internalMocks.MockAssetService)
			tt.setupMock(mockInternalService)

			// Create real API service with mocked internal service
			apiService := service.NewAssetService(mockInternalService)

			app := fiber.New()

			// Create service getter that returns our API service
			serviceGetter := func(ctx context.Context) *service.AssetService {
				return apiService
			}

			app.Post("/assets", httpHandlers.CreateAsset(serviceGetter))

			// Create request body
			var bodyBytes []byte
			var err error
			if str, ok := tt.requestBody.(string); ok {
				bodyBytes = []byte(str)
			} else {
				bodyBytes, err = json.Marshal(tt.requestBody)
				assert.NoError(t, err)
			}

			// Make request
			req := httptest.NewRequest("POST", "/assets", bytes.NewBuffer(bodyBytes))
			req.Header.Set("Content-Type", "application/json")

			resp, err := app.Test(req)
			assert.NoError(t, err)

			// Assert response
			assert.Equal(t, tt.expectedStatus, resp.StatusCode)

			// Read response body
			buf := new(bytes.Buffer)
			buf.ReadFrom(resp.Body)
			responseBody := buf.String()

			tt.validateBody(t, responseBody)

			// Verify mock expectations
			mockInternalService.AssertExpectations(t)
		})
	}
}

// Additional simplified tests for basic HTTP functionality
func TestCreateAsset_Handler_HTTPBasics(t *testing.T) {
	// This test verifies basic HTTP functionality without complex mocking
	app := fiber.New()

	// Use a minimal service getter for basic testing
	serviceGetter := func(ctx context.Context) *service.AssetService {
		mockService := new(internalMocks.MockAssetService)
		return service.NewAssetService(mockService)
	}

	app.Post("/assets", httpHandlers.CreateAsset(serviceGetter))

	t.Run("invalid_content_type", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/assets", bytes.NewBufferString("test"))
		// Don't set Content-Type header

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode)
	})

	t.Run("empty_body", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/assets", bytes.NewBuffer([]byte{}))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req)
		assert.NoError(t, err)
		// This might return 400 (bad request) due to empty JSON
		assert.True(t, resp.StatusCode >= 400)
	})
}

// TestCreateAsset_Handler_EdgeCases tests various edge cases and HTTP-specific scenarios
func TestCreateAsset_Handler_EdgeCases(t *testing.T) {
	tests := []struct {
		name           string
		setupRequest   func() (*http.Request, error)
		setupMock      func(*internalMocks.MockAssetService)
		expectedStatus int
		validateBody   func(t *testing.T, body string)
	}{
		{
			name: "large JSON payload",
			setupRequest: func() (*http.Request, error) {
				largeRequest := apiFixtures.NewTestCreateAssetRequestWithPorts(100) // Large number of ports
				bodyBytes, err := json.Marshal(largeRequest)
				if err != nil {
					return nil, err
				}
				req := httptest.NewRequest("POST", "/assets", bytes.NewBuffer(bodyBytes))
				req.Header.Set("Content-Type", "application/json")
				return req, nil
			},
			setupMock: func(mockService *internalMocks.MockAssetService) {
				testUUID := uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")
				mockService.On("CreateAsset", mock.Anything, mock.MatchedBy(func(asset domain.AssetDomain) bool {
					return len(asset.Ports) == 100
				}), []string(nil)).Return(testUUID, nil)
			},
			expectedStatus: fiber.StatusOK,
			validateBody: func(t *testing.T, body string) {
				var response map[string]interface{}
				err := json.Unmarshal([]byte(body), &response)
				assert.NoError(t, err)
				assert.Contains(t, response, "id")
			},
		},
		{
			name: "malformed JSON",
			setupRequest: func() (*http.Request, error) {
				req := httptest.NewRequest("POST", "/assets", bytes.NewBufferString(`{"name": "test", "unclosed": `))
				req.Header.Set("Content-Type", "application/json")
				return req, nil
			},
			setupMock: func(mockService *internalMocks.MockAssetService) {
				// No mock setup needed as JSON parsing should fail
			},
			expectedStatus: fiber.StatusBadRequest,
			validateBody: func(t *testing.T, body string) {
				assert.Contains(t, body, "Bad Request")
			},
		},
		{
			name: "empty request body",
			setupRequest: func() (*http.Request, error) {
				req := httptest.NewRequest("POST", "/assets", bytes.NewBuffer([]byte{}))
				req.Header.Set("Content-Type", "application/json")
				return req, nil
			},
			setupMock: func(mockService *internalMocks.MockAssetService) {
				// No mock setup needed as empty body should fail validation
			},
			expectedStatus: fiber.StatusBadRequest,
			validateBody: func(t *testing.T, body string) {
				assert.Contains(t, body, "Bad Request")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mock service
			mockInternalService := new(internalMocks.MockAssetService)
			tt.setupMock(mockInternalService)

			// Create real API service with mocked internal service
			apiService := service.NewAssetService(mockInternalService)

			app := fiber.New()

			// Create service getter that returns our API service
			serviceGetter := func(ctx context.Context) *service.AssetService {
				return apiService
			}

			app.Post("/assets", httpHandlers.CreateAsset(serviceGetter))

			// Setup request
			req, err := tt.setupRequest()
			assert.NoError(t, err)

			// Make request
			resp, err := app.Test(req)
			assert.NoError(t, err)

			// Assert response
			assert.Equal(t, tt.expectedStatus, resp.StatusCode)

			// Read response body
			buf := new(bytes.Buffer)
			buf.ReadFrom(resp.Body)
			responseBody := buf.String()

			tt.validateBody(t, responseBody)

			// Verify mock expectations
			mockInternalService.AssertExpectations(t)
		})
	}
}

// TestUpdateAsset_Handler tests the UpdateAsset HTTP handler
func TestUpdateAsset_Handler(t *testing.T) {
	tests := []struct {
		name           string
		assetID        string
		requestBody    interface{}
		setupMock      func(*internalMocks.MockAssetService)
		expectedStatus int
		validateBody   func(t *testing.T, body string)
	}{
		{
			name:        "successful asset update",
			assetID:     "550e8400-e29b-41d4-a716-446655440000",
			requestBody: apiFixtures.NewTestCreateAssetRequest(),
			setupMock: func(mockService *internalMocks.MockAssetService) {
				mockService.On("UpdateAsset", mock.Anything, mock.AnythingOfType("domain.AssetDomain")).
					Return(nil)
			},
			expectedStatus: fiber.StatusOK,
			validateBody: func(t *testing.T, body string) {
				var response map[string]interface{}
				err := json.Unmarshal([]byte(body), &response)
				assert.NoError(t, err)
			},
		},
		{
			name:        "missing asset ID",
			assetID:     "",
			requestBody: apiFixtures.NewTestCreateAssetRequest(),
			setupMock: func(mockService *internalMocks.MockAssetService) {
				// No mock setup needed as request should fail before reaching service
			},
			expectedStatus: fiber.StatusNotFound,
			validateBody: func(t *testing.T, body string) {
				assert.Contains(t, body, "Cannot PUT")
			},
		},
		{
			name:        "invalid asset UUID",
			assetID:     "invalid-uuid",
			requestBody: apiFixtures.NewTestCreateAssetRequest(),
			setupMock: func(mockService *internalMocks.MockAssetService) {
				// No mock setup needed as UUID validation happens in handler before service call
			},
			expectedStatus: fiber.StatusBadRequest,
			validateBody: func(t *testing.T, body string) {
				assert.Contains(t, body, "Bad Request")
			},
		},
		{
			name:        "IP already exists error",
			assetID:     "550e8400-e29b-41d4-a716-446655440000",
			requestBody: apiFixtures.NewTestCreateAssetRequestWithIP("192.168.1.100"),
			setupMock: func(mockService *internalMocks.MockAssetService) {
				mockService.On("UpdateAsset", mock.Anything, mock.AnythingOfType("domain.AssetDomain")).
					Return(service.ErrIPAlreadyExists)
			},
			expectedStatus: fiber.StatusConflict,
			validateBody: func(t *testing.T, body string) {
				assert.Contains(t, body, "IP address already exists")
			},
		},
		{
			name:        "hostname already exists error",
			assetID:     "550e8400-e29b-41d4-a716-446655440000",
			requestBody: apiFixtures.NewTestCreateAssetRequestWithHostname("existing-host"),
			setupMock: func(mockService *internalMocks.MockAssetService) {
				mockService.On("UpdateAsset", mock.Anything, mock.AnythingOfType("domain.AssetDomain")).
					Return(service.ErrHostnameAlreadyExists)
			},
			expectedStatus: fiber.StatusConflict,
			validateBody: func(t *testing.T, body string) {
				assert.Contains(t, body, "Hostname already exists")
			},
		},
		{
			name:        "invalid JSON request body",
			assetID:     "550e8400-e29b-41d4-a716-446655440000",
			requestBody: "invalid json",
			setupMock: func(mockService *internalMocks.MockAssetService) {
				// No mock setup needed as request parsing should fail
			},
			expectedStatus: fiber.StatusBadRequest,
			validateBody: func(t *testing.T, body string) {
				assert.Contains(t, body, "Bad Request")
			},
		},
		{
			name:        "internal server error",
			assetID:     "550e8400-e29b-41d4-a716-446655440000",
			requestBody: apiFixtures.NewTestCreateAssetRequest(),
			setupMock: func(mockService *internalMocks.MockAssetService) {
				mockService.On("UpdateAsset", mock.Anything, mock.AnythingOfType("domain.AssetDomain")).
					Return(errors.New("database connection failed"))
			},
			expectedStatus: fiber.StatusInternalServerError,
			validateBody: func(t *testing.T, body string) {
				assert.Contains(t, body, "database connection failed")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mock service
			mockInternalService := new(internalMocks.MockAssetService)
			tt.setupMock(mockInternalService)

			// Create real API service with mocked internal service
			apiService := service.NewAssetService(mockInternalService)

			app := fiber.New()

			// Create service getter that returns our API service
			serviceGetter := func(ctx context.Context) *service.AssetService {
				return apiService
			}

			app.Put("/assets/:id", httpHandlers.UpdateAsset(serviceGetter))

			// Create request body
			var bodyBytes []byte
			var err error
			if str, ok := tt.requestBody.(string); ok {
				bodyBytes = []byte(str)
			} else {
				bodyBytes, err = json.Marshal(tt.requestBody)
				assert.NoError(t, err)
			}

			// Make request
			url := "/assets/" + tt.assetID
			req := httptest.NewRequest("PUT", url, bytes.NewBuffer(bodyBytes))
			req.Header.Set("Content-Type", "application/json")

			resp, err := app.Test(req)
			assert.NoError(t, err)

			// Assert response
			assert.Equal(t, tt.expectedStatus, resp.StatusCode)

			// Read response body
			buf := new(bytes.Buffer)
			buf.ReadFrom(resp.Body)
			responseBody := buf.String()

			tt.validateBody(t, responseBody)

			// Verify mock expectations
			mockInternalService.AssertExpectations(t)
		})
	}
}

// TestGetAssetByID_Handler tests the GetAssetByID HTTP handler
func TestGetAssetByID_Handler(t *testing.T) {
	tests := []struct {
		name           string
		assetID        string
		setupMock      func(*internalMocks.MockAssetService)
		expectedStatus int
		validateBody   func(t *testing.T, body string)
	}{
		{
			name:    "successful asset retrieval",
			assetID: "550e8400-e29b-41d4-a716-446655440000",
			setupMock: func(mockService *internalMocks.MockAssetService) {
				testUUID := uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")
				testAsset := domain.AssetDomain{
					ID:       testUUID,
					Name:     "Test Asset",
					Hostname: "test-host",
				}
				mockService.On("GetByID", mock.Anything, testUUID).
					Return(&testAsset, nil)
			},
			expectedStatus: fiber.StatusOK,
			validateBody: func(t *testing.T, body string) {
				var response map[string]interface{}
				err := json.Unmarshal([]byte(body), &response)
				assert.NoError(t, err)
				assert.Contains(t, response, "asset")
			},
		},
		{
			name:    "missing asset ID",
			assetID: "",
			setupMock: func(mockService *internalMocks.MockAssetService) {
				// No mock setup needed as request should fail before reaching service
			},
			expectedStatus: fiber.StatusNotFound,
			validateBody: func(t *testing.T, body string) {
				assert.Contains(t, body, "Cannot GET")
			},
		},
		{
			name:    "invalid asset UUID",
			assetID: "invalid-uuid",
			setupMock: func(mockService *internalMocks.MockAssetService) {
				// No mock setup needed as UUID parsing should fail
			},
			expectedStatus: fiber.StatusBadRequest,
			validateBody: func(t *testing.T, body string) {
				assert.Contains(t, body, "Bad Request")
			},
		},
		{
			name:    "asset not found",
			assetID: "550e8400-e29b-41d4-a716-446655440000",
			setupMock: func(mockService *internalMocks.MockAssetService) {
				testUUID := uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")
				mockService.On("GetByID", mock.Anything, testUUID).
					Return((*domain.AssetDomain)(nil), service.ErrAssetNotFound)
			},
			expectedStatus: fiber.StatusNotFound,
			validateBody: func(t *testing.T, body string) {
				assert.Contains(t, body, "Not Found")
			},
		},
		{
			name:    "internal server error",
			assetID: "550e8400-e29b-41d4-a716-446655440000",
			setupMock: func(mockService *internalMocks.MockAssetService) {
				testUUID := uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")
				mockService.On("GetByID", mock.Anything, testUUID).
					Return((*domain.AssetDomain)(nil), errors.New("database connection failed"))
			},
			expectedStatus: fiber.StatusInternalServerError,
			validateBody: func(t *testing.T, body string) {
				assert.Contains(t, body, "database connection failed")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mock service
			mockInternalService := new(internalMocks.MockAssetService)
			tt.setupMock(mockInternalService)

			// Create real API service with mocked internal service
			apiService := service.NewAssetService(mockInternalService)

			app := fiber.New()

			// Create service getter that returns our API service
			serviceGetter := func(ctx context.Context) *service.AssetService {
				return apiService
			}

			app.Get("/assets/:id", httpHandlers.GetAssetByID(serviceGetter))

			// Make request
			url := "/assets/" + tt.assetID
			req := httptest.NewRequest("GET", url, nil)

			resp, err := app.Test(req)
			assert.NoError(t, err)

			// Assert response
			assert.Equal(t, tt.expectedStatus, resp.StatusCode)

			// Read response body
			buf := new(bytes.Buffer)
			buf.ReadFrom(resp.Body)
			responseBody := buf.String()

			tt.validateBody(t, responseBody)

			// Verify mock expectations
			mockInternalService.AssertExpectations(t)
		})
	}
}

// TestGetAssets_Handler tests the GetAssets HTTP handler
func TestGetAssets_Handler(t *testing.T) {
	tests := []struct {
		name           string
		queryParams    string
		setupMock      func(*internalMocks.MockAssetService)
		expectedStatus int
		validateBody   func(t *testing.T, body string)
	}{
		{
			name:        "successful assets retrieval with default pagination",
			queryParams: "",
			setupMock: func(mockService *internalMocks.MockAssetService) {
				testAssets := []domain.AssetDomain{
					{
						ID:       uuid.New(),
						Name:     "Test Asset 1",
						Hostname: "test-host-1",
					},
					{
						ID:       uuid.New(),
						Name:     "Test Asset 2",
						Hostname: "test-host-2",
					},
				}
				mockService.On("Get", mock.Anything, mock.AnythingOfType("domain.AssetFilters"),
					10, 0, mock.AnythingOfType("[]domain.SortOption")).
					Return(testAssets, 2, nil)
			},
			expectedStatus: fiber.StatusOK,
			validateBody: func(t *testing.T, body string) {
				var response map[string]interface{}
				err := json.Unmarshal([]byte(body), &response)
				assert.NoError(t, err)
				assert.Contains(t, response, "contents")
				assert.Contains(t, response, "count")
			},
		},
		{
			name:        "assets retrieval with pagination",
			queryParams: "limit=5&page=1",
			setupMock: func(mockService *internalMocks.MockAssetService) {
				testAssets := []domain.AssetDomain{
					{
						ID:       uuid.New(),
						Name:     "Test Asset 1",
						Hostname: "test-host-1",
					},
				}
				mockService.On("Get", mock.Anything, mock.AnythingOfType("domain.AssetFilters"),
					5, 5, mock.AnythingOfType("[]domain.SortOption")).
					Return(testAssets, 10, nil)
			},
			expectedStatus: fiber.StatusOK,
			validateBody: func(t *testing.T, body string) {
				var response map[string]interface{}
				err := json.Unmarshal([]byte(body), &response)
				assert.NoError(t, err)
				assert.Equal(t, float64(10), response["count"])
			},
		},
		{
			name:        "assets retrieval with filters",
			queryParams: "filter[name]=test&filter[hostname]=server",
			setupMock: func(mockService *internalMocks.MockAssetService) {
				testAssets := []domain.AssetDomain{}
				mockService.On("Get", mock.Anything, mock.MatchedBy(func(filter domain.AssetFilters) bool {
					return filter.Name == "test" && filter.Hostname == "server"
				}), 10, 0, mock.AnythingOfType("[]domain.SortOption")).
					Return(testAssets, 0, nil)
			},
			expectedStatus: fiber.StatusOK,
			validateBody: func(t *testing.T, body string) {
				var response map[string]interface{}
				err := json.Unmarshal([]byte(body), &response)
				assert.NoError(t, err)
				assert.Equal(t, float64(0), response["count"])
			},
		},
		{
			name:        "assets retrieval with sorting",
			queryParams: "sort[0][field]=name&sort[0][order]=asc",
			setupMock: func(mockService *internalMocks.MockAssetService) {
				testAssets := []domain.AssetDomain{}
				mockService.On("Get", mock.Anything, mock.AnythingOfType("domain.AssetFilters"),
					10, 0, mock.MatchedBy(func(sorts []domain.SortOption) bool {
						return len(sorts) > 0 && sorts[0].Field == "name" && sorts[0].Order == "asc"
					})).
					Return(testAssets, 0, nil)
			},
			expectedStatus: fiber.StatusOK,
			validateBody: func(t *testing.T, body string) {
				var response map[string]interface{}
				err := json.Unmarshal([]byte(body), &response)
				assert.NoError(t, err)
				assert.Contains(t, response, "contents")
			},
		},
		{
			name:        "internal server error",
			queryParams: "",
			setupMock: func(mockService *internalMocks.MockAssetService) {
				mockService.On("Get", mock.Anything, mock.AnythingOfType("domain.AssetFilters"),
					10, 0, mock.AnythingOfType("[]domain.SortOption")).
					Return([]domain.AssetDomain{}, 0, errors.New("database connection failed"))
			},
			expectedStatus: fiber.StatusInternalServerError,
			validateBody: func(t *testing.T, body string) {
				assert.Contains(t, body, "database connection failed")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mock service
			mockInternalService := new(internalMocks.MockAssetService)
			tt.setupMock(mockInternalService)

			// Create real API service with mocked internal service
			apiService := service.NewAssetService(mockInternalService)

			app := fiber.New()

			// Create service getter that returns our API service
			serviceGetter := func(ctx context.Context) *service.AssetService {
				return apiService
			}

			app.Get("/assets", httpHandlers.GetAssets(serviceGetter))

			// Make request
			url := "/assets"
			if tt.queryParams != "" {
				url += "?" + tt.queryParams
			}
			req := httptest.NewRequest("GET", url, nil)

			resp, err := app.Test(req)
			assert.NoError(t, err)

			// Assert response
			assert.Equal(t, tt.expectedStatus, resp.StatusCode)

			// Read response body
			buf := new(bytes.Buffer)
			buf.ReadFrom(resp.Body)
			responseBody := buf.String()

			tt.validateBody(t, responseBody)

			// Verify mock expectations
			mockInternalService.AssertExpectations(t)
		})
	}
}

// TestDeleteAsset_Handler tests the DeleteAsset HTTP handler
func TestDeleteAsset_Handler(t *testing.T) {
	tests := []struct {
		name           string
		assetID        string
		setupMock      func(*internalMocks.MockAssetService)
		expectedStatus int
		validateBody   func(t *testing.T, body string)
	}{
		{
			name:    "successful asset deletion",
			assetID: "550e8400-e29b-41d4-a716-446655440000",
			setupMock: func(mockService *internalMocks.MockAssetService) {
				mockService.On("DeleteAssets", mock.Anything,
					[]string{"550e8400-e29b-41d4-a716-446655440000"},
					(*domain.AssetFilters)(nil), false).
					Return(nil)
			},
			expectedStatus: fiber.StatusOK,
			validateBody: func(t *testing.T, body string) {
				var response map[string]interface{}
				err := json.Unmarshal([]byte(body), &response)
				assert.NoError(t, err)
			},
		},
		{
			name:    "missing asset ID",
			assetID: "",
			setupMock: func(mockService *internalMocks.MockAssetService) {
				// No mock setup needed as request should fail before reaching service
			},
			expectedStatus: fiber.StatusNotFound,
			validateBody: func(t *testing.T, body string) {
				assert.Contains(t, body, "Cannot DELETE")
			},
		},
		{
			name:    "invalid asset UUID",
			assetID: "invalid-uuid",
			setupMock: func(mockService *internalMocks.MockAssetService) {
				// No mock setup needed as UUID parsing should fail
			},
			expectedStatus: fiber.StatusBadRequest,
			validateBody: func(t *testing.T, body string) {
				assert.Contains(t, body, "Bad Request")
			},
		},
		{
			name:    "asset not found",
			assetID: "550e8400-e29b-41d4-a716-446655440000",
			setupMock: func(mockService *internalMocks.MockAssetService) {
				mockService.On("DeleteAssets", mock.Anything,
					[]string{"550e8400-e29b-41d4-a716-446655440000"},
					(*domain.AssetFilters)(nil), false).
					Return(service.ErrAssetNotFound)
			},
			expectedStatus: fiber.StatusNotFound,
			validateBody: func(t *testing.T, body string) {
				assert.Contains(t, body, "Not Found")
			},
		},
		{
			name:    "invalid asset UUID from service",
			assetID: "550e8400-e29b-41d4-a716-446655440000",
			setupMock: func(mockService *internalMocks.MockAssetService) {
				mockService.On("DeleteAssets", mock.Anything,
					[]string{"550e8400-e29b-41d4-a716-446655440000"},
					(*domain.AssetFilters)(nil), false).
					Return(service.ErrInvalidAssetUUID)
			},
			expectedStatus: fiber.StatusBadRequest,
			validateBody: func(t *testing.T, body string) {
				assert.Contains(t, body, "Bad Request")
			},
		},
		{
			name:    "internal server error",
			assetID: "550e8400-e29b-41d4-a716-446655440000",
			setupMock: func(mockService *internalMocks.MockAssetService) {
				mockService.On("DeleteAssets", mock.Anything,
					[]string{"550e8400-e29b-41d4-a716-446655440000"},
					(*domain.AssetFilters)(nil), false).
					Return(errors.New("database connection failed"))
			},
			expectedStatus: fiber.StatusInternalServerError,
			validateBody: func(t *testing.T, body string) {
				assert.Contains(t, body, "database connection failed")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mock service
			mockInternalService := new(internalMocks.MockAssetService)
			tt.setupMock(mockInternalService)

			// Create real API service with mocked internal service
			apiService := service.NewAssetService(mockInternalService)

			app := fiber.New()

			// Create service getter that returns our API service
			serviceGetter := func(ctx context.Context) *service.AssetService {
				return apiService
			}

			app.Delete("/assets/:id", httpHandlers.DeleteAsset(serviceGetter))

			// Make request
			url := "/assets/" + tt.assetID
			req := httptest.NewRequest("DELETE", url, nil)

			resp, err := app.Test(req)
			assert.NoError(t, err)

			// Assert response
			assert.Equal(t, tt.expectedStatus, resp.StatusCode)

			// Read response body
			buf := new(bytes.Buffer)
			buf.ReadFrom(resp.Body)
			responseBody := buf.String()

			tt.validateBody(t, responseBody)

			// Verify mock expectations
			mockInternalService.AssertExpectations(t)
		})
	}
}

// TestDeleteAssets_Handler tests the DeleteAssets HTTP handler
func TestDeleteAssets_Handler(t *testing.T) {
	tests := []struct {
		name           string
		requestBody    interface{}
		setupMock      func(*internalMocks.MockAssetService)
		expectedStatus int
		validateBody   func(t *testing.T, body string)
	}{
		{
			name: "successful multiple assets deletion",
			requestBody: map[string]interface{}{
				"ids": []string{
					"550e8400-e29b-41d4-a716-446655440000",
					"550e8400-e29b-41d4-a716-446655440001",
				},
			},
			setupMock: func(mockService *internalMocks.MockAssetService) {
				mockService.On("DeleteAssets", mock.Anything,
					[]string{
						"550e8400-e29b-41d4-a716-446655440000",
						"550e8400-e29b-41d4-a716-446655440001",
					},
					(*domain.AssetFilters)(nil), false).
					Return(nil)
			},
			expectedStatus: fiber.StatusOK,
			validateBody: func(t *testing.T, body string) {
				var response map[string]interface{}
				err := json.Unmarshal([]byte(body), &response)
				assert.NoError(t, err)
			},
		},
		{
			name: "deletion with filter",
			requestBody: map[string]interface{}{
				"ids": []string{"550e8400-e29b-41d4-a716-446655440000"},
				"filter": map[string]string{
					"name": "test",
				},
				"exclude": true,
			},
			setupMock: func(mockService *internalMocks.MockAssetService) {
				mockService.On("DeleteAssets", mock.Anything,
					[]string{"550e8400-e29b-41d4-a716-446655440000"},
					mock.MatchedBy(func(filter *domain.AssetFilters) bool {
						return filter != nil && filter.Name == "test"
					}), true).
					Return(nil)
			},
			expectedStatus: fiber.StatusOK,
			validateBody: func(t *testing.T, body string) {
				var response map[string]interface{}
				err := json.Unmarshal([]byte(body), &response)
				assert.NoError(t, err)
			},
		},
		{
			name:        "empty IDs list",
			requestBody: map[string]interface{}{"ids": []string{}},
			setupMock: func(mockService *internalMocks.MockAssetService) {
				// No mock setup needed as request should fail validation
			},
			expectedStatus: fiber.StatusBadRequest,
			validateBody: func(t *testing.T, body string) {
				assert.Contains(t, body, "IDs must not be empty")
			},
		},
		{
			name:        "invalid JSON request body",
			requestBody: "invalid json",
			setupMock: func(mockService *internalMocks.MockAssetService) {
				// No mock setup needed as request parsing should fail
			},
			expectedStatus: fiber.StatusBadRequest,
			validateBody: func(t *testing.T, body string) {
				assert.Contains(t, body, "Bad Request")
			},
		},
		{
			name: "invalid asset UUIDs",
			requestBody: map[string]interface{}{
				"ids": []string{"invalid-uuid"},
			},
			setupMock: func(mockService *internalMocks.MockAssetService) {
				mockService.On("DeleteAssets", mock.Anything,
					[]string{"invalid-uuid"},
					(*domain.AssetFilters)(nil), false).
					Return(service.ErrInvalidAssetUUID)
			},
			expectedStatus: fiber.StatusBadRequest,
			validateBody: func(t *testing.T, body string) {
				assert.Contains(t, body, "invalid asset UUID")
			},
		},
		{
			name: "internal server error",
			requestBody: map[string]interface{}{
				"ids": []string{"550e8400-e29b-41d4-a716-446655440000"},
			},
			setupMock: func(mockService *internalMocks.MockAssetService) {
				mockService.On("DeleteAssets", mock.Anything,
					[]string{"550e8400-e29b-41d4-a716-446655440000"},
					(*domain.AssetFilters)(nil), false).
					Return(errors.New("database connection failed"))
			},
			expectedStatus: fiber.StatusInternalServerError,
			validateBody: func(t *testing.T, body string) {
				assert.Contains(t, body, "database connection failed")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mock service
			mockInternalService := new(internalMocks.MockAssetService)
			tt.setupMock(mockInternalService)

			// Create real API service with mocked internal service
			apiService := service.NewAssetService(mockInternalService)

			app := fiber.New()

			// Create service getter that returns our API service
			serviceGetter := func(ctx context.Context) *service.AssetService {
				return apiService
			}

			app.Delete("/assets", httpHandlers.DeleteAssets(serviceGetter))

			// Create request body
			var bodyBytes []byte
			var err error
			if str, ok := tt.requestBody.(string); ok {
				bodyBytes = []byte(str)
			} else {
				bodyBytes, err = json.Marshal(tt.requestBody)
				assert.NoError(t, err)
			}

			// Make request
			req := httptest.NewRequest("DELETE", "/assets", bytes.NewBuffer(bodyBytes))
			req.Header.Set("Content-Type", "application/json")

			resp, err := app.Test(req)
			assert.NoError(t, err)

			// Assert response
			assert.Equal(t, tt.expectedStatus, resp.StatusCode)

			// Read response body
			buf := new(bytes.Buffer)
			buf.ReadFrom(resp.Body)
			responseBody := buf.String()

			tt.validateBody(t, responseBody)

			// Verify mock expectations
			mockInternalService.AssertExpectations(t)
		})
	}
}

// TestExportAssets_Handler tests the ExportAssets HTTP handler
func TestExportAssets_Handler(t *testing.T) {
	tests := []struct {
		name            string
		requestBody     interface{}
		setupMock       func(*internalMocks.MockAssetService)
		expectedStatus  int
		validateBody    func(t *testing.T, body string)
		validateHeaders func(t *testing.T, headers http.Header)
	}{
		{
			name: "successful full export",
			requestBody: map[string]interface{}{
				"asset_ids":   []string{"550e8400-e29b-41d4-a716-446655440000"},
				"export_type": 0, // FULL_EXPORT
			},
			setupMock: func(mockService *internalMocks.MockAssetService) {
				testUUID := uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")
				csvData := []byte("id,name,hostname\n550e8400-e29b-41d4-a716-446655440000,Test Asset,test-host")

				mockService.On("ExportAssets", mock.Anything,
					[]domain.AssetUUID{testUUID},
					domain.FullExport,
					[]string(nil)).
					Return(&domain.ExportData{}, nil)

				mockService.On("GenerateCSV", mock.Anything,
					mock.AnythingOfType("*domain.ExportData")).
					Return(csvData, nil)
			},
			expectedStatus: fiber.StatusOK,
			validateBody: func(t *testing.T, body string) {
				assert.Contains(t, body, "id,name,hostname")
				assert.Contains(t, body, "Test Asset")
			},
			validateHeaders: func(t *testing.T, headers http.Header) {
				assert.Contains(t, headers.Get("Content-Type"), "text/csv")
				assert.Contains(t, headers.Get("Content-Disposition"), "attachment")
			},
		},
		{
			name: "successful selected columns export",
			requestBody: map[string]interface{}{
				"asset_ids":        []string{"550e8400-e29b-41d4-a716-446655440000"},
				"export_type":      1, // SELECTED_COLUMNS
				"selected_columns": []string{"name", "hostname"},
			},
			setupMock: func(mockService *internalMocks.MockAssetService) {
				testUUID := uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")
				csvData := []byte("name,hostname\nTest Asset,test-host")

				mockService.On("ExportAssets", mock.Anything,
					[]domain.AssetUUID{testUUID},
					domain.SelectedColumnsExport,
					[]string{"name", "hostname"}).
					Return(&domain.ExportData{}, nil)

				mockService.On("GenerateCSV", mock.Anything,
					mock.AnythingOfType("*domain.ExportData")).
					Return(csvData, nil)
			},
			expectedStatus: fiber.StatusOK,
			validateBody: func(t *testing.T, body string) {
				assert.Contains(t, body, "name,hostname")
				assert.NotContains(t, body, "id")
			},
			validateHeaders: func(t *testing.T, headers http.Header) {
				assert.Contains(t, headers.Get("Content-Type"), "text/csv")
			},
		},
		{
			name: "export all assets",
			requestBody: map[string]interface{}{
				"asset_ids":   []string{"All"},
				"export_type": 0, // FULL_EXPORT
			},
			setupMock: func(mockService *internalMocks.MockAssetService) {
				csvData := []byte("id,name,hostname\nAll assets exported")

				mockService.On("ExportAssets", mock.Anything,
					[]domain.AssetUUID{}, // "All"
					domain.FullExport,
					[]string(nil)).
					Return(&domain.ExportData{}, nil)

				mockService.On("GenerateCSV", mock.Anything,
					mock.AnythingOfType("*domain.ExportData")).
					Return(csvData, nil)
			},
			expectedStatus: fiber.StatusOK,
			validateBody: func(t *testing.T, body string) {
				assert.Contains(t, body, "All assets exported")
			},
			validateHeaders: func(t *testing.T, headers http.Header) {
				assert.Contains(t, headers.Get("Content-Type"), "text/csv")
			},
		},
		{
			name: "selected columns export without columns",
			requestBody: map[string]interface{}{
				"asset_ids":        []string{"550e8400-e29b-41d4-a716-446655440000"},
				"export_type":      1, // SELECTED_COLUMNS
				"selected_columns": []string{},
			},
			setupMock: func(mockService *internalMocks.MockAssetService) {
				// No mock setup needed as request should fail validation
			},
			expectedStatus: fiber.StatusBadRequest,
			validateBody: func(t *testing.T, body string) {
				assert.Contains(t, body, "selected columns must not be empty")
			},
			validateHeaders: func(t *testing.T, headers http.Header) {
				// No special headers expected for error response
			},
		},
		{
			name:        "invalid JSON request body",
			requestBody: "invalid json",
			setupMock: func(mockService *internalMocks.MockAssetService) {
				// No mock setup needed as request parsing should fail
			},
			expectedStatus: fiber.StatusBadRequest,
			validateBody: func(t *testing.T, body string) {
				assert.Contains(t, body, "Bad Request")
			},
			validateHeaders: func(t *testing.T, headers http.Header) {
				// No special headers expected for error response
			},
		},
		{
			name: "invalid asset UUID",
			requestBody: map[string]interface{}{
				"asset_ids":   []string{"invalid-uuid"},
				"export_type": 0,
			},
			setupMock: func(mockService *internalMocks.MockAssetService) {
				// Mock should not be called as UUID parsing should fail in API service
			},
			expectedStatus: fiber.StatusBadRequest,
			validateBody: func(t *testing.T, body string) {
				assert.Contains(t, body, "Bad Request")
			},
			validateHeaders: func(t *testing.T, headers http.Header) {
				// No special headers expected for error response
			},
		},
		{
			name: "export service error",
			requestBody: map[string]interface{}{
				"asset_ids":   []string{"550e8400-e29b-41d4-a716-446655440000"},
				"export_type": 0,
			},
			setupMock: func(mockService *internalMocks.MockAssetService) {
				testUUID := uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")

				mockService.On("ExportAssets", mock.Anything,
					[]domain.AssetUUID{testUUID},
					domain.FullExport,
					[]string(nil)).
					Return((*domain.ExportData)(nil), errors.New("export failed"))
			},
			expectedStatus: fiber.StatusInternalServerError,
			validateBody: func(t *testing.T, body string) {
				assert.Contains(t, body, "export failed")
			},
			validateHeaders: func(t *testing.T, headers http.Header) {
				// No special headers expected for error response
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mock service
			mockInternalService := new(internalMocks.MockAssetService)
			tt.setupMock(mockInternalService)

			// Create real API service with mocked internal service
			apiService := service.NewAssetService(mockInternalService)

			app := fiber.New()

			// Create service getter that returns our API service
			serviceGetter := func(ctx context.Context) *service.AssetService {
				return apiService
			}

			app.Post("/assets/export", httpHandlers.ExportAssets(serviceGetter))

			// Create request body
			var bodyBytes []byte
			var err error
			if str, ok := tt.requestBody.(string); ok {
				bodyBytes = []byte(str)
			} else {
				bodyBytes, err = json.Marshal(tt.requestBody)
				assert.NoError(t, err)
			}

			// Make request
			req := httptest.NewRequest("POST", "/assets/export", bytes.NewBuffer(bodyBytes))
			req.Header.Set("Content-Type", "application/json")

			resp, err := app.Test(req)
			assert.NoError(t, err)

			// Assert response
			assert.Equal(t, tt.expectedStatus, resp.StatusCode)

			// Read response body
			buf := new(bytes.Buffer)
			buf.ReadFrom(resp.Body)
			responseBody := buf.String()

			tt.validateBody(t, responseBody)
			tt.validateHeaders(t, resp.Header)

			// Verify mock expectations
			mockInternalService.AssertExpectations(t)
		})
	}
}

// TestGetDistinctOSNames_Handler tests the GetDistinctOSNames HTTP handler
func TestGetDistinctOSNames_Handler(t *testing.T) {
	tests := []struct {
		name           string
		setupMock      func(*internalMocks.MockAssetService)
		expectedStatus int
		validateBody   func(t *testing.T, body string)
	}{
		{
			name: "successful OS names retrieval",
			setupMock: func(mockService *internalMocks.MockAssetService) {
				osNames := []string{"Ubuntu", "CentOS", "Windows Server 2019", "RHEL"}
				mockService.On("GetDistinctOSNames", mock.Anything).
					Return(osNames, nil)
			},
			expectedStatus: fiber.StatusOK,
			validateBody: func(t *testing.T, body string) {
				var response map[string]interface{}
				err := json.Unmarshal([]byte(body), &response)
				assert.NoError(t, err)
				assert.Contains(t, response, "os_names")

				osNames, ok := response["os_names"].([]interface{})
				assert.True(t, ok)
				assert.Len(t, osNames, 4)
				assert.Contains(t, osNames, "Ubuntu")
				assert.Contains(t, osNames, "CentOS")
			},
		},
		{
			name: "empty OS names list",
			setupMock: func(mockService *internalMocks.MockAssetService) {
				osNames := []string{}
				mockService.On("GetDistinctOSNames", mock.Anything).
					Return(osNames, nil)
			},
			expectedStatus: fiber.StatusOK,
			validateBody: func(t *testing.T, body string) {
				var response map[string]interface{}
				err := json.Unmarshal([]byte(body), &response)
				assert.NoError(t, err)

				// When the os_names array is empty, protobuf omits it from JSON output entirely
				osNames, exists := response["os_names"]
				if exists {
					osNamesSlice, ok := osNames.([]interface{})
					assert.True(t, ok)
					assert.Len(t, osNamesSlice, 0)
				} else {
					// If the field doesn't exist, that's also valid for an empty list
					assert.True(t, true)
				}
			},
		},
		{
			name: "internal server error",
			setupMock: func(mockService *internalMocks.MockAssetService) {
				mockService.On("GetDistinctOSNames", mock.Anything).
					Return([]string{}, errors.New("database connection failed"))
			},
			expectedStatus: fiber.StatusInternalServerError,
			validateBody: func(t *testing.T, body string) {
				assert.Contains(t, body, "database connection failed")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mock service
			mockInternalService := new(internalMocks.MockAssetService)
			tt.setupMock(mockInternalService)

			// Create real API service with mocked internal service
			apiService := service.NewAssetService(mockInternalService)

			app := fiber.New()

			// Create service getter that returns our API service
			serviceGetter := func(ctx context.Context) *service.AssetService {
				return apiService
			}

			app.Get("/assets/os-names", httpHandlers.GetDistinctOSNames(serviceGetter))

			// Make request
			req := httptest.NewRequest("GET", "/assets/os-names", nil)

			resp, err := app.Test(req)
			assert.NoError(t, err)

			// Assert response
			assert.Equal(t, tt.expectedStatus, resp.StatusCode)

			// Read response body
			buf := new(bytes.Buffer)
			buf.ReadFrom(resp.Body)
			responseBody := buf.String()

			tt.validateBody(t, responseBody)

			// Verify mock expectations
			mockInternalService.AssertExpectations(t)
		})
	}
}
