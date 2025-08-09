# Comprehensive Testing Guide for Asset Discovery Service

This guide explains how to write unit tests for the Asset Discovery service following the hexagonal architecture pattern. It includes specific patterns, examples, and best practices learned from implementing comprehensive test coverage for the Create Asset functionality.

## Project Structure and Testing Layers

The project follows hexagonal (ports and adapters) architecture with these main layers:

1. **API Layer** (`api/handlers/http/`, `api/service/`) - HTTP handlers and API service layer
2. **Internal Layer** (`internal/asset/service.go`) - Core business logic service
3. **Domain Layer** (`internal/asset/domain/`) - Domain models and business rules
4. **Infrastructure Layer** (`pkg/adapter/storage/`) - Database adapters and external dependencies

## Testing Framework and Tools

We use the standard Go testing framework with these additional tools:
- **testify/assert** - For assertions
- **testify/mock** - For mocking dependencies
- **sqlmock** - For mocking database interactions

## Testing Strategy

### 1. Unit Tests
Test individual components in isolation with mocked dependencies.

### 2. Mock Strategy
- Mock external dependencies (database, HTTP clients)
- Use interfaces for dependency injection
- Create test doubles for complex business logic

## Layer-by-Layer Testing Guide

### API Layer Testing

**What to test:**
- HTTP request/response handling
- Request validation
- Error handling and status codes
- Service method calls

**Example structure:**
```go
func TestCreateAsset_Handler(t *testing.T) {
    tests := []struct {
        name           string
        requestBody    interface{}
        mockResponse   interface{}
        mockError      error
        expectedStatus int
        expectedBody   interface{}
    }{
        // Test cases
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // Setup mocks
            // Create request
            // Call handler
            // Assert response
        })
    }
}
```

### API Service Layer Testing

**What to test:**
- Request/response transformation
- Business logic delegation
- Error mapping
- Data validation

**Mock dependencies:**
- Internal service layer (port.Service interface)

### Internal Service Layer Testing

**What to test:**
- Core business logic
- Domain rule enforcement
- Repository interactions
- Error handling

**Mock dependencies:**
- Repository layer (port.Repo interface)

### Repository/Storage Layer Testing

**What to test:**
- Database operations (CRUD)
- Query building
- Transaction handling
- Data mapping

**Mock dependencies:**
- Database (*gorm.DB) using sqlmock

## Test Data Management

### Understanding Test Fixtures

Test fixtures are reusable data structures that provide consistent, well-defined test data across your test suite. They eliminate code duplication and ensure test reliability by providing predictable data states.

#### Why Use Fixtures?
1. **Consistency**: Same data structure across multiple tests
2. **Maintainability**: Change in one place affects all tests
3. **Readability**: Clear intent of what data represents
4. **Isolation**: Each test gets fresh, unmodified data
5. **Flexibility**: Easy to create variations for different scenarios

#### Fixture Design Patterns

##### 1. Builder Pattern for Domain Objects
```go
// File: tests/fixtures/domain/asset.go
package domain

import (
    "time"
    "github.com/google/uuid"
    "gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/domain"
)

// AssetBuilder provides a fluent interface for building test assets
type AssetBuilder struct {
    asset domain.AssetDomain
}

func NewAssetBuilder() *AssetBuilder {
    return &AssetBuilder{
        asset: domain.AssetDomain{
            ID:          uuid.New(),
            Name:        "Test Asset",
            Hostname:    "test-host",
            Domain:      "test.local",
            OSName:      "Ubuntu",
            OSVersion:   "20.04",
            Description: "Test asset for unit tests",
            AssetType:   "Server",
            Risk:        1,
            AssetValue:  100,
            CreatedAt:   time.Now(),
            UpdatedAt:   time.Now(),
        },
    }
}

func (b *AssetBuilder) Build() domain.AssetDomain {
    return b.asset
}

// Convenience builders for common scenarios
func NewBasicAsset() domain.AssetDomain {
    return NewAssetBuilder().Build()
}

func NewAssetWithHostname(hostname string) domain.AssetDomain {
    return NewAssetBuilder().WithHostname(hostname).Build()
}

func NewAssetWithPorts(portCount int) domain.AssetDomain {
    builder := NewAssetBuilder()
    ports := make([]domain.Port, portCount)
    for i := 0; i < portCount; i++ {
        ports[i] = NewTestPort(80 + i)
    }
    return builder.WithPorts(ports).Build()
}

func NewAssetWithIPs(ipCount int) domain.AssetDomain {
    builder := NewAssetBuilder()
    ips := make([]domain.IP, ipCount)
    for i := 0; i < ipCount; i++ {
        ips[i] = NewTestIP(fmt.Sprintf("192.168.1.%d", 100+i))
    }
    return builder.WithIPs(ips).Build()
}

func NewTestPort(port int) domain.Port {
    return domain.Port{
        ID:       uuid.New(),
        Port:     port,
        Protocol: "TCP",
        State:    "open",
        Service:  "http",
        Version:  "1.0",
    }
}

func NewTestIP(ip string) domain.IP {
    return domain.IP{
        ID:      uuid.New(),
        IP:      ip,
        MAC:     "00:1B:44:11:3A:B7",
        AssetID: uuid.New(),
    }
}
```

##### 2. API Request/Response Fixtures
```go
// File: tests/fixtures/api/asset.go
package api

import (
    "github.com/google/uuid"
    "gitlab.apk-group.net/siem/backend/asset-discovery/api/pb"
)

func NewCreateAssetRequest() *pb.CreateAssetRequest {
    return &pb.CreateAssetRequest{
        Name:        "Test Asset",
        Hostname:    "test-host",
        Domain:      "test.local",
        OsName:      "Ubuntu",
        OsVersion:   "20.04",
        Description: "Test asset for unit tests",
        AssetType:   "Server",
        Risk:        1,
        AssetValue:  100,
        Ports: []*pb.Port{
            {Port: 80, Protocol: "TCP", State: "open", Service: "http"},
            {Port: 443, Protocol: "TCP", State: "open", Service: "https"},
        },
        Ips: []*pb.IP{
            {Ip: "192.168.1.100", Mac: "00:1B:44:11:3A:B7"},
        },
    }
}

func NewCreateAssetRequestWithHostname(hostname string) *pb.CreateAssetRequest {
    req := NewCreateAssetRequest()
    req.Hostname = hostname
    return req
}

func NewMinimalCreateAssetRequest() *pb.CreateAssetRequest {
    return &pb.CreateAssetRequest{
        Name:     "Minimal Asset",
        Hostname: "minimal-host",
    }
}

func NewInvalidCreateAssetRequest() *pb.CreateAssetRequest {
    return &pb.CreateAssetRequest{
        // Missing required fields like Name and Hostname
        Description: "Invalid request",
    }
}

func NewCreateAssetResponse(id uuid.UUID) *pb.CreateAssetResponse {
    return &pb.CreateAssetResponse{
        Id:      id.String(),
        Success: true,
        Message: "Asset created successfully",
    }
}
```

##### 3. Database Record Fixtures
```go
// File: tests/fixtures/storage/asset.go
package storage

import (
    "time"
    "github.com/google/uuid"
    "gitlab.apk-group.net/siem/backend/asset-discovery/pkg/adapter/storage/types"
)

func NewAssetRecord() types.Asset {
    return types.Asset{
        ID:          uuid.New(),
        Name:        "Test Asset",
        Hostname:    "test-host",
        Domain:      "test.local",
        OSName:      "Ubuntu",
        OSVersion:   "20.04",
        Description: "Test asset for unit tests",
        AssetType:   "Server",
        Risk:        1,
        AssetValue:  100,
        CreatedAt:   time.Now(),
        UpdatedAt:   time.Now(),
    }
}

func NewAssetRecordWithID(id uuid.UUID) types.Asset {
    asset := NewAssetRecord()
    asset.ID = id
    return asset
}
```

#### Fixture Usage Patterns

##### Test-Specific Modifications
```go
func TestCreateAsset_WithSpecificHostname(t *testing.T) {
    // Start with base fixture and modify as needed
    asset := domainFixtures.NewBasicAsset()
    asset.Hostname = "specific-test-host"
    
    // Use in test...
}
```

##### Parameterized Fixtures
```go
func TestCreateAsset_MultipleScenarios(t *testing.T) {
    tests := []struct {
        name     string
        fixture  func() domain.AssetDomain
        expected string
    }{
        {
            name:     "basic asset",
            fixture:  domainFixtures.NewBasicAsset,
            expected: "success",
        },
        {
            name:     "asset with ports",
            fixture:  func() domain.AssetDomain { return domainFixtures.NewAssetWithPorts(3) },
            expected: "success",
        },
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            asset := tt.fixture()
            // Test logic...
        })
    }
}
```

## Error Testing Scenarios

Test all error conditions:

1. **Validation Errors**
   - Invalid input data
   - Missing required fields
   - Business rule violations

2. **Infrastructure Errors**
   - Database connection failures
   - Transaction rollback scenarios
   - Network timeouts

3. **Business Logic Errors**
   - Duplicate IP addresses
   - Duplicate hostnames
   - Invalid asset states
   - ...

## Understanding Mocking in Testing

### What Are Mocks?

Mocks are test doubles that simulate the behavior of real dependencies in a controlled way. They allow you to:

1. **Isolate Units Under Test**: Test one component without depending on others
2. **Control External Behavior**: Define exactly how dependencies behave
3. **Verify Interactions**: Ensure correct methods are called with expected parameters
4. **Simulate Error Conditions**: Test error handling without causing real errors
5. **Improve Test Performance**: Avoid slow operations like database calls

### Types of Test Doubles

#### 1. Mocks
Verify that specific methods are called with expected parameters:
```go
mockRepo := &mocks.MockAssetRepo{}
mockRepo.On("Create", mock.Anything, mock.AnythingOfType("domain.AssetDomain")).
    Return(expectedID, nil)

// After test execution
mockRepo.AssertExpectations(t) // Verifies the method was called
```

#### 2. Stubs
Return predefined responses without verification:
```go
stubRepo := &mocks.MockAssetRepo{}
stubRepo.On("GetByID", mock.Anything, assetID).
    Return(expectedAsset, nil) // Just returns data, doesn't verify calls
```

#### 3. Fakes
Working implementations with simplified behavior:
```go
type FakeAssetRepo struct {
    assets map[uuid.UUID]domain.AssetDomain
}

func (f *FakeAssetRepo) Create(ctx context.Context, asset domain.AssetDomain) (uuid.UUID, error) {
    id := uuid.New()
    f.assets[id] = asset
    return id, nil
}
```

### Mock Implementation Patterns

#### 1. Interface-Based Mocking with testify/mock

##### Creating Mock Structures
```go
// File: tests/mocks/service/asset_service.go
package service

import (
    "context"
    "github.com/stretchr/testify/mock"
    "gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/domain"
)

type MockAssetService struct {
    mock.Mock
}

func (m *MockAssetService) CreateAsset(ctx context.Context, asset domain.AssetDomain) (uuid.UUID, error) {
    args := m.Called(ctx, asset)
    return args.Get(0).(uuid.UUID), args.Error(1)
}

func (m *MockAssetService) GetAsset(ctx context.Context, id uuid.UUID) (domain.AssetDomain, error) {
    args := m.Called(ctx, id)
    return args.Get(0).(domain.AssetDomain), args.Error(1)
}

func (m *MockAssetService) UpdateAsset(ctx context.Context, asset domain.AssetDomain) error {
    args := m.Called(ctx, asset)
    return args.Error(0)
}

func (m *MockAssetService) DeleteAsset(ctx context.Context, id uuid.UUID) error {
    args := m.Called(ctx, id)
    return args.Error(0)
}
```

##### Mock Setup Patterns
```go
func setupSuccessfulCreateMock(mockService *mocks.MockAssetService, expectedID uuid.UUID) {
    mockService.On("CreateAsset", 
        mock.Anything, // Context - we don't care about specific context
        mock.AnythingOfType("domain.AssetDomain"), // Type-based matching
    ).Return(expectedID, nil).Once() // Execute once only
}

func setupErrorMock(mockService *mocks.MockAssetService, expectedError error) {
    mockService.On("CreateAsset", 
        mock.Anything,
        mock.AnythingOfType("domain.AssetDomain"),
    ).Return(uuid.Nil, expectedError)
}

func setupSpecificParameterMock(mockService *mocks.MockAssetService, expectedAsset domain.AssetDomain) {
    mockService.On("CreateAsset", 
        mock.MatchedBy(func(ctx context.Context) bool {
            return ctx != nil // Custom context validation
        }),
        mock.MatchedBy(func(asset domain.AssetDomain) bool {
            return asset.Hostname == expectedAsset.Hostname // Specific validation
        }),
    ).Return(uuid.New(), nil)
}
```

#### 2. Database Mocking with sqlmock

##### Basic Setup
```go
// File: tests/unit/pkg/adapter/storage/asset_repo_test.go
package storage_test

import (
    "database/sql"
    "testing"
    "github.com/DATA-DOG/go-sqlmock"
    "gorm.io/driver/mysql"
    "gorm.io/gorm"
    "github.com/stretchr/testify/require"
)

type DatabaseTestSuite struct {
    db       *sql.DB
    gormDB   *gorm.DB
    mock     sqlmock.Sqlmock
    repo     *storage.AssetRepo
}

func setupDatabaseTest(t *testing.T) *DatabaseTestSuite {
    // Create sqlmock
    db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
    require.NoError(t, err)

    // Setup GORM with sqlmock
    gormDB, err := gorm.Open(mysql.New(mysql.Config{
        Conn:                      db,
        SkipInitializeWithVersion: true,
    }), &gorm.Config{
        DisableAutomaticPing: true,
    })
    require.NoError(t, err)

    repo := storage.NewAssetRepo(gormDB)

    return &DatabaseTestSuite{
        db:     db,
        gormDB: gormDB,
        mock:   mock,
        repo:   repo,
    }
}

func (suite *DatabaseTestSuite) tearDown() {
    suite.db.Close()
}
```

##### SQL Query Mocking Patterns
```go
func TestAssetRepository_Create_Success(t *testing.T) {
    suite := setupDatabaseTest(t)
    defer suite.tearDown()

    asset := domainFixtures.NewBasicAsset()

    // Mock hostname uniqueness check
    suite.mock.ExpectQuery(
        "SELECT count(*) FROM `assets` WHERE hostname = ? AND deleted_at IS NULL",
    ).WithArgs(asset.Hostname).
        WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

    // Mock transaction begin
    suite.mock.ExpectBegin()

    // Mock asset creation
    suite.mock.ExpectExec(
        "INSERT INTO `assets` (`id`,`name`,`hostname`,`domain`,`os_name`,`os_version`,`description`,`asset_type`,`risk`,`logging_completed`,`asset_value`,`updated_at`,`deleted_at`,`created_at`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
    ).WithArgs(
        asset.ID, asset.Name, asset.Hostname, asset.Domain,
        asset.OSName, asset.OSVersion, asset.Description,
        asset.AssetType, asset.Risk, false, asset.AssetValue,
        sqlmock.AnyArg(), nil, sqlmock.AnyArg(),
    ).WillReturnResult(sqlmock.NewResult(1, 1))

    // Mock transaction commit
    suite.mock.ExpectCommit()

    // Execute test
    resultID, err := suite.repo.Create(context.Background(), asset)

    // Assertions
    assert.NoError(t, err)
    assert.Equal(t, asset.ID, resultID)
    assert.NoError(t, suite.mock.ExpectationsWereMet())
}
```

##### Error Scenario Mocking
```go
func TestAssetRepository_Create_DatabaseError(t *testing.T) {
    suite := setupDatabaseTest(t)
    defer suite.tearDown()

    asset := domainFixtures.NewBasicAsset()

    // Mock database connection error
    suite.mock.ExpectQuery(
        "SELECT count(*) FROM `assets` WHERE hostname = ? AND deleted_at IS NULL",
    ).WithArgs(asset.Hostname).
        WillReturnError(sql.ErrConnDone)

    // Execute test
    _, err := suite.repo.Create(context.Background(), asset)

    // Assertions
    assert.Error(t, err)
    assert.Equal(t, sql.ErrConnDone, err)
    assert.NoError(t, suite.mock.ExpectationsWereMet())
}
```

#### 3. HTTP Client Mocking

##### Using httptest for HTTP Handlers
```go
func TestAssetHandler_CreateAsset(t *testing.T) {
    // Setup mock service
    mockService := &mocks.MockAssetService{}
    expectedID := uuid.New()
    mockService.On("CreateAsset", mock.Anything, mock.AnythingOfType("domain.AssetDomain")).
        Return(expectedID, nil)

    // Create handler with mock service
    handler := http.NewAssetHandler(mockService)

    // Setup HTTP request
    requestBody := apiFixtures.NewCreateAssetRequest()
    jsonBody, _ := json.Marshal(requestBody)
    req := httptest.NewRequest("POST", "/api/v1/assets", bytes.NewReader(jsonBody))
    req.Header.Set("Content-Type", "application/json")
    
    // Setup response recorder
    w := httptest.NewRecorder()

    // Execute
    handler.ServeHTTP(w, req)

    // Assert
    assert.Equal(t, http.StatusCreated, w.Code)
    mockService.AssertExpectations(t)
}
```

### Advanced Mocking Techniques

#### 1. Mock Chaining for Complex Scenarios
```go
func TestAssetService_ComplexWorkflow(t *testing.T) {
    mockRepo := &mocks.MockAssetRepo{}
    
    // Chain multiple mock calls for complex workflow
    mockRepo.On("BeginTransaction", mock.Anything).Return(mockTx, nil).Once()
    mockRepo.On("ValidateAsset", mock.Anything, mock.AnythingOfType("domain.AssetDomain")).Return(nil).Once()
    mockRepo.On("CreateAsset", mock.Anything, mock.AnythingOfType("domain.AssetDomain")).Return(assetID, nil).Once()
    mockRepo.On("CreatePorts", mock.Anything, assetID, mock.AnythingOfType("[]domain.Port")).Return(nil).Once()
    mockRepo.On("CommitTransaction", mock.Anything).Return(nil).Once()

    service := asset.NewAssetService(mockRepo)
    
    asset := domainFixtures.NewAssetWithPorts(3)
    result, err := service.CreateAssetWithPorts(context.Background(), asset)

    assert.NoError(t, err)
    assert.Equal(t, assetID, result)
    mockRepo.AssertExpectations(t)
}
```

#### 2. Conditional Mock Behavior
```go
func setupConditionalMock(mockRepo *mocks.MockAssetRepo) {
    mockRepo.On("CreateAsset", mock.Anything, mock.MatchedBy(func(asset domain.AssetDomain) bool {
        if asset.Hostname == "duplicate-host" {
            return true // This will trigger specific error
        }
        return false
    })).Return(uuid.Nil, domain.ErrHostnameAlreadyExists)

    mockRepo.On("CreateAsset", mock.Anything, mock.MatchedBy(func(asset domain.AssetDomain) bool {
        return asset.Hostname != "duplicate-host" // All other cases succeed
    })).Return(uuid.New(), nil)
}
```

#### 3. Mock Side Effects
```go
func TestAssetService_WithSideEffects(t *testing.T) {
    mockRepo := &mocks.MockAssetRepo{}
    var capturedAsset domain.AssetDomain

    mockRepo.On("CreateAsset", mock.Anything, mock.AnythingOfType("domain.AssetDomain")).
        Run(func(args mock.Arguments) {
            // Capture arguments for later inspection
            capturedAsset = args.Get(1).(domain.AssetDomain)
        }).Return(uuid.New(), nil)

    service := asset.NewAssetService(mockRepo)
    inputAsset := domainFixtures.NewBasicAsset()
    
    _, err := service.CreateAsset(context.Background(), inputAsset)

    assert.NoError(t, err)
    assert.Equal(t, inputAsset.Hostname, capturedAsset.Hostname)
    mockRepo.AssertExpectations(t)
}
```

### Mock Best Practices

#### 1. Mock Interface, Not Implementation
```go
// Good: Mock the interface
type AssetService interface {
    CreateAsset(ctx context.Context, asset domain.AssetDomain) (uuid.UUID, error)
}

// Bad: Mock concrete struct
type ConcreteAssetService struct {
    repo AssetRepo
}
```

#### 2. Use Descriptive Mock Setup Functions
```go
func setupSuccessfulAssetCreation(mock *mocks.MockAssetRepo, asset domain.AssetDomain, expectedID uuid.UUID) {
    mock.On("CreateAsset", mock.Anything, asset).Return(expectedID, nil)
}

func setupHostnameConflictError(mock *mocks.MockAssetRepo) {
    mock.On("CreateAsset", mock.Anything, mock.AnythingOfType("domain.AssetDomain")).
        Return(uuid.Nil, domain.ErrHostnameAlreadyExists)
}
```

#### 3. Verify Mock Expectations
```go
func TestAssetHandler_CreateAsset(t *testing.T) {
    mockService := &mocks.MockAssetService{}
    // ... setup mock expectations
    
    // ... execute test
    
    // Always verify mock expectations were met
    mockService.AssertExpectations(t)
    
    // Optionally verify specific methods were called
    mockService.AssertCalled(t, "CreateAsset", mock.Anything, mock.AnythingOfType("domain.AssetDomain"))
    
    // Verify method was called exact number of times
    mockService.AssertNumberOfCalls(t, "CreateAsset", 1)
}
```

#### 4. Reset Mocks Between Tests
```go
func TestAssetService_MultipleTests(t *testing.T) {
    mockRepo := &mocks.MockAssetRepo{}
    
    t.Run("first test", func(t *testing.T) {
        mockRepo.On("CreateAsset", mock.Anything, mock.AnythingOfType("domain.AssetDomain")).
            Return(uuid.New(), nil)
        
        // Test logic...
        
        mockRepo.AssertExpectations(t)
    })
    
    // Reset mock for next test
    mockRepo.ExpectedCalls = nil
    mockRepo.Calls = nil
    
    t.Run("second test", func(t *testing.T) {
        mockRepo.On("GetAsset", mock.Anything, mock.AnythingOfType("uuid.UUID")).
            Return(domainFixtures.NewBasicAsset(), nil)
        
        // Test logic...
        
        mockRepo.AssertExpectations(t)
    })
}
```

### Common Mocking Pitfalls to Avoid

#### 1. Over-Mocking
```go
// Bad: Mocking value objects
mockUUID := &MockUUID{}
mockTime := &MockTime{}

// Good: Use real value objects
realUUID := uuid.New()
realTime := time.Now()
```

#### 2. Mocking What You Don't Own
```go
// Bad: Mocking third-party libraries directly
mockGormDB := &mocks.MockGormDB{}

// Good: Create your own interface and mock that
type DatabaseInterface interface {
    Create(interface{}) error
    First(interface{}, ...interface{}) error
}
```

#### 3. Ignoring Mock Expectations
```go
// Bad: Setting up mocks without verification
mock.On("Method", arg).Return(result)
// Missing: mock.AssertExpectations(t)

// Good: Always verify
mock.On("Method", arg).Return(result)
// ... test execution ...
mock.AssertExpectations(t)
```

#### 4. Brittle Mocks
```go
// Bad: Too specific mocking
mock.On("CreateAsset", specificContext, exactAsset).Return(result)

// Good: Flexible matching
mock.On("CreateAsset", 
    mock.Anything, 
    mock.MatchedBy(func(asset domain.AssetDomain) bool {
        return asset.Hostname != ""
    }),
).Return(result)
```

## Test Coverage Measurement and Analysis

### Complete Coverage Report (All Layers)
```bash
# Generate coverage profile
go test -coverprofile=coverage.out ./tests/unit/api/handlers ./tests/unit/api/service ./tests/unit/internal/asset ./tests/unit/pkg/adapter/storage -coverpkg=./api/handlers/http,./api/service,./internal/asset,./pkg/adapter/storage

# Convert to HTML
go tool cover -html=coverage.out -o coverage.html
```

### Individual Layer Coverage Reports

#### Handler Layer Only
```bash
go test -coverprofile=coverage-handlers.out ./tests/unit/api/handlers -coverpkg=./api/handlers/http
go tool cover -html=coverage-handlers.out -o coverage-handlers.html
```

#### API Service Layer Only
```bash
go test -coverprofile=coverage-api-service.out ./tests/unit/api/service -coverpkg=./api/service
go tool cover -html=coverage-api-service.out -o coverage-api-service.html
```

#### Internal Service Layer Only
```bash
go test -coverprofile=coverage-internal.out ./tests/unit/internal/asset -coverpkg=./internal/asset
go tool cover -html=coverage-internal.out -o coverage-internal.html
```

#### Storage Layer Only
```bash
go test -coverprofile=coverage-storage.out ./tests/unit/pkg/adapter/storage -coverpkg=./pkg/adapter/storage
go tool cover -html=coverage-storage.out -o coverage-storage.html
```

## Coverage Analysis Commands

### View Coverage Summary
```bash
go tool cover -func=coverage.out
```

### View Coverage by Package
```bash
go tool cover -func=coverage.out | grep -E "(api/handlers|api/service|internal/asset|pkg/adapter)"
```

### Generate Coverage Report with Detailed Output
```bash
go test -v -coverprofile=coverage.out -covermode=count ./tests/unit/api/handlers ./tests/unit/api/service ./tests/unit/internal/asset ./tests/unit/pkg/adapter/storage -coverpkg=./api/handlers/http,./api/service,./internal/asset,./pkg/adapter/storage
```

## Coverage Files Generated
- `coverage.out` - Coverage profile data
- `coverage.html` - HTML visual coverage report
- `coverage-*.out` - Individual layer coverage profiles (if generated)
- `coverage-*.html` - Individual layer HTML reports (if generated)
