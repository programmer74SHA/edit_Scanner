package switch_scanner

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	scannerDomain "gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanner/domain"
	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/switch/domain"
	switchPort "gitlab.apk-group.net/siem/backend/asset-discovery/internal/switch/port"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/logger"
)

// switchService implements the switch service interface
type switchService struct {
	repo       switchPort.Repository
	switchRepo SwitchDataRepository // Interface for switch data operations
}

// SwitchDataRepository defines operations for switch data (to avoid circular imports)
type SwitchDataRepository interface {
	GetSwitchByAssetID(ctx context.Context, assetID uuid.UUID) (*domain.SwitchInfo, error)
	GetSwitchByScannerID(ctx context.Context, scannerID int64) (*domain.SwitchInfo, error)
	ListSwitches(ctx context.Context, filter domain.SwitchFilter, limit, offset int, sortField, sortOrder string) ([]domain.SwitchInfo, int, error)
	GetSwitchStats(ctx context.Context) (map[string]interface{}, error)

	// Methods for detailed data
	GetSwitchDataByAssetID(ctx context.Context, assetID uuid.UUID) (*scannerDomain.SwitchData, error)
}

// NewSwitchService creates a new switch service
func NewSwitchService(repo switchPort.Repository, switchRepo SwitchDataRepository) switchPort.Service {
	return &switchService{
		repo:       repo,
		switchRepo: switchRepo,
	}
}

// GetSwitchByID retrieves detailed information for a specific switch
func (s *switchService) GetSwitchByID(ctx context.Context, switchID uuid.UUID) (*domain.SwitchInfo, error) {
	logger.InfoContext(ctx, "[SwitchService] Getting switch by ID: %s", switchID.String())

	// Get basic switch info
	switchInfo, err := s.switchRepo.GetSwitchByAssetID(ctx, switchID)
	if err != nil {
		logger.InfoContext(ctx, "[SwitchService] Error getting switch info: %v", err)
		return nil, fmt.Errorf("failed to get switch info: %w", err)
	}

	if switchInfo == nil {
		logger.InfoContext(ctx, "[SwitchService] Switch not found: %s", switchID.String())
		return nil, nil
	}

	// Get detailed switch data (interfaces, VLANs, neighbors)
	switchData, err := s.switchRepo.GetSwitchDataByAssetID(ctx, switchID)
	if err != nil {
		logger.InfoContext(ctx, "[SwitchService] Warning: Could not get detailed switch data: %v", err)
		// Don't fail the request, just return basic info
	} else if switchData != nil {
		// Add detailed data to response
		switchInfo.Interfaces = switchData.Interfaces
		switchInfo.VLANs = switchData.VLANs
		switchInfo.Neighbors = switchData.Neighbors

		// Update counts with actual data
		switchInfo.NumberOfPorts = len(switchData.Interfaces)
		switchInfo.NumberOfVLANs = len(switchData.VLANs)
		switchInfo.NumberOfNeighbors = len(switchData.Neighbors)
	}

	logger.InfoContext(ctx, "[SwitchService] Successfully retrieved switch %s with %d interfaces, %d VLANs, %d neighbors",
		switchID.String(), switchInfo.NumberOfPorts, switchInfo.NumberOfVLANs, switchInfo.NumberOfNeighbors)

	return switchInfo, nil
}

// GetSwitchByScannerID retrieves detailed information for a switch by scanner ID
func (s *switchService) GetSwitchByScannerID(ctx context.Context, scannerID int64) (*domain.SwitchInfo, error) {
	logger.InfoContext(ctx, "[SwitchService] Getting switch by scanner ID: %d", scannerID)

	// Get basic switch info
	switchInfo, err := s.switchRepo.GetSwitchByScannerID(ctx, scannerID)
	if err != nil {
		logger.InfoContext(ctx, "[SwitchService] Error getting switch info: %v", err)
		return nil, fmt.Errorf("failed to get switch info: %w", err)
	}

	if switchInfo == nil {
		logger.InfoContext(ctx, "[SwitchService] Switch not found for scanner: %d", scannerID)
		return nil, nil
	}

	// Parse asset ID to get detailed data
	assetID, err := uuid.Parse(switchInfo.ID)
	if err != nil {
		logger.InfoContext(ctx, "[SwitchService] Invalid asset ID format: %s", switchInfo.ID)
		return switchInfo, nil // Return basic info without detailed data
	}

	// Get detailed switch data
	switchData, err := s.switchRepo.GetSwitchDataByAssetID(ctx, assetID)
	if err != nil {
		logger.InfoContext(ctx, "[SwitchService] Warning: Could not get detailed switch data: %v", err)
	} else if switchData != nil {
		// Add detailed data to response
		switchInfo.Interfaces = switchData.Interfaces
		switchInfo.VLANs = switchData.VLANs
		switchInfo.Neighbors = switchData.Neighbors

		// Update counts with actual data
		switchInfo.NumberOfPorts = len(switchData.Interfaces)
		switchInfo.NumberOfVLANs = len(switchData.VLANs)
		switchInfo.NumberOfNeighbors = len(switchData.Neighbors)
	}

	logger.InfoContext(ctx, "[SwitchService] Successfully retrieved switch for scanner %d", scannerID)
	return switchInfo, nil
}

// ListSwitches retrieves a list of switches with optional filtering and pagination
func (s *switchService) ListSwitches(ctx context.Context, req domain.SwitchListRequest) (*domain.SwitchListResponse, error) {
	logger.InfoContext(ctx, "[SwitchService] Listing switches with request: %+v", req)

	// Set default pagination
	limit := req.Limit
	if limit <= 0 {
		limit = 50 // Default limit
	}
	if limit > 1000 {
		limit = 1000 // Max limit
	}

	page := req.Page
	if page < 0 {
		page = 0
	}

	offset := page * limit

	// Set default sorting
	sortField := req.Sort
	if sortField == "" {
		sortField = "name"
	}

	sortOrder := req.Order
	if sortOrder == "" {
		sortOrder = "asc"
	}

	// Validate sort order
	if sortOrder != "asc" && sortOrder != "desc" {
		sortOrder = "asc"
	}

	// Get switches from repository
	switches, total, err := s.switchRepo.ListSwitches(ctx, req.Filter, limit, offset, sortField, sortOrder)
	if err != nil {
		logger.InfoContext(ctx, "[SwitchService] Error listing switches: %v", err)
		return nil, fmt.Errorf("failed to list switches: %w", err)
	}

	response := &domain.SwitchListResponse{
		Switches: switches,
		Count:    total,
		Success:  true,
	}

	logger.InfoContext(ctx, "[SwitchService] Successfully listed %d switches (total: %d)", len(switches), total)
	return response, nil
}

// GetSwitchStats retrieves basic statistics about switches
func (s *switchService) GetSwitchStats(ctx context.Context) (map[string]interface{}, error) {
	logger.InfoContext(ctx, "[SwitchService] Getting switch statistics")

	stats, err := s.switchRepo.GetSwitchStats(ctx)
	if err != nil {
		logger.InfoContext(ctx, "[SwitchService] Error getting switch stats: %v", err)
		return nil, fmt.Errorf("failed to get switch statistics: %w", err)
	}

	logger.InfoContext(ctx, "[SwitchService] Successfully retrieved switch statistics")
	return stats, nil
}
