package service

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/switch/domain"
	switchPort "gitlab.apk-group.net/siem/backend/asset-discovery/internal/switch/port"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/logger"
)

var (
	ErrSwitchNotFound     = errors.New("switch not found")
	ErrInvalidSwitchInput = errors.New("invalid switch input")
)

// SwitchService provides API operations for switches
type SwitchService struct {
	service switchPort.Service
}

// NewSwitchService creates a new SwitchService
func NewSwitchService(srv switchPort.Service) *SwitchService {
	return &SwitchService{
		service: srv,
	}
}

// GetSwitchByID retrieves detailed information for a specific switch
func (s *SwitchService) GetSwitchByID(ctx context.Context, switchID uuid.UUID) (*domain.SwitchDetailResponse, error) {
	logger.InfoContext(ctx, "API switch service: Getting switch by ID: %s", switchID.String())

	// Call internal service to get switch
	switchInfo, err := s.service.GetSwitchByID(ctx, switchID)
	if err != nil {
		logger.ErrorContext(ctx, "API switch service: Failed to get switch: %v", err)
		return &domain.SwitchDetailResponse{
			Success: false,
			Error:   err.Error(),
		}, err
	}

	if switchInfo == nil {
		logger.WarnContext(ctx, "API switch service: Switch not found with ID: %s", switchID.String())
		return &domain.SwitchDetailResponse{
			Success: false,
			Error:   "Switch not found",
		}, ErrSwitchNotFound
	}

	logger.InfoContext(ctx, "API switch service: Successfully retrieved switch with ID: %s", switchID.String())
	return &domain.SwitchDetailResponse{
		Switch:  *switchInfo,
		Success: true,
	}, nil
}

// GetSwitchByScannerID retrieves detailed information for a switch by scanner ID
func (s *SwitchService) GetSwitchByScannerID(ctx context.Context, scannerID int64) (*domain.SwitchDetailResponse, error) {
	logger.InfoContext(ctx, "API switch service: Getting switch by scanner ID: %d", scannerID)

	// Call internal service to get switch
	switchInfo, err := s.service.GetSwitchByScannerID(ctx, scannerID)
	if err != nil {
		logger.ErrorContext(ctx, "API switch service: Failed to get switch: %v", err)
		return &domain.SwitchDetailResponse{
			Success: false,
			Error:   err.Error(),
		}, err
	}

	if switchInfo == nil {
		logger.WarnContext(ctx, "API switch service: Switch not found for scanner ID: %d", scannerID)
		return &domain.SwitchDetailResponse{
			Success: false,
			Error:   "Switch not found",
		}, ErrSwitchNotFound
	}

	logger.InfoContext(ctx, "API switch service: Successfully retrieved switch for scanner ID: %d", scannerID)
	return &domain.SwitchDetailResponse{
		Switch:  *switchInfo,
		Success: true,
	}, nil
}

// ListSwitches retrieves a list of switches with optional filtering and pagination
func (s *SwitchService) ListSwitches(ctx context.Context, req domain.SwitchListRequest) (*domain.SwitchListResponse, error) {
	logger.InfoContextWithFields(ctx, "API switch service: Listing switches", map[string]interface{}{
		"limit": req.Limit,
		"page":  req.Page,
		"sort":  req.Sort,
		"order": req.Order,
	})

	// Call internal service to list switches
	response, err := s.service.ListSwitches(ctx, req)
	if err != nil {
		logger.ErrorContext(ctx, "API switch service: Failed to list switches: %v", err)
		return &domain.SwitchListResponse{
			Success: false,
		}, err
	}

	logger.InfoContextWithFields(ctx, "API switch service: Successfully listed switches", map[string]interface{}{
		"returned_count": len(response.Switches),
		"total_count":    response.Count,
	})

	return response, nil
}

// GetSwitchStats retrieves basic statistics about switches
func (s *SwitchService) GetSwitchStats(ctx context.Context) (map[string]interface{}, error) {
	logger.InfoContext(ctx, "API switch service: Getting switch statistics")

	// Call internal service to get switch stats
	stats, err := s.service.GetSwitchStats(ctx)
	if err != nil {
		logger.ErrorContext(ctx, "API switch service: Failed to get switch stats: %v", err)
		return nil, err
	}

	logger.InfoContext(ctx, "API switch service: Successfully retrieved switch statistics")
	return stats, nil
}
