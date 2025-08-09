package port

import (
	"context"

	"github.com/google/uuid"
	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/switch/domain"
)

// Service defines the interface for switch operations
type Service interface {
	// GetSwitchByID retrieves detailed information for a specific switch
	GetSwitchByID(ctx context.Context, switchID uuid.UUID) (*domain.SwitchInfo, error)

	// GetSwitchByScannerID retrieves detailed information for a switch by scanner ID
	GetSwitchByScannerID(ctx context.Context, scannerID int64) (*domain.SwitchInfo, error)

	// ListSwitches retrieves a list of switches with optional filtering and pagination
	ListSwitches(ctx context.Context, req domain.SwitchListRequest) (*domain.SwitchListResponse, error)

	// GetSwitchStats retrieves basic statistics about switches
	GetSwitchStats(ctx context.Context) (map[string]interface{}, error)
}

// Repository defines the interface for switch data persistence
type Repository interface {
	// GetSwitchByAssetID retrieves switch info by asset ID
	GetSwitchByAssetID(ctx context.Context, assetID uuid.UUID) (*domain.SwitchInfo, error)

	// GetSwitchByScannerID retrieves switch info by scanner ID
	GetSwitchByScannerID(ctx context.Context, scannerID int64) (*domain.SwitchInfo, error)

	// ListSwitches retrieves switches with filtering and pagination
	ListSwitches(ctx context.Context, filter domain.SwitchFilter, limit, offset int, sortField, sortOrder string) ([]domain.SwitchInfo, int, error)

	// GetSwitchStats retrieves aggregated switch statistics
	GetSwitchStats(ctx context.Context) (map[string]interface{}, error)
}
