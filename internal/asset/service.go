package asset

import (
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/domain"
	assetPort "gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/port"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/logger"
)

var (
	ErrAssetNotFound         = errors.New("asset not found")
	ErrInvalidAssetUUID      = errors.New("invalid asset UUID")
	ErrAssetCreateFailed     = errors.New("failed to create asset")
	ErrAssetUpdateFailed     = errors.New("failed to update asset")
	ErrAssetDeleteFailed     = errors.New("failed to delete asset")
	ErrExportFailed          = errors.New("failed to export assets")
	ErrOSNamesFailed         = errors.New("failed to get OS names")
	ErrIPAlreadyExists       = domain.ErrIPAlreadyExists
	ErrHostnameAlreadyExists = domain.ErrHostnameAlreadyExists
)

type service struct {
	repo assetPort.Repo
}

func NewAssetService(repo assetPort.Repo) assetPort.Service {
	return &service{
		repo: repo,
	}
}

func (s *service) CreateAsset(ctx context.Context, asset domain.AssetDomain, scannerType ...string) (domain.AssetUUID, error) {
	logger.InfoContextWithFields(ctx, "Internal service: Creating asset", map[string]interface{}{
		"asset_id":   asset.ID.String(),
		"asset_name": asset.Name,
		"hostname":   asset.Hostname,
		"ip_count":   len(asset.AssetIPs),
		"port_count": len(asset.Ports),
	})

	logger.DebugContext(ctx, "Internal service: Calling repository to create asset")
	assetID, err := s.repo.Create(ctx, asset)
	if err != nil {
		if errors.Is(err, domain.ErrIPAlreadyExists) {
			logger.WarnContext(ctx, "Internal service: Asset creation failed - IP already exists for asset %s", asset.Name)
			return uuid.Nil, err
		}
		if errors.Is(err, domain.ErrHostnameAlreadyExists) {
			logger.WarnContext(ctx, "Internal service: Asset creation failed - Hostname already exists for asset %s", asset.Name)
			return uuid.Nil, err
		}
		logger.ErrorContext(ctx, "Internal service: Asset creation failed for asset %s: %v", asset.Name, err)
		return uuid.Nil, ErrAssetCreateFailed
	}

	logger.InfoContext(ctx, "Internal service: Successfully created asset with ID: %s", assetID.String())
	return assetID, nil
}

func (s *service) GetByID(ctx context.Context, assetUUID domain.AssetUUID) (*domain.AssetDomain, error) {
	logger.InfoContext(ctx, "Internal service: Getting asset by ID: %s", assetUUID.String())

	var assetUUIDs []domain.AssetUUID
	assetUUIDs = append(assetUUIDs, assetUUID)

	logger.DebugContext(ctx, "Internal service: Calling repository to get asset by ID")
	assets, err := s.repo.GetByIDs(ctx, assetUUIDs)
	if err != nil {
		logger.ErrorContext(ctx, "Internal service: Failed to get asset by ID %s: %v", assetUUID.String(), err)
		return nil, err
	}

	if assets == nil {
		logger.InfoContext(ctx, "Internal service: Asset not found with ID: %s", assetUUID.String())
		return nil, ErrAssetNotFound
	}

	if len(assets) == 0 {
		logger.InfoContext(ctx, "Internal service: Asset not found with ID: %s (empty result)", assetUUID.String())
		return nil, ErrAssetNotFound
	}

	logger.DebugContext(ctx, "Internal service: Successfully retrieved asset with ID: %s", assetUUID.String())
	return &assets[0], nil
}

func (s *service) GetByIDs(ctx context.Context, assetUUIDs []domain.AssetUUID) ([]domain.AssetDomain, error) {
	logger.InfoContext(ctx, "Internal service: Getting assets by IDs (count: %d)", len(assetUUIDs))

	logger.DebugContext(ctx, "Internal service: Calling repository to get assets by IDs")
	assets, err := s.repo.GetByIDs(ctx, assetUUIDs)
	if err != nil {
		logger.ErrorContext(ctx, "Internal service: Failed to get assets by IDs: %v", err)
		return nil, err
	}

	logger.DebugContext(ctx, "Internal service: Successfully retrieved %d assets", len(assets))
	return assets, nil
}

func (s *service) GetByIDsWithSort(ctx context.Context, assetUUIDs []domain.AssetUUID, sortOptions ...domain.SortOption) ([]domain.AssetDomain, error) {
	logger.InfoContext(ctx, "Internal service: Getting assets by IDs with sort (count: %d, sort options: %d)", len(assetUUIDs), len(sortOptions))

	logger.DebugContext(ctx, "Internal service: Calling repository to get assets by IDs with sort")
	assets, err := s.repo.GetByIDsWithSort(ctx, assetUUIDs, sortOptions...)
	if err != nil {
		logger.ErrorContext(ctx, "Internal service: Failed to get assets by IDs with sort: %v", err)
		return nil, err
	}

	logger.DebugContext(ctx, "Internal service: Successfully retrieved %d assets with sort", len(assets))
	return assets, nil
}

func (s *service) Get(ctx context.Context, assetFilter domain.AssetFilters, limit, offset int, sortOptions ...domain.SortOption) ([]domain.AssetDomain, int, error) {
	logger.InfoContextWithFields(ctx, "Internal service: Getting assets with filters", map[string]interface{}{
		"limit":               limit,
		"offset":              offset,
		"sort_count":          len(sortOptions),
		"has_name_filter":     assetFilter.Name != "",
		"has_ip_filter":       assetFilter.IP != "",
		"has_hostname_filter": assetFilter.Hostname != "",
	})

	logger.DebugContext(ctx, "Internal service: Calling repository to get assets by filter")
	assets, total, err := s.repo.GetByFilter(ctx, assetFilter, limit, offset, sortOptions...)
	if err != nil {
		logger.ErrorContext(ctx, "Internal service: Failed to get assets with filters: %v", err)
		return nil, 0, err
	}

	logger.InfoContextWithFields(ctx, "Internal service: Successfully retrieved assets", map[string]interface{}{
		"returned_count": len(assets),
		"total_count":    total,
	})

	return assets, total, nil
}

func (s *service) UpdateAsset(ctx context.Context, asset domain.AssetDomain) error {
	logger.InfoContextWithFields(ctx, "Internal service: Updating asset", map[string]interface{}{
		"asset_id":   asset.ID.String(),
		"asset_name": asset.Name,
		"hostname":   asset.Hostname,
		"ip_count":   len(asset.AssetIPs),
		"port_count": len(asset.Ports),
	})

	logger.DebugContext(ctx, "Internal service: Calling repository to update asset")
	err := s.repo.Update(ctx, asset)
	if err != nil {
		if errors.Is(err, domain.ErrIPAlreadyExists) {
			logger.WarnContext(ctx, "Internal service: Asset update failed - IP already exists for asset %s", asset.ID.String())
			return err
		}
		logger.ErrorContext(ctx, "Internal service: Asset update failed for asset %s: %v", asset.ID.String(), err)
		return ErrAssetUpdateFailed
	}

	logger.InfoContext(ctx, "Internal service: Successfully updated asset with ID: %s", asset.ID.String())
	return nil
}

// DeleteAssets handles all asset deletion scenarios based on the provided parameters
func (s *service) DeleteAssets(ctx context.Context, ids []string, filter *domain.AssetFilters, exclude bool) error {
	logger.InfoContextWithFields(ctx, "Internal service: Deleting assets", map[string]interface{}{
		"id_count":   len(ids),
		"has_filter": filter != nil,
		"exclude":    exclude,
	})

	// Single Id case:
	if len(ids) == 1 && ids[0] != "All" && !exclude {
		logger.DebugContext(ctx, "Internal service: Deleting single asset with ID: %s", ids[0])
		assetUUID, err := uuid.Parse(ids[0])
		if err != nil {
			logger.WarnContext(ctx, "Internal service: Invalid asset UUID provided for deletion: %s", ids[0])
			return ErrInvalidAssetUUID
		}

		affected_rows, err := s.repo.DeleteAssets(ctx, domain.NewDeleteParamsWithUUID(assetUUID))
		return checkDeletedAssetsErrors(affected_rows, err)
	} else if len(ids) == 1 && ids[0] == "All" {
		logger.DebugContext(ctx, "Internal service: Deleting all assets (All specified)")
		// Special case: "All" in IDs list
		// If "All" is specified with filters, use the filters to delete specific assets
		if filter != nil {
			logger.DebugContext(ctx, "Internal service: Deleting all assets matching filter criteria")
			affected_rows, err := s.repo.DeleteAssets(ctx, domain.NewDeleteParamsWithFilters(*filter))
			return checkDeletedAssetsErrors(affected_rows, err)
		}

		// Delete all assets without filters
		logger.DebugContext(ctx, "Internal service: Deleting all assets without filters")
		affected_rows, err := s.repo.DeleteAssets(ctx, domain.NewDeleteParamsForAll())
		return checkDeletedAssetsErrors(affected_rows, err)
	}

	// Convert string IDs to UUIDs
	assetUUIDs := make([]domain.AssetUUID, 0, len(ids))
	for _, id := range ids {
		assetUUID, err := uuid.Parse(id)
		if err != nil {
			logger.WarnContext(ctx, "Internal service: Invalid asset UUID provided for deletion: %s", id)
			return ErrInvalidAssetUUID
		}
		assetUUIDs = append(assetUUIDs, assetUUID)
	}

	logger.DebugContext(ctx, "Internal service: Parsed %d valid asset UUIDs for deletion", len(assetUUIDs))

	// Case with both filters and IDs
	if filter != nil {
		if exclude {
			logger.DebugContext(ctx, "Internal service: Deleting assets matching filter excluding specified IDs")
			// Delete assets matching filter except those with the specified IDs
			affected_rows, err := s.repo.DeleteAssets(ctx, domain.NewDeleteParamsWithFiltersExclude(*filter, assetUUIDs))
			return checkDeletedAssetsErrors(affected_rows, err)
		}

		logger.DebugContext(ctx, "Internal service: Deleting assets matching both IDs and filter criteria")
		// Delete assets that match both specific IDs and filter criteria
		affected_rows, err := s.repo.DeleteAssets(ctx, domain.NewDeleteParamsWithUUIDsAndFilters(assetUUIDs, *filter))
		return checkDeletedAssetsErrors(affected_rows, err)
	}

	// Simple case: either include or exclude specific IDs
	if exclude {
		if len(assetUUIDs) == 0 {
			logger.DebugContext(ctx, "Internal service: Deleting all assets (exclude with empty IDs)")
			affected_rows, err := s.repo.DeleteAssets(ctx, domain.NewDeleteParamsForAll())
			return checkDeletedAssetsErrors(affected_rows, err)
		}

		logger.DebugContext(ctx, "Internal service: Deleting all assets excluding specified IDs")
		affected_rows, err := s.repo.DeleteAssets(ctx, domain.NewDeleteParamsWithUUIDsExclude(assetUUIDs))
		return checkDeletedAssetsErrors(affected_rows, err)
	}

	if len(assetUUIDs) == 0 {
		logger.DebugContext(ctx, "Internal service: No assets to delete (empty UUIDs list)")
		return nil
	}

	logger.DebugContext(ctx, "Internal service: Deleting specified assets by IDs")
	affected_rows, err := s.repo.DeleteAssets(ctx, domain.NewDeleteParamsWithUUIDs(assetUUIDs))
	return checkDeletedAssetsErrors(affected_rows, err)
}

// ExportAssets exports assets based on asset IDs and export type
func (s *service) ExportAssets(ctx context.Context, assetIDs []domain.AssetUUID, exportType domain.ExportType, selectedColumns []string) (*domain.ExportData, error) {
	logger.InfoContextWithFields(ctx, "Internal service: Exporting assets", map[string]interface{}{
		"asset_count":            len(assetIDs),
		"export_type":            exportType,
		"selected_columns_count": len(selectedColumns),
	})

	logger.DebugContext(ctx, "Internal service: Calling repository to export assets")
	exportData, err := s.repo.ExportAssets(ctx, assetIDs, exportType, selectedColumns)
	if err != nil {
		logger.ErrorContext(ctx, "Internal service: Failed to export assets: %v", err)
		return nil, ErrExportFailed
	}

	logger.DebugContextWithFields(ctx, "Internal service: Successfully exported assets", map[string]interface{}{
		"assets_count":     len(exportData.Assets),
		"asset_ips_count":  len(exportData.AssetIPs),
		"vmware_vms_count": len(exportData.VMwareVMs),
	})

	return exportData, nil
}

// GenerateCSV generates a CSV file from export data
func (s *service) GenerateCSV(ctx context.Context, exportData *domain.ExportData) ([]byte, error) {
	logger.InfoContext(ctx, "Internal service: Generating CSV from export data")

	var sb strings.Builder
	writer := csv.NewWriter(&sb)

	// Validate the export data
	if exportData == nil {
		logger.ErrorContext(ctx, "Internal service: Export data is nil")
		return nil, fmt.Errorf("export data is nil")
	}

	logger.DebugContextWithFields(ctx, "Internal service: Processing export data for CSV", map[string]interface{}{
		"assets_count":     len(exportData.Assets),
		"asset_ips_count":  len(exportData.AssetIPs),
		"vmware_vms_count": len(exportData.VMwareVMs),
	})

	// used for diff exports
	hasStatusField := false
	if len(exportData.Assets) > 0 {
		_, hasStatusField = exportData.Assets[0]["status"]
	}

	var headers []string
	if hasStatusField {
		headers = append(headers, "status")
	}

	// Collect headers from all assets
	assetHeaders := make([]string, 0)
	if len(exportData.Assets) > 0 {
		for key := range exportData.Assets[0] {
			if key != "status" || !hasStatusField {
				assetHeaders = append(assetHeaders, key)
			}
		}
	}

	// Collect headers from AssetIPs
	ipHeaders := make([]string, 0)
	if len(exportData.AssetIPs) > 0 {
		for key := range exportData.AssetIPs[0] {
			if key != "asset_id" {
				ipHeaders = append(ipHeaders, key)
			}
		}
	}

	// Collect headers from VMwareVMs
	vmHeaders := make([]string, 0)
	if len(exportData.VMwareVMs) > 0 {
		for key := range exportData.VMwareVMs[0] {
			if key != "asset_id" {
				vmHeaders = append(vmHeaders, key)
			}
		}
	}

	headers = append(headers, assetHeaders...)
	headers = append(headers, ipHeaders...)
	headers = append(headers, vmHeaders...)

	// Write headers
	if err := writer.Write(headers); err != nil {
		logger.ErrorContext(ctx, "Internal service: Failed to write CSV headers: %v", err)
		return nil, ErrExportFailed
	}

	logger.DebugContext(ctx, "Internal service: CSV headers written successfully (count: %d)", len(headers))

	// Create a map to store assets by their ID
	assetByID := make(map[string]map[string]interface{})

	// Group IPs by asset ID for lookup
	ipsByAssetID := make(map[string][]map[string]interface{})
	for _, ip := range exportData.AssetIPs {
		assetID := fmt.Sprint(ip["asset_id"])
		ipsByAssetID[assetID] = append(ipsByAssetID[assetID], ip)
	}

	// Group VMwareVMs by asset ID for lookup
	vmsByAssetID := make(map[string][]map[string]interface{})
	for _, vm := range exportData.VMwareVMs {
		assetID := fmt.Sprint(vm["asset_id"])
		vmsByAssetID[assetID] = append(vmsByAssetID[assetID], vm)
	}

	// Get all unique asset IDs from all data sources
	allAssetIDs := make(map[string]bool)

	for _, ip := range exportData.AssetIPs {
		assetID := fmt.Sprint(ip["asset_id"])
		allAssetIDs[assetID] = true
	}

	for _, vm := range exportData.VMwareVMs {
		assetID := fmt.Sprint(vm["asset_id"])
		allAssetIDs[assetID] = true
	}

	// Create a map of assets by their ID from the asset list
	for _, asset := range exportData.Assets {
		if id, ok := asset["id"]; ok {
			assetID := fmt.Sprint(id)
			assetByID[assetID] = asset
			allAssetIDs[assetID] = true
		}
	}

	// Process each asset ID to create CSV rows
	for assetID := range allAssetIDs {
		ips := ipsByAssetID[assetID]
		vms := vmsByAssetID[assetID]
		asset := assetByID[assetID]

		if asset == nil {
			asset = make(map[string]interface{})
			asset["id"] = assetID
		}

		// If there are both IPs and VMs for this asset
		if len(ips) > 0 && len(vms) > 0 {
			// For each IP and VM combination, create a row
			for _, ip := range ips {
				for _, vm := range vms {
					row := make([]string, len(headers))

					row = fillRowFromAsset(row, headers, asset)

					row = fillRowFromSource(row, headers, ip)
					row = fillRowFromSource(row, headers, vm)

					if err := writer.Write(row); err != nil {
						return nil, ErrExportFailed
					}
				}
			}
		} else if len(ips) > 0 {
			// Only IPs, no VMs
			for _, ip := range ips {
				row := make([]string, len(headers))

				row = fillRowFromAsset(row, headers, asset)

				row = fillRowFromSource(row, headers, ip)

				if err := writer.Write(row); err != nil {
					return nil, ErrExportFailed
				}
			}
		} else if len(vms) > 0 {
			// Only VMs, no IPs
			for _, vm := range vms {
				row := make([]string, len(headers))

				row = fillRowFromAsset(row, headers, asset)

				row = fillRowFromSource(row, headers, vm)

				if err := writer.Write(row); err != nil {
					return nil, ErrExportFailed
				}
			}
		} else {
			// No IPs or VMs, just the asset
			row := make([]string, len(headers))
			row = fillRowFromAsset(row, headers, asset)

			if err := writer.Write(row); err != nil {
				return nil, ErrExportFailed
			}
		}
	}

	for _, asset := range exportData.Assets {
		var assetID string
		if id, ok := asset["id"]; ok {
			assetID = fmt.Sprint(id)
			if allAssetIDs[assetID] {
				continue
			}
		}

		row := make([]string, len(headers))
		row = fillRowFromAsset(row, headers, asset)

		if err := writer.Write(row); err != nil {
			return nil, ErrExportFailed
		}
	}

	writer.Flush()
	if err := writer.Error(); err != nil {
		logger.ErrorContext(ctx, "Internal service: CSV writer error: %v", err)
		return nil, ErrExportFailed
	}

	csvData := []byte(sb.String())
	logger.InfoContextWithFields(ctx, "Internal service: Successfully generated CSV", map[string]interface{}{
		"csv_size":       len(csvData),
		"rows_processed": len(allAssetIDs),
	})

	return csvData, nil
}

// fillRowFromAsset fills a row with data from an asset map
func fillRowFromAsset(row []string, headers []string, asset map[string]interface{}) []string {
	for i, header := range headers {
		if val, ok := asset[header]; ok {
			row[i] = toString(val)
		}
	}
	return row
}

// fillRowFromSource fills a row with data from a source map
func fillRowFromSource(row []string, headers []string, source map[string]interface{}) []string {
	for i, header := range headers {
		if val, ok := source[header]; ok {
			row[i] = toString(val)
		}
	}
	return row
}

// toString converts an interface to a string
func toString(v interface{}) string {
	if v == nil {
		return ""
	}
	return strings.TrimSpace(strings.Replace(fmt.Sprint(v), "\n", " ", -1))
}

// GetDistinctOSNames returns a list of distinct OS names from all assets
func (s *service) GetDistinctOSNames(ctx context.Context) ([]string, error) {
	logger.InfoContext(ctx, "Internal service: Getting distinct OS names")

	logger.DebugContext(ctx, "Internal service: Calling repository to get distinct OS names")
	osNames, err := s.repo.GetDistinctOSNames(ctx)
	if err != nil {
		logger.ErrorContext(ctx, "Internal service: Failed to get distinct OS names: %v", err)
		return nil, ErrOSNamesFailed
	}

	logger.InfoContext(ctx, "Internal service: Successfully retrieved %d distinct OS names", len(osNames))
	return osNames, nil
}

// Dashboard methods implementation

// GetDashboardAssetCount returns asset count statistics for dashboard
func (s *service) GetDashboardAssetCount(ctx context.Context) (*domain.AssetCountData, error) {
	logger.InfoContext(ctx, "Internal service: Getting dashboard asset count")

	count, err := s.repo.GetAssetCount(ctx)
	if err != nil {
		logger.ErrorContext(ctx, "Internal service: Failed to get asset count: %v", err)
		return nil, err
	}

	// TODO: For now, consider all assets as offline
	// This can be updated later when the online/offline feature is implemented
	data := &domain.AssetCountData{
		Count: count,
		Contents: []domain.AssetStatusCount{
			{
				Source:  "offline",
				Percent: 100,
			},
			{
				Source:  "online",
				Percent: 0,
			},
		},
	}

	logger.InfoContext(ctx, "Internal service: Successfully retrieved dashboard asset count: %d", count)
	return data, nil
}

// GetDashboardAssetPerScanner returns asset counts grouped by scanner type
func (s *service) GetDashboardAssetPerScanner(ctx context.Context) (*domain.AssetPerScannerData, error) {
	logger.InfoContext(ctx, "Internal service: Getting dashboard asset per scanner")

	scannerCounts, err := s.repo.GetAssetCountByScanner(ctx)
	if err != nil {
		logger.ErrorContext(ctx, "Internal service: Failed to get asset count by scanner: %v", err)
		return nil, err
	}

	data := &domain.AssetPerScannerData{
		Contents: scannerCounts,
	}

	logger.InfoContext(ctx, "Internal service: Successfully retrieved dashboard asset per scanner with %d scanner types", len(scannerCounts))
	return data, nil
}

// GetDashboardLoggingCompleted returns logging completion statistics by OS type
func (s *service) GetDashboardLoggingCompleted(ctx context.Context) (*domain.LoggingCompletedData, error) {
	logger.InfoContext(ctx, "Internal service: Getting dashboard logging completed by OS")

	osStats, err := s.repo.GetLoggingCompletedByOS(ctx)
	if err != nil {
		logger.ErrorContext(ctx, "Internal service: Failed to get logging completed by OS: %v", err)
		return nil, err
	}

	data := &domain.LoggingCompletedData{
		Contents: osStats,
	}

	logger.InfoContext(ctx, "Internal service: Successfully retrieved dashboard logging completed with %d OS types", len(osStats))
	return data, nil
}

// GetDashboardAssetsPerSource returns asset statistics grouped by source for the dashboard
func (s *service) GetDashboardAssetsPerSource(ctx context.Context) (*domain.AssetsPerSourceData, error) {
	logger.InfoContext(ctx, "Internal service: Getting dashboard assets per source")

	sourceStats, totalCount, err := s.repo.GetAssetsPerSource(ctx)
	if err != nil {
		logger.ErrorContext(ctx, "Internal service: Failed to get assets per source: %v", err)
		return nil, err
	}

	data := &domain.AssetsPerSourceData{
		Contents: sourceStats,
		Count:    totalCount,
	}

	logger.InfoContext(ctx, "Internal service: Successfully retrieved dashboard assets per source with %d sources, total: %d", len(sourceStats), totalCount)
	return data, nil
}

func checkDeletedAssetsErrors(affected_rows int, err error) error {
	if err != nil {
		logger.Error("Internal service: Error deleting assets: %v", err)
		return ErrAssetDeleteFailed
	}

	logger.Info("Internal service: Successfully deleted %d assets", affected_rows)
	if affected_rows == 0 {
		return ErrAssetNotFound
	}

	return nil
}
