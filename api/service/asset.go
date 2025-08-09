package service

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"gitlab.apk-group.net/siem/backend/asset-discovery/api/pb"
	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset"
	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/domain"
	assetPort "gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/port"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/logger"
)

var (
	ErrAssetNotFound         = asset.ErrAssetNotFound
	ErrInvalidAssetUUID      = asset.ErrInvalidAssetUUID
	ErrAssetCreateFailed     = asset.ErrAssetCreateFailed
	ErrAssetDeleteFailed     = asset.ErrAssetDeleteFailed
	ErrIPAlreadyExists       = asset.ErrIPAlreadyExists
	ErrHostnameAlreadyExists = asset.ErrHostnameAlreadyExists
)

type AssetService struct {
	service assetPort.Service
}

func NewAssetService(srv assetPort.Service) *AssetService {
	return &AssetService{
		service: srv,
	}
}

func (s *AssetService) GetAsset(ctx context.Context, req *pb.GetAssetByIDRequest) (*pb.GetAssetResponse, error) {
	logger.InfoContext(ctx, "API service: Getting asset by ID: %s", req.GetId())

	assetUUID, err := uuid.Parse(req.GetId())
	if err != nil {
		logger.WarnContext(ctx, "API service: Invalid asset UUID provided: %s", req.GetId())
		return nil, ErrInvalidAssetUUID
	}

	logger.DebugContext(ctx, "API service: Calling internal service to get asset by ID: %s", assetUUID.String())
	asset, err := s.service.GetByID(ctx, assetUUID)
	if err != nil {
		if errors.Is(err, ErrAssetNotFound) {
			logger.InfoContext(ctx, "API service: Asset not found with ID: %s", assetUUID.String())
			return &pb.GetAssetResponse{}, nil
		}
		logger.ErrorContext(ctx, "API service: Failed to get asset by ID %s: %v", assetUUID.String(), err)
		return nil, err
	}

	logger.InfoContext(ctx, "API service: Successfully retrieved asset with ID: %s", assetUUID.String())
	return &pb.GetAssetResponse{
		Asset: domainToPbAsset(*asset),
	}, nil
}

func (s *AssetService) GetAssets(ctx context.Context, req *pb.GetAssetsRequest) (*pb.GetAssetsResponse, error) {
	logger.InfoContextWithFields(ctx, "API service: Getting assets with filters", map[string]interface{}{
		"limit":      req.GetLimit(),
		"page":       req.GetPage(),
		"sort_count": len(req.GetSort()),
		"has_filter": req.GetFilter() != nil,
	})

	filter := domain.AssetFilters{
		Name:        req.GetFilter().GetName(),
		Domain:      req.GetFilter().GetDomain(),
		Hostname:    req.GetFilter().GetHostname(),
		OSName:      req.GetFilter().GetOsName(),
		OSVersion:   req.GetFilter().GetOsVersion(),
		Type:        req.GetFilter().GetType(),
		IP:          req.GetFilter().GetIp(),
		ScannerType: req.GetFilter().GetScannerType(),
		Network:     req.GetFilter().GetNetwork(),
	}

	limit := int(req.GetLimit())
	// Convert page to offset
	offset := int(req.GetPage()) * limit

	if limit < 0 {
		logger.WarnContext(ctx, "API service: Invalid limit provided: %d, setting to 0", limit)
		limit = 0
	}

	if offset < 0 {
		logger.WarnContext(ctx, "API service: Invalid offset calculated: %d, setting to 0", offset)
		offset = 0
	}

	// Extract sort options
	sortFields := make([]domain.SortOption, 0, len(req.GetSort()))
	for _, sort := range req.GetSort() {
		sortFields = append(sortFields, domain.SortOption{
			Field: sort.GetField(),
			Order: sort.GetOrder(),
		})
	}

	logger.DebugContextWithFields(ctx, "API service: Calling internal service with processed parameters", map[string]interface{}{
		"processed_limit":   limit,
		"processed_offset":  offset,
		"sort_fields_count": len(sortFields),
	})

	assets, total, err := s.service.Get(ctx, filter, limit, offset, sortFields...)
	if err != nil {
		logger.ErrorContext(ctx, "API service: Failed to get assets: %v", err)
		return nil, err
	}

	pbAssets := make([]*pb.Asset, 0, len(assets))
	for _, asset := range assets {
		pbAssets = append(pbAssets, domainToPbAsset(asset))
	}

	logger.InfoContextWithFields(ctx, "API service: Successfully retrieved assets", map[string]interface{}{
		"total_count":    total,
		"returned_count": len(pbAssets),
	})

	return &pb.GetAssetsResponse{
		Contents: pbAssets,
		Count:    int32(total),
	}, nil
}

// CreateAsset handles creation of a new asset
func (s *AssetService) CreateAsset(ctx context.Context, req *pb.CreateAssetRequest) (*pb.CreateAssetResponse, error) {
	logger.InfoContextWithFields(ctx, "API service: Creating new asset", map[string]interface{}{
		"asset_name": req.GetName(),
		"hostname":   req.GetHostname(),
		"ip_count":   len(req.GetPorts()),
		"port_count": len(req.GetPorts()),
	})

	id := uuid.New()
	now := time.Now()

	logger.DebugContext(ctx, "API service: Generated new asset ID: %s", id.String())

	// Prepare ports
	ports := make([]domain.Port, 0, len(req.GetPorts()))
	for _, p := range req.GetPorts() {
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

	// Prepare asset IPs
	ips := make([]domain.AssetIP, 0, len(req.GetAssetIps()))
	for _, ip := range req.GetAssetIps() {
		ips = append(ips, domain.AssetIP{
			ID:          uuid.New().String(),
			AssetID:     id.String(),
			InterfaceID: "", // Will be set when linked to interface
			IP:          ip.GetIp(),
			MACAddress:  ip.GetMacAddress(),
		})
	}

	assetDomain := domain.AssetDomain{
		ID:               id,
		Name:             req.GetName(),
		Domain:           req.GetDomain(),
		Hostname:         req.GetHostname(),
		OSName:           req.GetOsName(),
		OSVersion:        req.GetOsVersion(),
		Type:             req.GetType(),
		Description:      req.GetDescription(),
		DiscoveredBy:     "System User", // hardcoded
		Risk:             int(req.GetRisk()),
		LoggingCompleted: req.GetLoggingCompleted(),
		AssetValue:       int(req.GetAssetValue()),
		CreatedAt:        now,
		Ports:            ports,
		AssetIPs:         ips,
	}

	// Normalize and validate asset fields
	assetDomain.NormalizeOSName()
	assetDomain.NormalizeAssetType()

	// Validate standardized field values
	if err := assetDomain.ValidateFieldValues(); err != nil {
		logger.ErrorContext(ctx, "API service: Asset field validation failed: %v", err)
		return nil, err
	}

	logger.DebugContext(ctx, "API service: Calling internal service to create asset")
	aid, err := s.service.CreateAsset(ctx, assetDomain)
	if err != nil {
		logger.ErrorContext(ctx, "API service: Failed to create asset: %v", err)
		return nil, err
	}

	logger.InfoContext(ctx, "API service: Successfully created asset with ID: %s", aid.String())
	return &pb.CreateAssetResponse{Id: aid.String()}, nil
}

// UpdateAsset handles updating an existing asset
func (s *AssetService) UpdateAsset(ctx context.Context, req *pb.UpdateAssetRequest) (*pb.UpdateAssetResponse, error) {
	logger.InfoContext(ctx, "API service: Updating asset with ID: %s", req.GetId())

	assetUUID, err := uuid.Parse(req.GetId())
	if err != nil {
		logger.WarnContext(ctx, "API service: Invalid asset UUID provided for update: %s", req.GetId())
		return nil, ErrInvalidAssetUUID
	}

	now := time.Now()

	logger.DebugContextWithFields(ctx, "API service: Preparing asset update data", map[string]interface{}{
		"asset_id":   assetUUID.String(),
		"port_count": len(req.GetPorts()),
		"ip_count":   len(req.GetAssetIps()),
	})

	// Prepare ports
	ports := make([]domain.Port, 0, len(req.GetPorts()))
	for _, p := range req.GetPorts() {
		dt, _ := time.Parse(time.RFC3339, p.GetDiscoveredAt())
		ports = append(ports, domain.Port{
			ID:             p.GetId(),
			AssetID:        assetUUID.String(),
			PortNumber:     int(p.GetPortNumber()),
			Protocol:       p.GetProtocol(),
			State:          p.GetState(),
			ServiceName:    p.GetServiceName(),
			ServiceVersion: p.GetServiceVersion(),
			Description:    p.GetDescription(),
			DiscoveredAt:   dt,
		})
	}

	// Prepare asset IPs
	ips := make([]domain.AssetIP, 0, len(req.GetAssetIps()))
	for _, ip := range req.GetAssetIps() {
		ips = append(ips, domain.AssetIP{
			AssetID:    assetUUID.String(),
			IP:         ip.GetIp(),
			MACAddress: ip.GetMacAddress(),
		})
	}

	assetDomain := domain.AssetDomain{
		ID:               assetUUID,
		Name:             req.GetName(),
		Domain:           req.GetDomain(),
		Hostname:         req.GetHostname(),
		OSName:           req.GetOsName(),
		OSVersion:        req.GetOsVersion(),
		Type:             req.GetType(),
		Description:      req.GetDescription(),
		DiscoveredBy:     "System User", // hardcoded
		Risk:             int(req.GetRisk()),
		LoggingCompleted: req.GetLoggingCompleted(),
		AssetValue:       int(req.GetAssetValue()),
		CreatedAt:        now,
		UpdatedAt:        now,
		Ports:            ports,
		AssetIPs:         ips,
	}

	// Normalize and validate asset fields
	assetDomain.NormalizeOSName()
	assetDomain.NormalizeAssetType()

	// Validate standardized field values
	if err := assetDomain.ValidateFieldValues(); err != nil {
		logger.ErrorContext(ctx, "API service: Asset field validation failed during update: %v", err)
		return nil, err
	}

	logger.DebugContext(ctx, "API service: Calling internal service to update asset")
	if err := s.service.UpdateAsset(ctx, assetDomain); err != nil {
		logger.ErrorContext(ctx, "API service: Failed to update asset with ID %s: %v", assetUUID.String(), err)
		return nil, err
	}

	logger.InfoContext(ctx, "API service: Successfully updated asset with ID: %s", assetUUID.String())
	return &pb.UpdateAssetResponse{}, nil
}

func (s *AssetService) DeleteAssets(ctx context.Context, req *pb.DeleteAssetsRequest) (*pb.DeleteAssetsResponse, error) {
	logger.InfoContextWithFields(ctx, "API service: Deleting assets", map[string]interface{}{
		"asset_count": len(req.Ids),
		"has_filter":  req.Filter != nil,
		"exclude":     req.GetExclude(),
	})

	// Convert the filter from proto to domain if present
	var filter *domain.AssetFilters
	if req.Filter != nil {
		logger.DebugContext(ctx, "API service: Converting filter from proto to domain")
		f := domain.AssetFilters{
			Name:        req.GetFilter().GetName(),
			Domain:      req.GetFilter().GetDomain(),
			Hostname:    req.GetFilter().GetHostname(),
			OSName:      req.GetFilter().GetOsName(),
			OSVersion:   req.GetFilter().GetOsVersion(),
			Type:        req.GetFilter().GetType(),
			IP:          req.GetFilter().GetIp(),
			ScannerType: req.GetFilter().GetScannerType(),
			Network:     req.GetFilter().GetNetwork(),
		}
		filter = &f
	}

	logger.DebugContext(ctx, "API service: Calling internal service to delete assets")
	err := s.service.DeleteAssets(ctx, req.Ids, filter, req.GetExclude())
	if err != nil {
		logger.ErrorContext(ctx, "API service: Failed to delete assets: %v", err)
		return nil, err
	}

	logger.InfoContext(ctx, "API service: Successfully deleted assets (count: %d)", len(req.Ids))
	return &pb.DeleteAssetsResponse{
		Success: true,
	}, nil
}

func (s *AssetService) ExportAssets(ctx context.Context, req *pb.ExportAssetsRequest) ([]byte, error) {
	logger.InfoContextWithFields(ctx, "API service: Exporting assets", map[string]interface{}{
		"asset_count":            len(req.GetAssetIds()),
		"export_type":            req.GetExportType().String(),
		"selected_columns_count": len(req.GetSelectedColumns()),
	})

	assetUUIDs := []domain.AssetUUID{}

	// Check if we need to export all assets
	if len(req.GetAssetIds()) == 1 && req.GetAssetIds()[0] == "All" {
		logger.DebugContext(ctx, "API service: Exporting all assets")
		// Empty assetUUIDs means export all assets
	} else {
		logger.DebugContext(ctx, "API service: Parsing individual asset IDs for export")
		// Parse individual asset IDs
		for _, id := range req.GetAssetIds() {
			assetUUID, err := uuid.Parse(id)
			if err != nil {
				logger.WarnContext(ctx, "API service: Invalid asset UUID provided for export: %s", id)
				return nil, ErrInvalidAssetUUID
			}
			assetUUIDs = append(assetUUIDs, assetUUID)
		}
	}

	// Map export type from PB to domain
	var exportType domain.ExportType

	switch req.GetExportType() {
	case pb.ExportType_FULL_EXPORT:
		exportType = domain.FullExport
		logger.DebugContext(ctx, "API service: Using full export type")
	case pb.ExportType_SELECTED_COLUMNS:
		exportType = domain.SelectedColumnsExport
		logger.DebugContext(ctx, "API service: Using selected columns export type")
	default:
		exportType = domain.FullExport
		logger.DebugContext(ctx, "API service: Using default full export type")
	}

	logger.DebugContext(ctx, "API service: Calling internal service to export assets")
	exportData, err := s.service.ExportAssets(ctx, assetUUIDs, exportType, req.GetSelectedColumns())
	if err != nil {
		logger.ErrorContext(ctx, "API service: Failed to export assets: %v", err)
		return nil, err
	}

	logger.DebugContext(ctx, "API service: Calling internal service to generate CSV")
	csvData, err := s.service.GenerateCSV(ctx, exportData)
	if err != nil {
		logger.ErrorContext(ctx, "API service: Failed to generate CSV: %v", err)
		return nil, err
	}

	logger.InfoContextWithFields(ctx, "API service: Successfully exported assets", map[string]interface{}{
		"csv_size": len(csvData),
	})

	return csvData, nil
}

// GetDistinctOSNames returns a list of all distinct OS names from assets
func (s *AssetService) GetDistinctOSNames(ctx context.Context, req *pb.GetDistinctOSNamesRequest) (*pb.GetDistinctOSNamesResponse, error) {
	logger.InfoContext(ctx, "API service: Getting distinct OS names")

	logger.DebugContext(ctx, "API service: Calling internal service to get distinct OS names")
	osNames, err := s.service.GetDistinctOSNames(ctx)
	if err != nil {
		logger.ErrorContext(ctx, "API service: Failed to get distinct OS names: %v", err)
		return nil, err
	}

	logger.InfoContext(ctx, "API service: Successfully retrieved distinct OS names (count: %d)", len(osNames))

	return &pb.GetDistinctOSNamesResponse{
		OsNames: osNames,
	}, nil
}

// Dashboard API methods

func (s *AssetService) GetDashboardAssetCount(ctx context.Context, req *pb.GetDashboardAssetCountRequest) (*pb.GetDashboardAssetCountResponse, error) {
	logger.InfoContext(ctx, "API service: Getting dashboard asset count")

	logger.DebugContext(ctx, "API service: Calling internal service to get dashboard asset count")
	data, err := s.service.GetDashboardAssetCount(ctx)
	if err != nil {
		logger.ErrorContext(ctx, "API service: Failed to get dashboard asset count: %v", err)
		return nil, err
	}

	// Convert domain to protobuf
	pbContents := make([]*pb.AssetStatusCount, len(data.Contents))
	for i, content := range data.Contents {
		pbContents[i] = &pb.AssetStatusCount{
			Source:  content.Source,
			Percent: int32(content.Percent),
		}
	}

	response := &pb.GetDashboardAssetCountResponse{
		Contents: pbContents,
		Count:    int32(data.Count),
	}

	logger.InfoContext(ctx, "API service: Successfully retrieved dashboard asset count")
	return response, nil
}

func (s *AssetService) GetDashboardAssetPerScanner(ctx context.Context, req *pb.GetDashboardAssetPerScannerRequest) (*pb.GetDashboardAssetPerScannerResponse, error) {
	logger.InfoContext(ctx, "API service: Getting dashboard asset per scanner")

	logger.DebugContext(ctx, "API service: Calling internal service to get dashboard asset per scanner")
	data, err := s.service.GetDashboardAssetPerScanner(ctx)
	if err != nil {
		logger.ErrorContext(ctx, "API service: Failed to get dashboard asset per scanner: %v", err)
		return nil, err
	}

	// Convert domain to protobuf
	pbContents := make([]*pb.ScannerTypeCount, len(data.Contents))
	for i, content := range data.Contents {
		pbContents[i] = &pb.ScannerTypeCount{
			Source: content.Source,
			Count:  int32(content.Count),
		}
	}

	response := &pb.GetDashboardAssetPerScannerResponse{
		Contents: pbContents,
	}

	logger.InfoContext(ctx, "API service: Successfully retrieved dashboard asset per scanner")
	return response, nil
}

func (s *AssetService) GetDashboardLoggingCompleted(ctx context.Context, req *pb.GetDashboardLoggingCompletedRequest) (*pb.GetDashboardLoggingCompletedResponse, error) {
	logger.InfoContext(ctx, "API service: Getting dashboard logging completed")

	logger.DebugContext(ctx, "API service: Calling internal service to get dashboard logging completed")
	data, err := s.service.GetDashboardLoggingCompleted(ctx)
	if err != nil {
		logger.ErrorContext(ctx, "API service: Failed to get dashboard logging completed: %v", err)
		return nil, err
	}

	// Convert domain to protobuf
	pbContents := make([]*pb.OSLoggingStats, len(data.Contents))
	for i, content := range data.Contents {
		pbContents[i] = &pb.OSLoggingStats{
			Source: content.Source,
			Count:  int32(content.Count),
			Total:  int32(content.Total),
		}
	}

	response := &pb.GetDashboardLoggingCompletedResponse{
		Contents: pbContents,
	}

	logger.InfoContext(ctx, "API service: Successfully retrieved dashboard logging completed")
	return response, nil
}

func (s *AssetService) GetDashboardAssetsPerSource(ctx context.Context, req *pb.GetDashboardAssetsPerSourceRequest) (*pb.GetDashboardAssetsPerSourceResponse, error) {
	logger.InfoContext(ctx, "API service: Getting dashboard assets per source")

	logger.DebugContext(ctx, "API service: Calling internal service to get dashboard assets per source")
	data, err := s.service.GetDashboardAssetsPerSource(ctx)
	if err != nil {
		logger.ErrorContext(ctx, "API service: Failed to get dashboard assets per source: %v", err)
		return nil, err
	}

	// Convert domain to protobuf
	pbContents := make([]*pb.AssetSourceStats, len(data.Contents))
	for i, content := range data.Contents {
		pbContents[i] = &pb.AssetSourceStats{
			Source:  content.Source,
			Percent: int32(content.Percent),
		}
	}

	response := &pb.GetDashboardAssetsPerSourceResponse{
		Contents: pbContents,
		Count:    int32(data.Count),
	}

	logger.InfoContext(ctx, "API service: Successfully retrieved dashboard assets per source")
	return response, nil
}

func domainToPbAsset(asset domain.AssetDomain) *pb.Asset {
	// Convert ports to protobuf format
	pbPorts := make([]*pb.Port, 0, len(asset.Ports))
	for _, port := range asset.Ports {
		pbPorts = append(pbPorts, &pb.Port{
			Id:             port.ID,
			AssetId:        port.AssetID,
			PortNumber:     int32(port.PortNumber),
			Protocol:       port.Protocol,
			State:          port.State,
			ServiceName:    port.ServiceName,
			ServiceVersion: port.ServiceVersion,
			Description:    port.Description,
			DiscoveredAt:   port.DiscoveredAt.Format("2006-01-02 15:04:05"),
		})
	}

	// Convert VMware VMs to protobuf format
	pbVMwareVMs := make([]*pb.VMwareVM, 0, len(asset.VMwareVMs))
	for _, vm := range asset.VMwareVMs {
		pbVMwareVMs = append(pbVMwareVMs, &pb.VMwareVM{
			VmId:         vm.VMID,
			AssetId:      vm.AssetID,
			VmName:       vm.VMName,
			Hypervisor:   vm.Hypervisor,
			CpuCount:     int32(vm.CPUCount),
			MemoryMb:     int32(vm.MemoryMB),
			DiskSizeGb:   int32(vm.DiskSizeGB),
			PowerState:   vm.PowerState,
			LastSyncedAt: vm.LastSyncedAt.Format("2006-01-02 15:04:05"),
		})
	}

	// Convert asset IPs to protobuf format
	pbAssetIPs := make([]*pb.AssetIP, 0, len(asset.AssetIPs))
	for _, ip := range asset.AssetIPs {
		pbAssetIPs = append(pbAssetIPs, &pb.AssetIP{
			AssetId:    ip.AssetID,
			Ip:         ip.IP,
			MacAddress: ip.MACAddress,
		})
	}

	// Convert scanner info to protobuf format
	var pbScanner *pb.Scanner
	if asset.Scanner != nil {
		pbScanner = &pb.Scanner{
			Type: asset.Scanner.Type,
		}
	} else {
		pbScanner = &pb.Scanner{
			Type: "",
		}
	}

	return &pb.Asset{
		Id:               asset.ID.String(),
		Name:             asset.Name,
		Domain:           asset.Domain,
		Hostname:         asset.Hostname,
		OsName:           asset.OSName,
		OsVersion:        asset.OSVersion,
		Type:             asset.Type,
		DiscoveredBy:     asset.DiscoveredBy,
		Description:      asset.Description,
		Risk:             int32(asset.Risk),
		LoggingCompleted: asset.LoggingCompleted,
		AssetValue:       int32(asset.AssetValue),
		CreatedAt:        asset.CreatedAt.Format("2006-01-02 15:04:05"),
		UpdatedAt:        asset.UpdatedAt.Format("2006-01-02 15:04:05"),
		Ports:            pbPorts,
		VmwareVms:        pbVMwareVMs,
		AssetIps:         pbAssetIPs,
		Scanner:          pbScanner,
	}
}
