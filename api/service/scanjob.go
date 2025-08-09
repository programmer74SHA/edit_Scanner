package service

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"gitlab.apk-group.net/siem/backend/asset-discovery/api/pb"
	assetDomain "gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/domain"
	domain "gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanjob/domain"
	scanjobPort "gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanjob/port"
	schedulerPort "gitlab.apk-group.net/siem/backend/asset-discovery/internal/scheduler/port"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/logger"
)

var (
	ErrScanJobNotFound    = errors.New("scan job not found")
	ErrInvalidScanJobUUID = errors.New("invalid scan job UUID")
	ErrJobNotComplete     = errors.New("scan job is not complete")
)

// ScanJobService provides API operations for scan jobs
type ScanJobService struct {
	service          scanjobPort.Service
	schedulerService schedulerPort.Service
}

// NewScanJobService creates a new ScanJobService
func NewScanJobService(srv scanjobPort.Service, schedulerSrv schedulerPort.Service) *ScanJobService {
	return &ScanJobService{
		service:          srv,
		schedulerService: schedulerSrv,
	}
}

// GetJobs handles listing of scan jobs with filters, pagination, and sorting
func (s *ScanJobService) GetJobs(ctx context.Context, req *pb.GetJobsRequest) (*pb.GetJobsResponse, error) {
	// Parse filters
	filter := domain.ScanJobFilters{
		Name:   req.GetFilter().GetName(),
		Status: req.GetFilter().GetStatus(),
	}

	// Parse time range
	if f := req.GetFilter().GetStartTimeFrom(); f != "" {
		if t, err := time.Parse(time.RFC3339, f); err == nil {
			filter.StartTimeFrom = &t
		}
	}

	if tStr := req.GetFilter().GetStartTimeTo(); tStr != "" {
		if t, err := time.Parse(time.RFC3339, tStr); err == nil {
			filter.StartTimeTo = &t
		}
	}

	// Pagination
	limit := int(req.GetLimit())
	offset := int(req.GetPage()) * limit

	// Sorting
	sorts := make([]domain.SortOption, len(req.GetSort()))
	for i, srt := range req.GetSort() {
		sorts[i] = domain.SortOption{Field: srt.GetField(), Order: srt.GetOrder()}
	}

	jobs, total, err := s.service.GetJobs(ctx, filter, limit, offset, sorts...)
	if err != nil {
		return nil, err
	}

	// Map to protobuf
	pbJobs := make([]*pb.ScanJob, 0, len(jobs))
	for _, job := range jobs {
		pbJob := &pb.ScanJob{
			Id:        job.ID,
			Name:      job.Name,
			Status:    job.Status,
			StartTime: job.StartTime.Format(time.RFC3339),
			EndTime:   "",
			Progress:  0,
			ScannerId: job.ScannerID,
		}
		if job.EndTime != nil {
			pbJob.EndTime = job.EndTime.Format(time.RFC3339)
		}
		if job.Progress != nil {
			pbJob.Progress = int32(*job.Progress)
			if pbJob.Progress == 0 {
				pbJob.Progress = -1
			}
		}

		pbJobs = append(pbJobs, pbJob)
	}

	return &pb.GetJobsResponse{Contents: pbJobs, Count: int32(total)}, nil
}

// GetJobByID handles retrieving a scan job by its ID
func (s *ScanJobService) GetJobByID(ctx context.Context, req *pb.GetJobByIDRequest) (*pb.GetJobByIDResponse, error) {
	// Parse UUID
	id := req.GetId()

	job, err := s.service.GetJobByID(ctx, id)
	if err != nil {
		return nil, err
	}

	if job == nil {
		return nil, ErrScanJobNotFound
	}

	scannerService := s.service.GetScannerService()
	scanner, err := scannerService.GetScannerByID(ctx, job.ScannerID)
	if err != nil {
		logger.ErrorContext(ctx, "failed to get scanner info for job %d: %v", job.ID, err)
		scanner = nil
	}

	// Map to protobuf
	resp := &pb.GetJobByIDResponse{Job: &pb.ScanJob{
		Id:        job.ID,
		Name:      job.Name,
		Status:    job.Status,
		StartTime: job.StartTime.Format(time.RFC3339),
	}}

	// optional fields
	if job.EndTime != nil {
		resp.Job.EndTime = job.EndTime.Format(time.RFC3339)
	}

	if job.Progress != nil {
		resp.Job.Progress = int32(*job.Progress)
	}

	resp.Job.ScannerId = job.ScannerID

	// Add scanner information
	if scanner != nil {
		resp.Job.ScannerType = scanner.ScanType

		targetType, targetIP, targetIPStart, targetIPEnd := scannerService.GetScannerTargetDetails(
			scanner.ScanType,
			scanner.Target,
			scanner.IP,
			scanner.Subnet,
			scanner.StartIP,
			scanner.EndIP,
		)

		resp.Job.Target = targetType
		resp.Job.Ip = targetIP
		resp.Job.IpStart = targetIPStart
		resp.Job.IpEnd = targetIPEnd
	} else {
		resp.Job.ScannerType = ""
		resp.Job.Target = ""
		resp.Job.Ip = ""
		resp.Job.IpStart = ""
		resp.Job.IpEnd = ""
	}

	resp.Job.AssetScanJobs = make([]*pb.AssetScanJob, 0)

	// assets
	for _, as := range job.AssetScanJobs {
		asset := as.Asset
		pbAsset := &pb.Asset{Id: asset.ID.String(), Name: asset.Name, Domain: asset.Domain, Hostname: asset.Hostname, OsName: asset.OSName, OsVersion: asset.OSVersion, Type: asset.Type, Description: asset.Description, CreatedAt: asset.CreatedAt.Format(time.RFC3339), UpdatedAt: asset.UpdatedAt.Format(time.RFC3339), Risk: int32(asset.Risk)}
		resp.Job.AssetScanJobs = append(resp.Job.AssetScanJobs, &pb.AssetScanJob{Asset: pbAsset, DiscoveredAt: as.DiscoveredAt.Format(time.RFC3339)})
	}

	return resp, nil
}

// CancelScanJob cancels a running scan job
func (s *ScanJobService) CancelScanJob(ctx context.Context, req *pb.CancelScanJobRequest) (*pb.CancelScanJobResponse, error) {
	logger.InfoContext(ctx, "Service: Attempting to cancel scan job with ID: %s", req.GetId())

	// Check if scheduler service is set
	if s.schedulerService == nil {
		logger.ErrorContext(ctx, "Service: Scheduler service is not available - this indicates a service initialization problem")
		return &pb.CancelScanJobResponse{
			Success:      false,
			ErrorMessage: "Scheduler service not available",
		}, fmt.Errorf("scheduler service not initialized")
	}

	// Parse job ID
	jobID, err := strconv.ParseInt(req.GetId(), 10, 64)
	if err != nil {
		logger.ErrorContext(ctx, "Service: Invalid job ID format: %s, error: %v", req.GetId(), err)
		return &pb.CancelScanJobResponse{
			Success:      false,
			ErrorMessage: fmt.Sprintf("Invalid job ID format: %s", req.GetId()),
		}, fmt.Errorf("invalid job ID format")
	}

	// Add debugging: Get job details first to see what we're working with
	internalJobService := s.service
	job, err := internalJobService.GetJobByID(ctx, jobID)
	if err != nil {
		logger.ErrorContext(ctx, "Service: Failed to get job details for debugging: %v", err)
		// Continue with cancellation attempt
	} else if job != nil {
		logger.InfoContext(ctx, "Service: DEBUG - Job details: ID=%d, Name=%s, Status=%s, ScannerID=%d",
			job.ID, job.Name, job.Status, job.ScannerID)

		// Get scanner details to understand the type
		scannerService := internalJobService.GetScannerService()
		if scannerService != nil {
			scanner, scannerErr := scannerService.GetScannerByID(ctx, job.ScannerID)
			if scannerErr == nil && scanner != nil {
				logger.InfoContext(ctx, "Service: DEBUG - Scanner details: ID=%d, Type=%s, ScanType=%s",
					scanner.ID, scanner.Type, scanner.ScanType)
			} else {
				logger.WarnContext(ctx, "Service: DEBUG - Could not get scanner details: %v", scannerErr)
			}
		}
	}

	logger.InfoContext(ctx, "Service: Calling scheduler service to cancel job ID: %d", jobID)

	// Call scheduler service to cancel the job
	err = s.schedulerService.CancelScanJob(ctx, jobID)
	if err != nil {
		logger.ErrorContext(ctx, "Service: Failed to cancel scan job: %v", err)

		// Handle specific error types with proper logging
		errMsg := err.Error()
		if strings.Contains(strings.ToLower(errMsg), "not found") ||
			strings.Contains(strings.ToLower(errMsg), "job not found") {
			logger.InfoContext(ctx, "Service: Scan job not found or already completed")
			return &pb.CancelScanJobResponse{
				Success:      false,
				ErrorMessage: "Scan job not found or already completed",
			}, fmt.Errorf("scan job not found")
		}

		if strings.Contains(strings.ToLower(errMsg), "not running") {
			logger.InfoContext(ctx, "Service: Scan job is not currently running")
			return &pb.CancelScanJobResponse{
				Success:      false,
				ErrorMessage: "Scan job is not currently running",
			}, fmt.Errorf("scan job is not running")
		}

		return &pb.CancelScanJobResponse{
			Success:      false,
			ErrorMessage: fmt.Sprintf("Failed to cancel scan job: %v", err),
		}, err
	}

	logger.InfoContext(ctx, "Service: Successfully cancelled scan job ID: %d", jobID)
	return &pb.CancelScanJobResponse{
		Success: true,
		JobId:   jobID,
	}, nil
}

// DiffJobs handles comparing two scan jobs to find new and missing assets
func (s *ScanJobService) DiffJobs(ctx context.Context, req *pb.DiffJobsRequest) (*pb.DiffJobsResponse, error) {
	ids := req.GetIds()

	// Validate that exactly 2 job IDs are provided
	if len(ids) != 2 {
		return nil, errors.New("exactly 2 job IDs must be provided")
	}

	// Get type (new or missing)
	assetType := req.GetType()
	if assetType != "new" && assetType != "missing" {
		return nil, errors.New("type must be 'new' or 'missing'")
	}

	// Get pagination parameters
	limit := int(req.GetLimit())
	page := int(req.GetPage())

	// Default values if not provided
	if limit <= 0 {
		limit = 5
	}
	if page < 0 {
		page = 0
	}

	// Calculate offset from page and limit
	offset := page * limit

	// Get sorting parameters
	sorts := req.GetSort()

	// Call service to get differences
	assets, count, err := s.service.DiffJobsByType(ctx, ids, assetType, limit, offset, sorts)
	if err != nil {
		// Map internal errors to API errors
		switch err.Error() {
		case "newer job is not complete", "older job is not complete":
			return nil, ErrJobNotComplete
		case "scan job not found", "one or both jobs not found":
			return nil, ErrScanJobNotFound
		case "exactly 2 job IDs must be provided":
			return nil, errors.New("exactly 2 job IDs must be provided")
		default:
			return nil, err
		}
	}

	convertAssetDomainToPb := func(asset assetDomain.AssetDomain) *pb.Asset {
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
				DiscoveredAt:   port.DiscoveredAt.Format(time.RFC3339),
			})
		}

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
				LastSyncedAt: vm.LastSyncedAt.Format(time.RFC3339),
			})
		}

		pbAssetIPs := make([]*pb.AssetIP, 0, len(asset.AssetIPs))
		for _, ip := range asset.AssetIPs {
			pbAssetIPs = append(pbAssetIPs, &pb.AssetIP{
				AssetId:    ip.AssetID,
				Ip:         ip.IP,
				MacAddress: ip.MACAddress,
			})
		}

		return &pb.Asset{
			Id:          asset.ID.String(),
			Name:        asset.Name,
			Domain:      asset.Domain,
			Hostname:    asset.Hostname,
			OsName:      asset.OSName,
			OsVersion:   asset.OSVersion,
			Type:        asset.Type,
			Description: asset.Description,
			Risk:        int32(asset.Risk),
			CreatedAt:   asset.CreatedAt.Format(time.RFC3339),
			UpdatedAt:   asset.UpdatedAt.Format(time.RFC3339),
			Ports:       pbPorts,
			VmwareVms:   pbVMwareVMs,
			AssetIps:    pbAssetIPs,
		}
	}

	pbAssets := make([]*pb.Asset, 0, len(assets))
	for _, asset := range assets {
		pbAssets = append(pbAssets, convertAssetDomainToPb(asset))
	}

	return &pb.DiffJobsResponse{
		Contents: pbAssets,
		Count:    int32(count),
	}, nil
}

// ExportJobDiff exports the differences between two scan jobs as a CSV file
func (s *ScanJobService) ExportJobDiff(ctx context.Context, req *pb.ExportJobDiffRequest) ([]byte, error) {
	ids := req.GetIds()

	// Validate that exactly 2 job IDs are provided
	if len(ids) != 2 {
		return nil, errors.New("exactly 2 job IDs must be provided")
	}

	export_data, err := s.service.ExportDiffJobs(ctx, ids)
	if err != nil {
		return nil, err
	}

	// Get the asset service from the container
	assetSvc := s.service.GetAssetService()

	// Use the asset service's GenerateCSV method
	csvData, err := assetSvc.GenerateCSV(ctx, export_data)
	if err != nil {
		return nil, err
	}

	return csvData, nil
}
