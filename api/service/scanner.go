package service

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"time"

	"gitlab.apk-group.net/siem/backend/asset-discovery/api/pb"
	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanner"
	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanner/domain"
	scannerPort "gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanner/port"
	schedulerDomain "gitlab.apk-group.net/siem/backend/asset-discovery/internal/scheduler/domain"
	schedulerPort "gitlab.apk-group.net/siem/backend/asset-discovery/internal/scheduler/port"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/logger"
)

var (
	ErrScannerOnCreate     = scanner.ErrScannerOnCreate
	ErrScannerOnUpdate     = scanner.ErrScannerOnUpdate
	ErrScannerOnDelete     = scanner.ErrScannerOnDelete
	ErrScannerNotFound     = scanner.ErrScannerNotFound
	ErrInvalidScannerInput = scanner.ErrInvalidScannerInput
)

type ScannerService struct {
	service                  scannerPort.Service
	schedulerService         schedulerPort.Service
	concreteSchedulerService interface{} // For accessing internal methods
}

func NewScannerService(srv scannerPort.Service) *ScannerService {
	return &ScannerService{
		service: srv,
	}
}

// SetSchedulerService sets the scheduler service reference
func (s *ScannerService) SetSchedulerService(schedulerSrv schedulerPort.Service) {
	s.schedulerService = schedulerSrv
	// Store the concrete implementation for internal method access
	s.concreteSchedulerService = schedulerSrv
}

// CreateScanner creates a new scanner
func (s *ScannerService) CreateScanner(ctx context.Context, req *pb.CreateScannerRequest) (*pb.CreateScannerResponse, error) {
	logger.DebugContext(ctx, "API Service: Creating scanner")

	// Map request to domain model
	scanner := domain.ScannerDomain{
		Name:               req.GetName(),
		ScanType:           req.GetScanType(),
		Type:               req.GetType(),
		Status:             req.GetStatus(),
		UserID:             req.GetUserId(),
		Target:             req.GetTarget(),
		IP:                 req.GetIp(),
		Subnet:             req.GetSubnet(),
		StartIP:            req.GetStartIp(),
		EndIP:              req.GetEndIp(),
		Port:               req.GetPort(),
		Username:           req.GetUsername(),
		Password:           req.GetPassword(),
		ApiKey:             req.GetApiKey(),
		Domain:             req.GetDomain(),
		AuthenticationType: req.GetAuthenticationType(),
		Protocol:           req.GetProtocol(),
		CustomSwitches:     req.GetCustomSwitches(),
	}

	// Handle NMAP scanner configuration based on profile_id and custom_switches
	if req.GetScanType() == "NMAP" {
		if req.GetProfileId() == "-1" {
			// Custom switches mode - this will trigger custom profile creation in the service layer
			if req.GetCustomSwitches() == "" {
				return &pb.CreateScannerResponse{
					Success:      false,
					ErrorMessage: "custom_switches is required when profile_id is -1",
				}, fmt.Errorf("custom_switches is required when profile_id is -1")
			}
			scanner.Type = "custom"
			scanner.CustomSwitches = req.GetCustomSwitches()
			// Don't set profile ID - it will be created by the service layer
		} else if req.GetProfileId() != "" && req.GetProfileId() != "0" && req.GetProfileId() != "-1" {
			// Profile mode with specific profile
			profileID, err := strconv.ParseInt(req.GetProfileId(), 10, 64)
			if err != nil {
				return &pb.CreateScannerResponse{
					Success:      false,
					ErrorMessage: "Invalid profile_id format",
				}, fmt.Errorf("invalid profile_id format: %v", err)
			}
			scanner.Type = "profile"
			scanner.NmapProfileID = &profileID
		} else {
			// Default profile mode (profile_id == "0" or not specified)
			scanner.Type = "profile"
			// Service layer will use default profile
		}
	}

	// Rest of the method remains the same...
	// Map schedule from request
	if req.GetSchedule() != nil {
		schedule := &domain.Schedule{
			ScheduleType:   domain.ScheduleType(req.GetSchedule().GetScheduleType()),
			FrequencyValue: req.GetSchedule().GetFrequencyValue(),
			FrequencyUnit:  req.GetSchedule().GetFrequencyUnit(),
			Month:          req.GetSchedule().GetMonth(),
			Week:           req.GetSchedule().GetWeek(),
			Day:            req.GetSchedule().GetDay(),
			Hour:           req.GetSchedule().GetHour(),
			Minute:         req.GetSchedule().GetMinute(),
		}

		// Parse RunTime if provided
		if runTimeStr := req.GetSchedule().GetRunTime(); runTimeStr != "" {
			runTime, err := parseRunTime(runTimeStr)
			if err != nil {
				return &pb.CreateScannerResponse{
					Success:      false,
					ErrorMessage: fmt.Sprintf("failed to parse RunTime: %v", err),
				}, err
			}
			schedule.RunTime = runTime

			// Additional validation for RUN_ONCE schedules
			if strings.ToUpper(string(schedule.ScheduleType)) == "RUN_ONCE" {
				now := time.Now()
				if !runTime.After(now) {
					return &pb.CreateScannerResponse{
						Success: false,
						ErrorMessage: fmt.Sprintf("run_time must be in the future for RUN_ONCE schedule. Current time: %s, provided run_time: %s",
							now.Format("2006-01-02 15:04:05"), runTime.Format("2006-01-02 15:04:05")),
					}, fmt.Errorf("run_time must be in the future")
				}
			}
		}

		scanner.Schedule = schedule
	}

	// Call internal service - all validation will be done there
	id, err := s.service.CreateScanner(ctx, scanner)
	if err != nil {
		return &pb.CreateScannerResponse{
			Success:      false,
			ErrorMessage: err.Error(),
		}, err
	}

	// Get the created scanner to return complete data
	createdScanner, err := s.service.GetScannerByID(ctx, id)
	if err != nil {
		// If we can't get the created scanner, return basic info
		return &pb.CreateScannerResponse{
			Success: true,
			Scanner: &pb.Scanner{
				Id:       strconv.FormatInt(id, 10),
				Name:     scanner.Name,
				ScanType: scanner.ScanType,
				Status:   scanner.Status,
			},
		}, nil
	}

	// Return success response with complete scanner data
	return &pb.CreateScannerResponse{
		Success: true,
		Scanner: mapDomainToProto(createdScanner),
	}, nil
}

func (s *ScannerService) GetScanner(ctx context.Context, req *pb.GetScannerRequest) (*pb.GetScannerResponse, error) {
	id, err := strconv.ParseInt(req.GetId(), 10, 64)
	if err != nil {
		return &pb.GetScannerResponse{
			Success:      false,
			ErrorMessage: "Invalid scanner ID",
		}, ErrInvalidScannerInput
	}

	// Get scanner from internal service
	scanner, err := s.service.GetScannerByID(ctx, id)
	if err != nil {
		return &pb.GetScannerResponse{
			Success:      false,
			ErrorMessage: err.Error(),
		}, err
	}

	// Map domain model to response
	pbScanner := mapDomainToProto(scanner)

	return &pb.GetScannerResponse{
		Success: true,
		Scanner: pbScanner,
	}, nil
}

func (s *ScannerService) UpdateScanner(ctx context.Context, req *pb.UpdateScannerRequest) (*pb.UpdateScannerResponse, error) {
	logger.DebugContext(ctx, "API Service: Updating scanner")

	// Parse and validate scanner ID
	id, err := strconv.ParseInt(req.GetId(), 10, 64)
	if err != nil {
		return &pb.UpdateScannerResponse{
			Success:      false,
			ErrorMessage: "Invalid scanner ID",
		}, ErrInvalidScannerInput
	}

	// Create scanner domain object with only the fields that are being updated
	scanner := domain.ScannerDomain{
		ID:                 id,
		Name:               req.GetName(),
		ScanType:           req.GetScanType(),
		Status:             req.GetStatus(),
		UserID:             req.GetUserId(),
		Target:             req.GetTarget(),
		Type:               req.GetType(),
		IP:                 req.GetIp(),
		Subnet:             req.GetSubnet(),
		StartIP:            req.GetStartIp(),
		EndIP:              req.GetEndIp(),
		Port:               req.GetPort(),
		Username:           req.GetUsername(),
		Password:           req.GetPassword(),
		ApiKey:             req.GetApiKey(),
		Domain:             req.GetDomain(),
		AuthenticationType: req.GetAuthenticationType(),
		Protocol:           req.GetProtocol(),
		CustomSwitches:     req.GetCustomSwitches(),
	}

	// Handle NMAP scanner configuration based on profile_id and custom_switches
	if req.GetScanType() == "NMAP" {
		if req.GetProfileId() == "-1" {
			// Custom switches mode - this will trigger custom profile creation in the service layer
			if req.GetCustomSwitches() == "" {
				return &pb.UpdateScannerResponse{
					Success:      false,
					ErrorMessage: "custom_switches is required when profile_id is -1",
				}, fmt.Errorf("custom_switches is required when profile_id is -1")
			}
			scanner.Type = "custom"
			scanner.CustomSwitches = req.GetCustomSwitches()
			// Don't set profile ID - it will be created by the service layer
		} else if req.GetProfileId() != "" && req.GetProfileId() != "0" && req.GetProfileId() != "-1" {
			// Profile mode with specific profile
			profileID, err := strconv.ParseInt(req.GetProfileId(), 10, 64)
			if err != nil {
				return &pb.UpdateScannerResponse{
					Success:      false,
					ErrorMessage: "Invalid profile_id format",
				}, fmt.Errorf("invalid profile_id format: %v", err)
			}
			scanner.Type = "profile"
			scanner.NmapProfileID = &profileID
			// Clear custom switches when using profile
			scanner.CustomSwitches = ""
		} else if req.GetProfileId() == "0" {
			// Default profile mode - don't change existing mode unless explicitly switching
			// This will be handled by the merge logic in the service layer
		}
	}

	// Handle schedule updates if present
	if hasScheduleUpdates(req) {
		schedule := &domain.Schedule{
			ScannerID:      id,
			ScheduleType:   domain.ScheduleType(req.GetScheduleType()),
			FrequencyValue: req.GetFrequencyValue(),
			FrequencyUnit:  req.GetFrequencyUnit(),
			Month:          req.GetMonth(),
			Week:           req.GetWeek(),
			Day:            req.GetDay(),
			Hour:           req.GetHour(),
			Minute:         req.GetMinute(),
		}

		// Parse RunTime if provided
		if req.GetRunTime() != "" {
			runTime, err := parseRunTime(req.GetRunTime())
			if err != nil {
				return &pb.UpdateScannerResponse{
					Success:      false,
					ErrorMessage: fmt.Sprintf("failed to parse RunTime: %v", err),
				}, err
			}
			schedule.RunTime = runTime

			// Additional validation for RUN_ONCE schedules
			if strings.ToUpper(req.GetScheduleType()) == "RUN_ONCE" {
				now := time.Now()
				if !runTime.After(now) {
					return &pb.UpdateScannerResponse{
						Success: false,
						ErrorMessage: fmt.Sprintf("run_time must be in the future for RUN_ONCE schedule. Current time: %s, provided run_time: %s",
							now.Format("2006-01-02 15:04:05"), runTime.Format("2006-01-02 15:04:05")),
					}, fmt.Errorf("run_time must be in the future")
				}
			}
		}

		scanner.Schedule = schedule
	}

	// Call internal service to update scanner
	if err := s.service.UpdateScanner(ctx, scanner); err != nil {
		return &pb.UpdateScannerResponse{
			Success:      false,
			ErrorMessage: err.Error(),
		}, err
	}

	// Get the updated scanner to return accurate data
	updatedScanner, err := s.service.GetScannerByID(ctx, id)
	if err != nil {
		// If we can't get the updated scanner, return basic info
		return &pb.UpdateScannerResponse{
			Success: true,
			Scanner: &pb.Scanner{
				Id:       req.GetId(),
				Name:     req.GetName(),
				ScanType: req.GetScanType(),
				Status:   req.GetStatus(),
			},
		}, nil
	}

	// Build and return success response with updated scanner data
	return &pb.UpdateScannerResponse{
		Success: true,
		Scanner: mapDomainToProto(updatedScanner),
	}, nil
}

func (s *ScannerService) DeleteScanner(ctx context.Context, req *pb.DeleteScannerRequest) (*pb.DeleteScannerResponse, error) {
	id, err := strconv.ParseInt(req.GetId(), 10, 64)
	if err != nil {
		return &pb.DeleteScannerResponse{
			Success:      false,
			ErrorMessage: "Invalid scanner ID",
		}, ErrInvalidScannerInput
	}

	if err := s.service.DeleteScanner(ctx, id); err != nil {
		return &pb.DeleteScannerResponse{
			Success:      false,
			ErrorMessage: err.Error(),
		}, err
	}

	return &pb.DeleteScannerResponse{
		Success: true,
	}, nil
}

func (s *ScannerService) DeleteScanners(ctx context.Context, req *pb.DeleteScannersRequest) (*pb.DeleteScannersResponse, error) {
	// Convert the filter from proto to domain if present
	var filter *domain.ScannerFilter
	if req.Filter != nil {
		var status bool
		hasStatusFilter := req.Filter.GetHasStatusFilter()

		if hasStatusFilter {
			status = req.Filter.GetStatus()
		}

		f := domain.ScannerFilter{
			Name:     req.Filter.GetName(),
			ScanType: req.Filter.GetType(),
		}

		if hasStatusFilter {
			f.Status = &status
		}

		filter = &f
	}

	deletedCount, err := s.service.DeleteScanners(ctx, req.Ids, filter, req.GetExclude())
	if err != nil {
		return &pb.DeleteScannersResponse{
			Success:      false,
			ErrorMessage: err.Error(),
			DeletedCount: 0,
		}, err
	}

	return &pb.DeleteScannersResponse{
		Success:      true,
		DeletedCount: int32(deletedCount),
	}, nil
}

func (s *ScannerService) ListScanners(
	ctx context.Context,
	req *pb.ListScannersRequest,
	limit int,
	page int,
	sortField string,
	sortOrder string,
) (*pb.ListScannersResponse, int, error) {
	// Create filter
	filter := domain.ScannerFilter{
		Name:     req.GetName(),
		ScanType: req.GetScanType(),
	}

	// Use the has_status_filter field directly
	if req.GetHasStatusFilter() {
		status := req.GetStatus()
		filter.Status = &status
		logger.InfoContext(ctx, "Service: Status filter explicitly provided: %v", status)
	} else {
		logger.InfoContext(ctx, "Service: No status filter provided, will fetch all scanners")
		// Don't set filter.Status, which means no status filtering
	}

	// Create pagination options
	pagination := domain.Pagination{
		Limit:     limit,
		Page:      page,
		SortField: sortField,
		SortOrder: sortOrder,
	}

	// Call internal service
	scanners, totalCount, err := s.service.ListScanners(ctx, filter, pagination)
	if err != nil {
		return nil, 0, err
	}

	// Convert domain objects to protobuf objects
	pbScanners := make([]*pb.Scanner, 0)

	for _, scanner := range scanners {
		// Make a copy to avoid modifying the original
		scannerCopy := scanner
		pbScanner := mapDomainToProto(&scannerCopy)

		// Ensure status is set explicitly
		pbScanner.Status = scanner.Status

		pbScanners = append(pbScanners, pbScanner)
	}

	return &pb.ListScannersResponse{
		Scanners:   pbScanners,
		TotalCount: int32(totalCount),
		Success:    true,
	}, totalCount, nil
}

func (s *ScannerService) UpdateScannerStatus(ctx context.Context, req *pb.UpdateScannerStatusRequest) (*pb.UpdateScannerStatusResponse, error) {
	logger.InfoContext(ctx, "API Service: Update scanner status request: %+v", req)

	// Parse IDs if provided
	var ids []int64
	for _, idStr := range req.GetIds() {
		// Special case for "all"
		if idStr == "all" || idStr == "All" {
			req.UpdateAll = true
			ids = []int64{} // empty the IDs list
			break
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			continue // Skip invalid IDs
		}
		ids = append(ids, id)
	}

	// Create filter from request
	filter := domain.ScannerFilter{}
	if req.GetFilter() != nil {
		filter.Name = req.GetFilter().GetName()

		// Handle case insensitivity for scan_type
		scanType := req.GetFilter().GetType()
		if strings.EqualFold(scanType, "domain") {
			scanType = domain.ScannerTypeDomain
		} else if strings.EqualFold(scanType, "nmap") {
			scanType = domain.ScannerTypeNmap
		} else if strings.EqualFold(scanType, "vcenter") {
			scanType = domain.ScannerTypeVCenter
		}
		filter.ScanType = scanType
	}

	// Call internal service method with all parameters
	updatedCount, err := s.service.UpdateScannerStatus(
		ctx,
		filter,
		ids,
		req.GetStatus(),
		req.GetExclude(),
		req.GetUpdateAll(),
	)

	if err != nil {
		return &pb.UpdateScannerStatusResponse{
			Success:      false,
			ErrorMessage: err.Error(),
		}, err
	}

	return &pb.UpdateScannerStatusResponse{
		Success:      true,
		UpdatedCount: int32(updatedCount),
	}, nil
}


// RunScanNow handles HTTP requests to immediately execute a scan for a scanner
func (s *ScannerService) RunScanNow(ctx context.Context, req *pb.RunScanNowRequest) (*pb.RunScanNowResponse, error) {
	logger.InfoContext(ctx, "Service: Running immediate scan for scanner ID: %s", req.GetScannerId())

	// Parse scanner ID
	scannerID, err := strconv.ParseInt(req.GetScannerId(), 10, 64)
	if err != nil {
		logger.InfoContext(ctx, "Service: Invalid scanner ID: %v", err)
		return &pb.RunScanNowResponse{
			Success:      false,
			ErrorMessage: "Invalid scanner ID",
		}, ErrInvalidScannerInput
	}

	// Get the scanner details
	scanner, err := s.service.GetScannerByID(ctx, scannerID)
	if err != nil {
		logger.InfoContext(ctx, "Service: Error retrieving scanner: %v", err)
		return &pb.RunScanNowResponse{
			Success:      false,
			ErrorMessage: err.Error(),
		}, err
	}

	if scanner == nil {
		logger.InfoContext(ctx, "Service: Scanner not found with ID: %d", scannerID)
		return &pb.RunScanNowResponse{
			Success:      false,
			ErrorMessage: "Scanner not found",
		}, ErrScannerNotFound
	}

	// Log the scanner type for debugging
	logger.InfoContext(ctx, "Service: Scanner has type: '%s'", scanner.ScanType)

	// Check if scheduler service is set
	if s.schedulerService == nil {
		logger.InfoContext(ctx, "Service: Scheduler service not available")
		return &pb.RunScanNowResponse{
			Success:      false,
			ErrorMessage: "Scheduler service not available",
		}, errors.New("scheduler service not available")
	}

	// Create a scan job record using the concrete implementation
	var jobID int64
	if scheduler, ok := s.concreteSchedulerService.(interface {
		CreateScanJob(ctx context.Context, job schedulerDomain.ScanJob) (int64, error)
	}); ok {
		scanJob := schedulerDomain.ScanJob{
			ScannerID: scannerID,
			Name:      fmt.Sprintf("%s - Manual Run", scanner.Name),
			Type:      string(scanner.ScanType),
			Status:    schedulerDomain.ScheduleStatusRunning,
			StartTime: time.Now(),
			Progress:  0,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}

		var createJobErr error
		jobID, createJobErr = scheduler.CreateScanJob(ctx, scanJob)
		if createJobErr != nil {
			logger.InfoContext(ctx, "Service: Error creating scan job: %v", createJobErr)
			return &pb.RunScanNowResponse{
				Success:      false,
				ErrorMessage: "Failed to create scan job: " + createJobErr.Error(),
			}, createJobErr
		}
	} else {
		logger.InfoContext(ctx, "Service: Cannot create scan job - scheduler service doesn't support required methods")
		return &pb.RunScanNowResponse{
			Success:      false,
			ErrorMessage: "Scheduler service missing required capabilities",
		}, errors.New("scheduler service missing required capabilities")
	}

	// Execute the scan in a goroutine
	go func() {
		// Create a new context for the background operation
		bgCtx := context.Background()

		// Update job status to show scan is starting
		if scheduler, ok := s.concreteSchedulerService.(interface {
			UpdateScanJobStatus(ctx context.Context, jobID int64, status schedulerDomain.ScheduleStatus, progress int) error
		}); ok {
			err := scheduler.UpdateScanJobStatus(bgCtx, jobID, schedulerDomain.ScheduleStatusRunning, 10)
			if err != nil {
				logger.InfoContext(ctx, "Service: Failed to update scan job status: %v", err)
			}
		}

		// Execute the scan via the scheduler service's ExecuteManualScan method
		scanErr := s.schedulerService.ExecuteManualScan(bgCtx, *scanner, jobID)

		// Update job status based on scan result
		if completer, ok := s.concreteSchedulerService.(interface {
			CompleteScanJob(ctx context.Context, jobID int64, status schedulerDomain.ScheduleStatus) error
		}); ok {
			if scanErr != nil {
				logger.InfoContext(ctx, "Service: Error executing scan: %v", scanErr)
				err := completer.CompleteScanJob(bgCtx, jobID, schedulerDomain.ScheduleStatusFailed)
				if err != nil {
					logger.InfoContext(ctx, "Service: Failed to update job status to failed: %v", err)
				}
			} else {
				err := completer.CompleteScanJob(bgCtx, jobID, schedulerDomain.ScheduleStatusComplete)
				if err != nil {
					logger.InfoContext(ctx, "Service: Failed to update job status to complete: %v", err)
				}
			}
		}

		logger.InfoContext(ctx, "Service: Manual scan job ID %d completed with status: %v", jobID, scanErr == nil)
	}()

	return &pb.RunScanNowResponse{
		Success: true,
		JobId:   jobID,
	}, nil
}

// Helper functions
func hasScheduleUpdates(req *pb.UpdateScannerRequest) bool {
	return req.GetScheduleType() != "" ||
		req.GetFrequencyValue() > 0 ||
		req.GetFrequencyUnit() != "" ||
		req.GetRunTime() != "" ||
		req.GetHour() >= 0 ||
		req.GetMinute() >= 0 ||
		req.GetDay() > 0 ||
		req.GetWeek() > 0 ||
		req.GetMonth() > 0
}

func parseRunTime(runTimeStr string) (time.Time, error) {
	// Try parsing with different formats in order of preference
	formats := []string{
		"2006-01-02 15:04:05",       // Local time format
		"2006-01-02T15:04:05Z07:00", // RFC3339 with timezone
		"2006-01-02 15:04:05",       // Fallback format
	}

	// First try parsing as local time
	if runTime, err := time.ParseInLocation(formats[0], runTimeStr, time.Local); err == nil {
		return runTime, nil
	}

	// Try other formats
	for _, format := range formats[1:] {
		if runTime, err := time.Parse(format, runTimeStr); err == nil {
			return runTime, nil
		}
	}

	return time.Time{}, fmt.Errorf("unable to parse time format: %s", runTimeStr)
}

// Helper function to map domain scanner to protobuf scanner
func mapDomainToProto(scanner *domain.ScannerDomain) *pb.Scanner {
	if scanner == nil {
		return nil
	}

	pbScanner := &pb.Scanner{
		Id:                 strconv.FormatInt(scanner.ID, 10),
		Name:               scanner.Name,
		ScanType:           scanner.ScanType,
		Status:             scanner.Status,
		UserId:             scanner.UserID,
		CreatedAt:          scanner.CreatedAt.Format("2006-01-02 15:04:05"),
		UpdatedAt:          scanner.UpdatedAt.Format("2006-01-02 15:04:05"),
		Type:               scanner.Type,
		Target:             scanner.Target,
		Ip:                 scanner.IP,
		Subnet:             scanner.Subnet,
		StartIp:            scanner.StartIP,
		EndIp:              scanner.EndIP,
		Port:               scanner.Port,
		Username:           scanner.Username,
		Domain:             scanner.Domain,
		AuthenticationType: scanner.AuthenticationType,
		Protocol:           scanner.Protocol,
		CustomSwitches:     scanner.CustomSwitches,
	}

	// Add Nmap profile information
	if scanner.NmapProfileID != nil {
		pbScanner.ProfileId = strconv.FormatInt(*scanner.NmapProfileID, 10)
	}

	if scanner.NmapProfile != nil {
		pbScanner.NmapProfile = &pb.NmapProfile{
			Id:        scanner.NmapProfile.ID, // Fixed: Use int64 directly, not strconv.FormatInt
			Name:      scanner.NmapProfile.Name,
			Arguments: scanner.NmapProfile.Arguments,
			IsDefault: scanner.NmapProfile.IsDefault,
			IsSystem:  scanner.NmapProfile.IsSystem,
			CreatedAt: scanner.NmapProfile.CreatedAt.Format("2006-01-02 15:04:05"),
		}

		if scanner.NmapProfile.Description != nil {
			pbScanner.NmapProfile.Description = *scanner.NmapProfile.Description
		}

		if scanner.NmapProfile.CreatedBy != nil {
			pbScanner.NmapProfile.CreatedBy = *scanner.NmapProfile.CreatedBy
		}

		if scanner.NmapProfile.UpdatedAt != nil {
			pbScanner.NmapProfile.UpdatedAt = scanner.NmapProfile.UpdatedAt.Format("2006-01-02 15:04:05")
		}

		// Removed: pbScanner.NmapProfile.CustomSwitches (field doesn't exist in protobuf)
	}

	// Add schedule if available
	if scanner.Schedule != nil {
		pbScanner.Schedule = &pb.Schedule{
			ScheduleType:   string(scanner.Schedule.ScheduleType),
			FrequencyValue: scanner.Schedule.FrequencyValue,
			FrequencyUnit:  scanner.Schedule.FrequencyUnit,
			Month:          scanner.Schedule.Month,
			Week:           scanner.Schedule.Week,
			Day:            scanner.Schedule.Day,
			Hour:           scanner.Schedule.Hour,
			Minute:         scanner.Schedule.Minute,
		}

		// Include run_time in the response if it's set
		if !scanner.Schedule.RunTime.IsZero() {
			pbScanner.Schedule.RunTime = scanner.Schedule.RunTime.Format("2006-01-02 15:04:05")
		}
	}

	return pbScanner
}

// GetNmapProfiles retrieves all available Nmap profiles
func (s *ScannerService) GetNmapProfiles(ctx context.Context, req *pb.GetNmapProfilesRequest) (*pb.GetNmapProfilesResponse, error) {
	logger.DebugContext(ctx, "API Service: Getting Nmap profiles")

	profiles, err := s.service.GetNmapProfiles(ctx)
	if err != nil {
		return &pb.GetNmapProfilesResponse{
			Success:      false,
			ErrorMessage: err.Error(),
		}, err
	}

	// Convert domain profiles to protobuf profiles
	var pbProfiles []*pb.NmapProfile
	for _, profile := range profiles {
		pbProfile := &pb.NmapProfile{
			Id:        profile.ID, // Fixed: Use int64 directly, not strconv.FormatInt
			Name:      profile.Name,
			Arguments: profile.Arguments,
			IsDefault: profile.IsDefault,
			IsSystem:  profile.IsSystem,
			CreatedAt: profile.CreatedAt.Format("2006-01-02 15:04:05"),
		}

		if profile.Description != nil {
			pbProfile.Description = *profile.Description
		}

		if profile.CreatedBy != nil {
			pbProfile.CreatedBy = *profile.CreatedBy
		}

		if profile.UpdatedAt != nil {
			pbProfile.UpdatedAt = profile.UpdatedAt.Format("2006-01-02 15:04:05")
		}

		// Removed: pbProfile.CustomSwitches (field doesn't exist in protobuf)

		pbProfiles = append(pbProfiles, pbProfile)
	}

	return &pb.GetNmapProfilesResponse{
		Success:  true,
		Profiles: pbProfiles,
	}, nil
}

// GetNmapProfile retrieves a specific Nmap profile by ID
func (s *ScannerService) GetNmapProfile(ctx context.Context, req *pb.GetNmapProfileRequest) (*pb.GetNmapProfileResponse, error) {
	logger.DebugContext(ctx, "API Service: Getting Nmap profile with ID: %d", req.GetId())

	// Fixed: Use int64 directly, no need to parse
	profileID := req.GetId()

	profile, err := s.service.GetNmapProfileByID(ctx, profileID)
	if err != nil {
		return &pb.GetNmapProfileResponse{
			Success:      false,
			ErrorMessage: err.Error(),
		}, err
	}

	if profile == nil {
		return &pb.GetNmapProfileResponse{
			Success:      false,
			ErrorMessage: "Nmap profile not found",
		}, fmt.Errorf("nmap profile not found")
	}

	// Convert domain profile to protobuf profile
	pbProfile := &pb.NmapProfile{
		Id:        profile.ID, // Fixed: Use int64 directly, not strconv.FormatInt
		Name:      profile.Name,
		Arguments: profile.Arguments,
		IsDefault: profile.IsDefault,
		IsSystem:  profile.IsSystem,
		CreatedAt: profile.CreatedAt.Format("2006-01-02 15:04:05"),
	}

	if profile.Description != nil {
		pbProfile.Description = *profile.Description
	}

	if profile.CreatedBy != nil {
		pbProfile.CreatedBy = *profile.CreatedBy
	}

	if profile.UpdatedAt != nil {
		pbProfile.UpdatedAt = profile.UpdatedAt.Format("2006-01-02 15:04:05")
	}

	// Removed: pbProfile.CustomSwitches (field doesn't exist in protobuf)

	return &pb.GetNmapProfileResponse{
		Success: true,
		Profile: pbProfile,
	}, nil
}
