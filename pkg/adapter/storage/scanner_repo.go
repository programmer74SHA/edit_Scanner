package storage

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanner/domain"
	scannerDomain "gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanner/domain"
	scannerPort "gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanner/port" // Add this import
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/adapter/storage/types"
	appCtx "gitlab.apk-group.net/siem/backend/asset-discovery/pkg/context"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/query"
	"gorm.io/gorm"
)

// Updated struct definition to include switch repository
type scannerRepo struct {
	db         *gorm.DB
	switchRepo *SwitchRepository
}

// NewScannerRepository creates a new unified scanner repository
func NewScannerRepository(db *gorm.DB, switchRepo *SwitchRepository) scannerPort.Repo {
	return &scannerRepo{
		db:         db,
		switchRepo: switchRepo,
	}
}

// UpdateAllEnabled implements port.Repo by updating the status of all scanners
func (r *scannerRepo) UpdateAllEnabled(ctx context.Context, status bool) (int, error) {
	log.Printf("Repository: Updating all scanners to status=%v", status)

	// Get the DB from context or use the repo's DB
	db := appCtx.GetDB(ctx)
	if db == nil {
		db = r.db
	}

	// Using GORM to update all non-deleted scanners at once
	now := time.Now()
	result := db.Table("scanners").
		Where("deleted_at IS NULL"). // Only update non-deleted scanners
		Updates(map[string]interface{}{
			"status":     status,
			"updated_at": now,
		})

	if result.Error != nil {
		log.Printf("Repository: Error updating all scanners: %v", result.Error)
		return 0, result.Error
	}

	log.Printf("Repository: Successfully updated %d scanners", result.RowsAffected)
	return int(result.RowsAffected), nil
}

func (r *scannerRepo) Create(ctx context.Context, scanner domain.ScannerDomain) (int64, error) {
	log.Printf("Repository: Creating scanner: %+v", scanner)

	// Get the DB from context or use the repo's DB
	db := appCtx.GetDB(ctx)
	if db == nil {
		db = r.db
	}

	var scannerID int64

	// Use transaction to ensure data consistency
	err := db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Convert domain model to storage model
		storageScanner := &types.Scanner{
			Name:      scanner.Name,
			ScanType:  scanner.ScanType,
			Status:    scanner.Status,
			CreatedAt: scanner.CreatedAt,
			UpdatedAt: &scanner.UpdatedAt,
		}

		if scanner.UserID != "" {
			storageScanner.UserID = &scanner.UserID
		}

		// Use a map to ensure all fields are included in the INSERT
		scannerValues := map[string]interface{}{
			"name":       scanner.Name,
			"scan_type":  scanner.ScanType,
			"status":     scanner.Status,
			"created_at": scanner.CreatedAt,
			"updated_at": scanner.UpdatedAt,
		}

		if scanner.UserID != "" {
			scannerValues["user_id"] = scanner.UserID
		}

		// Create using the map to ensure all fields are set
		if err := tx.Table("scanners").Create(scannerValues).Error; err != nil {
			log.Printf("Repository: Error creating scanner: %v", err)
			return err
		}

		// Get the last inserted ID
		var lastID int64
		if err := tx.Raw("SELECT LAST_INSERT_ID()").Scan(&lastID).Error; err != nil {
			log.Printf("Repository: Error getting last insert ID: %v", err)
			return err
		}

		scannerID = lastID

		// Handle metadata based on scanner type - DON'T RETURN EARLY
		switch scanner.ScanType {
		case domain.ScannerTypeNmap:
			if err := r.createNmapDataTx(tx, scannerID, scanner); err != nil {
				return err
			}
		case domain.ScannerTypeVCenter:
			if err := r.createVcenterDataTx(tx, scannerID, scanner); err != nil {
				return err
			}
		case domain.ScannerTypeDomain:
			if err := r.createDomainDataTx(tx, scannerID, scanner); err != nil {
				return err
			}
		case domain.ScannerTypeFirewall:
			if err := r.createFirewallDataTx(tx, scannerID, scanner); err != nil {
				return err
			}
		case domain.ScannerTypeSwitch:
			if err := r.createSwitchDataTx(tx, scannerID, scanner); err != nil {
				return err
			}
		case domain.ScannerTypeNessus:
			if err := r.createNessusDataTx(tx, scannerID, scanner); err != nil {
				return err
			}
		}

		// Handle schedule data if it exists - NOW THIS WILL BE REACHED!
		if scanner.Schedule != nil {
			if err := r.createScheduleTx(tx, scannerID, scanner.Schedule); err != nil {
				log.Printf("Repository: Error creating schedule: %v", err)
				return err
			}
		}

		return nil
	})

	if err != nil {
		return 0, err
	}

	return scannerID, nil
}

// CreateNmapProfile creates a new Nmap profile in the database
func (r *scannerRepo) CreateNmapProfile(ctx context.Context, profile domain.NmapProfile) (int64, error) {
	log.Printf("Repository: Creating Nmap profile: %s", profile.Name)

	// Convert domain profile to storage profile
	storageProfile := &types.NmapProfile{
		Name:        profile.Name,
		Description: profile.Description,
		Arguments:   types.NmapArguments(profile.Arguments),
		IsDefault:   profile.IsDefault,
		IsSystem:    profile.IsSystem,
		CreatedBy:   profile.CreatedBy,
		CreatedAt:   profile.CreatedAt,
	}

	if profile.UpdatedAt != nil {
		storageProfile.UpdatedAt = profile.UpdatedAt
	}

	// Create the profile in the database
	if err := r.db.WithContext(ctx).Table("nmap_profiles").Create(storageProfile).Error; err != nil {
		log.Printf("Repository: Error creating Nmap profile: %v", err)
		return 0, err
	}

	log.Printf("Repository: Successfully created Nmap profile with ID: %d", storageProfile.ID)
	return storageProfile.ID, nil
}

// applyIDCondition applies ID-based conditions to a query based on exclude flag
func applyIDCondition(query *gorm.DB, ids []int64, exclude bool) *gorm.DB {
	if len(ids) == 0 {
		return query
	}

	if exclude {
		// Exclude specified IDs
		return query.Where("id NOT IN ?", ids)
	}
	// Include only specified IDs
	return query.Where("id IN ?", ids)
}

// applyScannerFiltersToQuery applies filter conditions to a query
func applyScannerFiltersToQuery(query *gorm.DB, filters *domain.ScannerFilter) *gorm.DB {
	if filters == nil {
		return query
	}

	if filters.Name != "" {
		query = query.Where("name LIKE ?", "%"+filters.Name+"%")
	}

	if filters.ScanType != "" {
		query = query.Where("scan_type = ?", filters.ScanType)
	}

	// Only apply status filter if explicitly provided
	if filters.Status != nil {
		query = query.Where("status = ?", *filters.Status)
	}

	return query
}

// DeleteBatch is a unified method that handles all scanner deletion scenarios
func (r *scannerRepo) DeleteBatch(ctx context.Context, params domain.DeleteParams) (int, error) {
	currentTime := time.Now()
	query := r.db.WithContext(ctx).Table("scanners")

	// Always only delete non-deleted scanners
	query = query.Where("deleted_at IS NULL")

	// Case 1: Single scanner deletion by ID
	if params.ID != nil {
		result := query.Where("id = ?", *params.ID).
			Update("deleted_at", currentTime)

		if result.Error != nil {
			return 0, result.Error
		}

		return int(result.RowsAffected), nil
	}

	// Use transaction for all other cases to ensure atomicity
	var affectedRows int64
	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		txQuery := tx.Table("scanners").Where("deleted_at IS NULL")

		// Apply filters if they exist
		txQuery = applyScannerFiltersToQuery(txQuery, params.Filters)

		// Apply ID conditions if IDs exist
		if len(params.IDs) > 0 {
			txQuery = applyIDCondition(txQuery, params.IDs, params.Exclude)
		}

		result := txQuery.Update("deleted_at", currentTime)
		if result.Error != nil {
			return result.Error
		}

		affectedRows = result.RowsAffected
		return nil
	})

	if err != nil {
		return 0, err
	}

	return int(affectedRows), nil
}

// Updated List method to handle schedule types and nullable RunTime
func (r *scannerRepo) List(ctx context.Context, filter domain.ScannerFilter, pagination domain.Pagination) ([]domain.ScannerDomain, int, error) {
	log.Printf("Repository: Listing scanners with filter: %+v, pagination: %+v", filter, pagination)

	// Use the query package to handle filtering, sorting, and pagination
	queryBuilder := query.NewGormQueryBuilder(r.db.Table("scanners").WithContext(ctx).Where("deleted_at IS NULL"))

	// Apply filters
	if filter.Name != "" {
		queryBuilder.AddFilter("name LIKE ?", "%"+filter.Name+"%")
	}

	if filter.ScanType != "" {
		queryBuilder.AddFilter("scan_type = ?", filter.ScanType)
	}

	// Only apply status filter if it's explicitly provided
	if filter.Status != nil {
		queryBuilder.AddFilter("status = ?", *filter.Status)
		log.Printf("Repository: Applying status filter: %v", *filter.Status)
	} else {
		log.Printf("Repository: No status filter provided, fetching all scanners regardless of status")
	}

	// Get total count before applying pagination
	var totalCount int64
	countQuery := queryBuilder.BuildForCount()
	if err := countQuery.Count(&totalCount).Error; err != nil {
		return nil, 0, err
	}

	// Apply sorting
	if pagination.SortField != "" {
		sortOrder := "asc"
		if pagination.SortOrder == "desc" {
			sortOrder = "desc"
		}
		queryBuilder.AddSort(pagination.SortField, sortOrder)
	} else {
		// Default sort by ID ascending
		queryBuilder.AddSort("id", "asc")
	}

	// Apply pagination
	if pagination.Limit > 0 {
		offset := pagination.Page * pagination.Limit
		queryBuilder.SetPagination(pagination.Limit, offset)
	}

	// Execute the query
	var scanners []types.Scanner
	finalQuery := queryBuilder.Build()

	if err := finalQuery.Find(&scanners).Error; err != nil {
		log.Printf("Repository: Error listing scanners: %v", err)
		return nil, 0, err
	}

	// Convert to domain models and load related data
	var result []domain.ScannerDomain
	for _, s := range scanners {
		// Create domain scanner
		scanner := domain.ScannerDomain{
			ID:        s.ID,
			Name:      s.Name,
			ScanType:  s.ScanType,
			Status:    s.Status,
			CreatedAt: s.CreatedAt,
		}

		if s.UserID != nil {
			scanner.UserID = *s.UserID
		}

		if s.UpdatedAt != nil {
			scanner.UpdatedAt = *s.UpdatedAt
		}

		// Load related data for each scanner
		switch scanner.ScanType {
		case domain.ScannerTypeNmap:
			_ = r.LoadNmapData(ctx, &scanner)
		case domain.ScannerTypeVCenter:
			_ = r.LoadVcenterData(ctx, &scanner)
		case domain.ScannerTypeDomain:
			_ = r.LoadDomainData(ctx, &scanner)
		case domain.ScannerTypeFirewall:
			_ = r.LoadFirewallData(ctx, &scanner)
		case domain.ScannerTypeSwitch:
			_ = r.LoadSwitchData(ctx, &scanner)
		case domain.ScannerTypeNessus:
			_ = r.LoadNessusData(ctx, &scanner)
		}

		// Load schedule with schedule type and handle nullable RunTime
		var schedules []types.Schedule
		if err := r.db.WithContext(ctx).Table("schedules").
			Where("scanner_id = ?", scanner.ID).
			Find(&schedules).Error; err == nil && len(schedules) > 0 {

			// Convert storage schedule type to domain schedule type
			scheduleType := domain.ScheduleTypePeriodic // default
			if schedules[0].ScheduleType != "" {
				scheduleType = domain.ScheduleType(schedules[0].ScheduleType)
			}

			// Handle nullable RunTime when converting to domain
			var domainRunTime time.Time
			if schedules[0].RunTime != nil {
				domainRunTime = *schedules[0].RunTime
			} else {
				domainRunTime = time.Time{} // Zero time if NULL
			}

			scanner.Schedule = &domain.Schedule{
				ID:             schedules[0].ID,
				ScannerID:      schedules[0].ScannerID,
				ScheduleType:   scheduleType,
				FrequencyValue: schedules[0].FrequencyValue,
				FrequencyUnit:  schedules[0].FrequencyUnit,
				RunTime:        domainRunTime,
				Month:          schedules[0].Month,
				Week:           schedules[0].Week,
				Day:            schedules[0].Day,
				Hour:           schedules[0].Hour,
				Minute:         schedules[0].Minute,
				CreatedAt:      schedules[0].CreatedAt,
				UpdatedAt:      schedules[0].UpdatedAt,
			}

			// Set NextRunTime if available
			if schedules[0].NextRunTime != nil {
				scanner.Schedule.NextRunTime = schedules[0].NextRunTime
			}
		}

		result = append(result, scanner)
	}

	return result, int(totalCount), nil
}

// Helper method for updating VCenter related data
func (r *scannerRepo) updateVcenterData(db *gorm.DB, scanner domain.ScannerDomain) error {
	// Get existing VCenter metadata
	var vcenterMetadata types.VcenterMetadata
	if err := db.Table("vcenter_metadata").Where("scanner_id = ?", scanner.ID).First(&vcenterMetadata).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// Create new VCenter metadata if it doesn't exist
			return r.createVcenterData(db, scanner.ID, scanner)
		}
		return err
	}

	// Update VCenter metadata
	vcenterMetadata.IP = scanner.IP
	vcenterMetadata.Port = scanner.Port
	vcenterMetadata.Username = scanner.Username
	vcenterMetadata.Password = scanner.Password

	return db.Table("vcenter_metadata").Where("id = ?", vcenterMetadata.ID).Updates(vcenterMetadata).Error
}

// Helper method for updating Domain related data
func (r *scannerRepo) updateDomainData(db *gorm.DB, scanner domain.ScannerDomain) error {
	// Get existing Domain metadata
	var domainMetadata types.DomainMetadata
	if err := db.Table("domain_metadata").Where("scanner_id = ?", scanner.ID).First(&domainMetadata).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// Create new Domain metadata if it doesn't exist
			return r.createDomainData(db, scanner.ID, scanner)
		}
		return err
	}

	// Update Domain metadata
	domainMetadata.IP = scanner.IP
	domainMetadata.Port = scanner.Port
	domainMetadata.Username = scanner.Username
	domainMetadata.Password = scanner.Password
	domainMetadata.Domain = scanner.Domain
	domainMetadata.AuthenticationType = scanner.AuthenticationType
	domainMetadata.Protocol = scanner.Protocol

	return db.Table("domain_metadata").Where("id = ?", domainMetadata.ID).Updates(domainMetadata).Error
}

func (r *scannerRepo) Delete(ctx context.Context, scannerID int64) error {
	log.Printf("Repository: Deleting scanner with ID: %d", scannerID)

	// Get the DB from context or use the repo's DB
	db := appCtx.GetDB(ctx)
	if db == nil {
		db = r.db
	}

	// First, check if the scanner exists at all (regardless of deleted status)
	var scanner types.Scanner
	err := db.Table("scanners").
		Where("id = ?", scannerID).
		First(&scanner).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			log.Printf("Repository: Scanner with ID %d does not exist", scannerID)
			return fmt.Errorf("scanner with ID %d not found", scannerID)
		}
		log.Printf("Repository: Error checking scanner existence: %v", err)
		return err
	}

	// Check if it's already deleted
	if scanner.DeletedAt != nil {
		log.Printf("Repository: Scanner with ID %d is already deleted", scannerID)
		return nil // Success - already deleted
	}

	// Soft delete by updating the deleted_at timestamp
	now := time.Now()
	result := db.Table("scanners").
		Where("id = ?", scannerID).
		Update("deleted_at", now)

	if result.Error != nil {
		log.Printf("Repository: Error deleting scanner: %v", result.Error)
		return result.Error
	}

	log.Printf("Repository: Successfully deleted scanner with ID: %d", scannerID)
	return nil
}

// Helper method for updating Nmap related data
func (r *scannerRepo) updateNmapData(db *gorm.DB, scanner domain.ScannerDomain) error {
	// Get existing Nmap metadata
	var nmapMetadata types.NmapMetadata
	if err := db.Table("nmap_metadata").Where("scanner_id = ?", scanner.ID).First(&nmapMetadata).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// Create new Nmap metadata if it doesn't exist
			return r.createNmapData(db, scanner.ID, scanner)
		}
		return err
	}

	// Update metadata with new target and profile information
	updateMap := map[string]interface{}{
		"target": scanner.Target,
	}

	// With the new approach, we always use profile IDs
	if scanner.NmapProfileID != nil {
		updateMap["profile_id"] = *scanner.NmapProfileID
	}

	// Custom switches are no longer stored in metadata - they're in the profile
	updateMap["custom_switches"] = nil

	if err := db.Table("nmap_metadata").Where("id = ?", nmapMetadata.ID).Updates(updateMap).Error; err != nil {
		return err
	}

	// Remove old target-specific data
	if err := db.Table("nmap_ip_scans").Where("nmap_metadatas_id = ?", nmapMetadata.ID).Delete(&types.NmapIPScan{}).Error; err != nil {
		return err
	}

	if err := db.Table("nmap_network_scans").Where("nmap_metadatas_id = ?", nmapMetadata.ID).Delete(&types.NmapNetworkScan{}).Error; err != nil {
		return err
	}

	if err := db.Table("nmap_range_scans").Where("nmap_metadatas_id = ?", nmapMetadata.ID).Delete(&types.NmapRangeScan{}).Error; err != nil {
		return err
	}

	// Create new target-specific data
	return r.createNmapTargetData(db, nmapMetadata.ID, scanner)
}

// Updated Update method to handle schedule types and nullable RunTime
func (r *scannerRepo) Update(ctx context.Context, scanner domain.ScannerDomain) error {
	log.Printf("Repository: Updating scanner: %+v", scanner)

	// Get the DB from context or use the repo's DB
	db := appCtx.GetDB(ctx)
	if db == nil {
		db = r.db
	}

	// Create a map to ensure all fields, including false values, are included in the update
	updateMap := map[string]interface{}{
		"name":       scanner.Name,
		"scan_type":  scanner.ScanType,
		"status":     scanner.Status,
		"updated_at": scanner.UpdatedAt,
	}

	if scanner.UserID != "" {
		updateMap["user_id"] = scanner.UserID
	}

	// Update the scanner in the database using a map
	result := db.Table("scanners").
		Where("id = ?", scanner.ID).
		Updates(updateMap)

	if result.Error != nil {
		log.Printf("Repository: Error updating scanner: %v", result.Error)
		return result.Error
	}

	if result.RowsAffected == 0 {
		log.Printf("Repository: No rows affected when updating scanner with ID: %d", scanner.ID)
		return fmt.Errorf("scanner with ID %d not found", scanner.ID)
	}

	// Update related data based on scanner type
	var err error
	switch scanner.ScanType {
	case domain.ScannerTypeNmap:
		err = r.updateNmapData(db, scanner)
	case domain.ScannerTypeVCenter:
		err = r.updateVcenterData(db, scanner)
	case domain.ScannerTypeDomain:
		err = r.updateDomainData(db, scanner)
	case domain.ScannerTypeFirewall:
		err = r.updateFirewallData(db, scanner)
	case domain.ScannerTypeSwitch:
		err = r.updateSwitchData(db, scanner)
	case domain.ScannerTypeNessus:
		err = r.updateNessusData(db, scanner)
	}

	if err != nil {
		return err
	}

	// Update schedule if it exists
	if scanner.Schedule != nil {
		err = r.updateSchedule(db, scanner.ID, *scanner.Schedule)
		if err != nil {
			log.Printf("Repository: Error updating schedule: %v", err)
			return err
		}
	}

	log.Printf("Repository: Successfully updated scanner with ID: %d", scanner.ID)
	return nil
}

// Helper method to update or create schedule
func (r *scannerRepo) updateSchedule(db *gorm.DB, scannerID int64, schedule domain.Schedule) error {
	log.Printf("Repository: Updating schedule for scanner ID: %d with type: %s", scannerID, schedule.ScheduleType)

	// Check if schedule exists
	var existingSchedule types.Schedule
	err := db.Table("schedules").Where("scanner_id = ?", scannerID).First(&existingSchedule).Error

	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}

	// Prepare schedule data for update/create - use values provided by service
	scheduleMap := map[string]interface{}{
		"scanner_id":      scannerID,
		"schedule_type":   string(schedule.ScheduleType),
		"frequency_value": schedule.FrequencyValue,
		"frequency_unit":  schedule.FrequencyUnit,
		"month":           schedule.Month,
		"week":            schedule.Week,
		"day":             schedule.Day,
		"hour":            schedule.Hour,
		"minute":          schedule.Minute,
		"updated_at":      time.Now(),
	}

	// Handle RunTime - store exactly as provided by service
	if !schedule.RunTime.IsZero() {
		scheduleMap["run_time"] = schedule.RunTime.Format("2006-01-02 15:04:05")
	} else {
		scheduleMap["run_time"] = nil // Set to NULL
	}

	// Handle NextRunTime - use the value calculated by service
	if schedule.NextRunTime != nil {
		scheduleMap["next_run_time"] = schedule.NextRunTime.Format("2006-01-02 15:04:05")
	} else {
		scheduleMap["next_run_time"] = nil
	}

	if errors.Is(err, gorm.ErrRecordNotFound) {
		// Create new schedule
		scheduleMap["created_at"] = time.Now()
		if err := db.Table("schedules").Create(scheduleMap).Error; err != nil {
			return err
		}
		log.Printf("Repository: Created new schedule for scanner ID: %d", scannerID)
	} else {
		// Update existing schedule
		if err := db.Table("schedules").Where("scanner_id = ?", scannerID).
			Updates(scheduleMap).Error; err != nil {
			return err
		}
		log.Printf("Repository: Updated existing schedule for scanner ID: %d", scannerID)
	}

	return nil
}

// Helper method for creating VCenter related data
func (r *scannerRepo) createVcenterData(db *gorm.DB, scannerID int64, scanner domain.ScannerDomain) error {
	vcenterMetadata := &types.VcenterMetadata{
		ScannerID: scannerID,
		IP:        scanner.IP,
		Port:      scanner.Port,
		Username:  scanner.Username,
		Password:  scanner.Password,
	}

	return db.Table("vcenter_metadata").Create(vcenterMetadata).Error
}

// Helper method for creating Domain related data
func (r *scannerRepo) createDomainData(db *gorm.DB, scannerID int64, scanner domain.ScannerDomain) error {
	domainMetadata := &types.DomainMetadata{
		ScannerID:          scannerID,
		IP:                 scanner.IP,
		Port:               scanner.Port,
		Username:           scanner.Username,
		Password:           scanner.Password,
		Domain:             scanner.Domain,
		AuthenticationType: scanner.AuthenticationType,
		Protocol:           scanner.Protocol,
	}

	return db.Table("domain_metadata").Create(domainMetadata).Error
}

// Helper method for creating Nessus related data
func (r *scannerRepo) createNessusData(db *gorm.DB, scannerID int64, scanner domain.ScannerDomain) error {
	nessusMetadata := &types.NessusMetadata{
		ScannerID: scannerID,
		URL:       scanner.Domain,
		Username:  scanner.Username,
		Password:  scanner.Password,
		APIKey:    scanner.ApiKey,
	}

	return db.Table("nessus_metadata").Create(nessusMetadata).Error
}

func (r *scannerRepo) GetByID(ctx context.Context, scannerID int64) (*domain.ScannerDomain, error) {
	log.Printf("Repository: Getting scanner with ID: %d", scannerID)

	var scanner types.Scanner
	err := r.db.Table("scanners").WithContext(ctx).
		Where("id = ?", scannerID).
		First(&scanner).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			log.Printf("Repository: Scanner not found for ID: %d", scannerID)
			return nil, nil
		}
		log.Printf("Repository: Error querying scanner: %v", err)
		return nil, err
	}

	// Convert to domain model
	domainScanner := &domain.ScannerDomain{
		ID:        scanner.ID,
		Name:      scanner.Name,
		ScanType:  scanner.ScanType,
		Status:    scanner.Status,
		CreatedAt: scanner.CreatedAt,
	}

	if scanner.UserID != nil {
		domainScanner.UserID = *scanner.UserID
	}

	if scanner.UpdatedAt != nil {
		domainScanner.UpdatedAt = *scanner.UpdatedAt
	}

	if scanner.DeletedAt != nil {
		domainScanner.DeletedAt = *scanner.DeletedAt
	}

	// Load all related data based on scanner type
	switch domainScanner.ScanType {
	case domain.ScannerTypeNmap:
		if err := r.LoadNmapData(ctx, domainScanner); err != nil {
			return nil, err
		}
	case domain.ScannerTypeVCenter:
		if err := r.LoadVcenterData(ctx, domainScanner); err != nil {
			return nil, err
		}
	case domain.ScannerTypeDomain:
		if err := r.LoadDomainData(ctx, domainScanner); err != nil {
			return nil, err
		}
	case domain.ScannerTypeFirewall:
		if err := r.LoadFirewallData(ctx, domainScanner); err != nil {
			return nil, err
		}
	case domain.ScannerTypeSwitch:
		if err := r.LoadSwitchData(ctx, domainScanner); err != nil {
			return nil, err
		}
	case domain.ScannerTypeNessus:
		if err := r.LoadNessusData(ctx, domainScanner); err != nil {
			return nil, err
		}
	}

	// Load schedule data with schedule type and handle nullable RunTime
	var schedules []types.Schedule
	if err := r.db.WithContext(ctx).Table("schedules").
		Where("scanner_id = ?", scannerID).
		Find(&schedules).Error; err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}

	if len(schedules) > 0 {
		// Convert storage schedule type to domain schedule type
		scheduleType := domain.ScheduleTypePeriodic // default
		if schedules[0].ScheduleType != "" {
			scheduleType = domain.ScheduleType(schedules[0].ScheduleType)
		}

		// Handle nullable RunTime when converting to domain
		var domainRunTime time.Time
		if schedules[0].RunTime != nil {
			domainRunTime = *schedules[0].RunTime
		} else {
			domainRunTime = time.Time{} // Zero time if NULL
		}

		domainScanner.Schedule = &domain.Schedule{
			ID:             schedules[0].ID,
			ScannerID:      schedules[0].ScannerID,
			ScheduleType:   scheduleType,
			FrequencyValue: schedules[0].FrequencyValue,
			FrequencyUnit:  schedules[0].FrequencyUnit,
			RunTime:        domainRunTime,
			Month:          schedules[0].Month,
			Week:           schedules[0].Week,
			Day:            schedules[0].Day,
			Hour:           schedules[0].Hour,
			Minute:         schedules[0].Minute,
			CreatedAt:      schedules[0].CreatedAt,
			UpdatedAt:      schedules[0].UpdatedAt,
		}

		if schedules[0].NextRunTime != nil {
			domainScanner.Schedule.NextRunTime = schedules[0].NextRunTime
		}
	}

	return domainScanner, nil
}

// Helper method to load VCenter related data
func (r *scannerRepo) LoadVcenterData(ctx context.Context, scanner *domain.ScannerDomain) error {
	var vcenterMetadata types.VcenterMetadata
	if err := r.db.WithContext(ctx).Table("vcenter_metadata").
		Where("scanner_id = ?", scanner.ID).
		First(&vcenterMetadata).Error; err != nil {
		return err
	}

	scanner.IP = vcenterMetadata.IP
	scanner.Port = vcenterMetadata.Port
	scanner.Username = vcenterMetadata.Username
	scanner.Password = vcenterMetadata.Password

	return nil
}

// Helper method to load Domain related data
func (r *scannerRepo) LoadDomainData(ctx context.Context, scanner *domain.ScannerDomain) error {
	var domainMetadata types.DomainMetadata
	if err := r.db.WithContext(ctx).Table("domain_metadata").
		Where("scanner_id = ?", scanner.ID).
		First(&domainMetadata).Error; err != nil {
		return err
	}

	scanner.IP = domainMetadata.IP
	scanner.Port = domainMetadata.Port
	scanner.Username = domainMetadata.Username
	scanner.Password = domainMetadata.Password
	scanner.Domain = domainMetadata.Domain
	scanner.AuthenticationType = domainMetadata.AuthenticationType
	scanner.Protocol = domainMetadata.Protocol

	return nil
}

// Helper method to load Nessus related data
func (r *scannerRepo) LoadNessusData(ctx context.Context, scanner *domain.ScannerDomain) error {
	var nessusMetadata types.NessusMetadata
	if err := r.db.WithContext(ctx).Table("nessus_metadata").
		Where("scanner_id = ?", scanner.ID).
		First(&nessusMetadata).Error; err != nil {
		return err
	}

	scanner.Domain = nessusMetadata.URL
	scanner.Username = nessusMetadata.Username
	scanner.Password = nessusMetadata.Password
	scanner.ApiKey = nessusMetadata.APIKey

	if nessusMetadata.URL != "" {
		parsedURL, err := url.Parse(nessusMetadata.URL)
		if err == nil {
			scanner.Protocol = parsedURL.Scheme

			host := parsedURL.Hostname()
			port := parsedURL.Port()

			if host != "" {
				scanner.IP = host
			}

			if port != "" {
				scanner.Port = port
			} else {
				switch strings.ToLower(parsedURL.Scheme) {
				case "https":
					scanner.Port = "443"
				case "http":
					scanner.Port = "80"
				}
			}
		}
	}

	if nessusMetadata.APIKey != "" {
		scanner.AuthenticationType = "api_key"
	} else {
		scanner.AuthenticationType = "username_password"
	}

	return nil
}

// UpdateScannerStatus implements a unified approach to update scanner status based on various criteria
func (r *scannerRepo) UpdateScannerStatus(ctx context.Context, params domain.StatusUpdateParams) (int, error) {
	log.Printf("Repository: Updating scanner status with params: IDs=%v, Filter=%+v, Status=%v, Exclude=%v, UpdateAll=%v",
		params.IDs, params.Filter, params.Status, params.Exclude, params.UpdateAll)

	if len(params.IDs) == 0 && !params.UpdateAll && params.Filter.Name == "" &&
		params.Filter.ScanType == "" && params.Filter.Status == nil {
		log.Printf("Repository: No update criteria provided")
		return 0, nil
	}

	// Get the DB from context or use repo default
	db := appCtx.GetDB(ctx)
	if db == nil {
		db = r.db
	}

	// Start building base query
	query := db.Table("scanners").Where("deleted_at IS NULL")

	// If filter provided, apply it
	if params.Filter.Name != "" {
		query = query.Where("name LIKE ?", "%"+params.Filter.Name+"%")
	}
	if params.Filter.ScanType != "" {
		query = query.Where("UPPER(scan_type) = UPPER(?)", params.Filter.ScanType)
	}
	if params.Filter.Status != nil {
		query = query.Where("status = ?", *params.Filter.Status)
	}

	// Apply exclusion logic
	if params.Exclude {
		var excludedIDs []int64

		if params.UpdateAll || params.Filter.Name != "" || params.Filter.ScanType != "" || params.Filter.Status != nil {
			if err := query.Pluck("id", &excludedIDs).Error; err != nil {
				log.Printf("Repository: Error fetching IDs for exclusion: %v", err)
				return 0, err
			}
		} else {
			excludedIDs = params.IDs
		}

		query = db.Table("scanners").Where("deleted_at IS NULL")

		if len(excludedIDs) > 0 {
			query = query.Where("id NOT IN ?", excludedIDs)
		}
	} else {
		// Not excluding, limit by IDs if provided
		if len(params.IDs) > 0 {
			query = query.Where("id IN ?", params.IDs)
		}
	}

	// Apply status update
	now := time.Now()
	result := query.Updates(map[string]interface{}{
		"status":     params.Status,
		"updated_at": now,
	})

	if result.Error != nil {
		log.Printf("Repository: Error updating scanners: %v", result.Error)
		return 0, result.Error
	}

	log.Printf("Repository: Successfully updated %d scanners", result.RowsAffected)
	return int(result.RowsAffected), nil
}

// Helper method for creating Firewall related data
func (r *scannerRepo) createFirewallData(db *gorm.DB, scannerID int64, scanner domain.ScannerDomain) error {
	firewallMetadata := &types.FirewallMetadata{
		ScannerID: scannerID,
		IP:        scanner.IP,
		Port:      scanner.Port,
		Type:      scanner.Type,
		ApiKey:    scanner.ApiKey,
	}

	return db.Table("firewall_metadata").Create(firewallMetadata).Error
}

// Helper method for updating Firewall related data
func (r *scannerRepo) updateFirewallData(db *gorm.DB, scanner domain.ScannerDomain) error {
	// Get existing Firewall metadata
	var firewallMetadata types.FirewallMetadata
	if err := db.Table("firewall_metadata").Where("scanner_id = ?", scanner.ID).First(&firewallMetadata).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// Create new Firewall metadata if it doesn't exist
			return r.createFirewallData(db, scanner.ID, scanner)
		}
		return err
	}

	// Update Firewall metadata
	firewallMetadata.IP = scanner.IP
	firewallMetadata.Port = scanner.Port
	firewallMetadata.ApiKey = scanner.ApiKey

	return db.Table("firewall_metadata").Where("id = ?", firewallMetadata.ID).Updates(firewallMetadata).Error
}

// Helper method to load Firewall related data
func (r *scannerRepo) LoadFirewallData(ctx context.Context, scanner *domain.ScannerDomain) error {
	var firewallMetadata types.FirewallMetadata
	if err := r.db.WithContext(ctx).Table("firewall_metadata").
		Where("scanner_id = ?", scanner.ID).
		First(&firewallMetadata).Error; err != nil {
		return err
	}

	scanner.IP = firewallMetadata.IP
	scanner.Port = firewallMetadata.Port
	scanner.ApiKey = firewallMetadata.ApiKey
	scanner.Type = firewallMetadata.Type

	return nil
}

// GetNmapProfiles retrieves all available Nmap profiles
func (r *scannerRepo) GetNmapProfiles(ctx context.Context) ([]domain.NmapProfile, error) {
	log.Printf("Repository: Getting all Nmap profiles")

	var profiles []types.NmapProfile
	err := r.db.WithContext(ctx).Table("nmap_profiles").
		Order("is_default DESC, name ASC").
		Find(&profiles).Error

	if err != nil {
		log.Printf("Repository: Error retrieving Nmap profiles: %v", err)
		return nil, err
	}

	// Convert to domain models
	var result []domain.NmapProfile
	for _, p := range profiles {
		profile := domain.NmapProfile{
			ID:          p.ID,
			Name:        p.Name,
			Description: p.Description,
			Arguments:   []string(p.Arguments),
			IsDefault:   p.IsDefault,
			IsSystem:    p.IsSystem,
			CreatedBy:   p.CreatedBy,
			CreatedAt:   p.CreatedAt,
		}

		if p.UpdatedAt != nil {
			profile.UpdatedAt = p.UpdatedAt
		}

		result = append(result, profile)
	}

	return result, nil
}

// GetNmapProfileByID retrieves a specific Nmap profile by ID
func (r *scannerRepo) GetNmapProfileByID(ctx context.Context, profileID int64) (*domain.NmapProfile, error) {
	log.Printf("Repository: Getting Nmap profile with ID: %d", profileID)

	var profile types.NmapProfile
	err := r.db.WithContext(ctx).Table("nmap_profiles").
		Where("id = ?", profileID).
		First(&profile).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		log.Printf("Repository: Error retrieving Nmap profile: %v", err)
		return nil, err
	}

	// Convert to domain model
	result := &domain.NmapProfile{
		ID:          profile.ID,
		Name:        profile.Name,
		Description: profile.Description,
		Arguments:   []string(profile.Arguments),
		IsDefault:   profile.IsDefault,
		IsSystem:    profile.IsSystem,
		CreatedBy:   profile.CreatedBy,
		CreatedAt:   profile.CreatedAt,
	}

	if profile.UpdatedAt != nil {
		result.UpdatedAt = profile.UpdatedAt
	}

	return result, nil
}

// GetDefaultNmapProfile retrieves the default Nmap profile
func (r *scannerRepo) GetDefaultNmapProfile(ctx context.Context) (*domain.NmapProfile, error) {
	log.Printf("Repository: Getting default Nmap profile")

	var profile types.NmapProfile
	err := r.db.WithContext(ctx).Table("nmap_profiles").
		Where("is_default = ?", true).
		First(&profile).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		log.Printf("Repository: Error retrieving default Nmap profile: %v", err)
		return nil, err
	}

	// Convert to domain model
	result := &domain.NmapProfile{
		ID:          profile.ID,
		Name:        profile.Name,
		Description: profile.Description,
		Arguments:   []string(profile.Arguments),
		IsDefault:   profile.IsDefault,
		IsSystem:    profile.IsSystem,
		CreatedBy:   profile.CreatedBy,
		CreatedAt:   profile.CreatedAt,
	}

	if profile.UpdatedAt != nil {
		result.UpdatedAt = profile.UpdatedAt
	}

	return result, nil
}

func (r *scannerRepo) createNmapData(db *gorm.DB, scannerID int64, scanner domain.ScannerDomain) error {
	log.Printf("Repository: Creating Nmap data for scanner ID: %d", scannerID)

	// With the new approach, all NMAP scanners should have a profile ID
	// Custom scanners now have their custom switches stored in a dedicated profile
	profileID := int64(1) // Default fallback
	if scanner.NmapProfileID != nil {
		profileID = *scanner.NmapProfileID

		// Validate that the profile exists
		var profileExists int64
		if err := db.Table("nmap_profiles").Where("id = ?", profileID).Count(&profileExists).Error; err != nil {
			return fmt.Errorf("error checking profile existence: %v", err)
		}
		if profileExists == 0 {
			return fmt.Errorf("nmap profile with ID %d does not exist", profileID)
		}
	} else {
		// Get the default profile ID if no profile is specified
		var defaultProfile types.NmapProfile
		if err := db.Table("nmap_profiles").Where("is_default = ?", true).First(&defaultProfile).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				log.Printf("Repository: No default profile found, using fallback profile ID 1")
			} else {
				return fmt.Errorf("error finding default profile: %v", err)
			}
		} else {
			profileID = defaultProfile.ID
		}
	}

	log.Printf("Repository: Using profile ID %d for scanner %d", profileID, scannerID)

	nmapMetadata := &types.NmapMetadata{
		ScannerID:      scannerID,
		ProfileID:      &profileID,
		Target:         scanner.Target,
		CustomSwitches: nil, // Always nil now since switches are in the profile
	}

	if err := db.Table("nmap_metadata").Create(nmapMetadata).Error; err != nil {
		return fmt.Errorf("error creating nmap metadata: %v", err)
	}

	metadataID := nmapMetadata.ID

	// Create target-specific data
	return r.createNmapTargetData(db, metadataID, scanner)
}

func (r *scannerRepo) LoadNmapData(ctx context.Context, scanner *domain.ScannerDomain) error {
	log.Printf("Repository: Loading Nmap data for scanner ID: %d", scanner.ID)

	var nmapMetadata types.NmapMetadata
	if err := r.db.WithContext(ctx).Table("nmap_metadata").
		Where("scanner_id = ?", scanner.ID).
		First(&nmapMetadata).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("nmap metadata not found for scanner ID: %d", scanner.ID)
		}
		return fmt.Errorf("error loading nmap metadata: %v", err)
	}

	scanner.Target = nmapMetadata.Target

	// With the new approach, all scanners should have a profile ID
	if nmapMetadata.ProfileID != nil && *nmapMetadata.ProfileID > 0 {
		scanner.NmapProfileID = nmapMetadata.ProfileID

		// Load profile information
		var profile types.NmapProfile
		if err := r.db.WithContext(ctx).Table("nmap_profiles").
			Where("id = ?", *nmapMetadata.ProfileID).
			First(&profile).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				log.Printf("Repository: Warning - Profile ID %d not found for scanner %d", *nmapMetadata.ProfileID, scanner.ID)
				// Don't fail the entire operation, just log the warning
			} else {
				return fmt.Errorf("error loading nmap profile: %v", err)
			}
		} else {
			scanner.NmapProfile = &domain.NmapProfile{
				ID:          profile.ID,
				Name:        profile.Name,
				Description: profile.Description,
				Arguments:   []string(profile.Arguments),
				IsDefault:   profile.IsDefault,
				IsSystem:    profile.IsSystem,
				CreatedBy:   profile.CreatedBy,
				CreatedAt:   profile.CreatedAt,
			}

			if profile.UpdatedAt != nil {
				scanner.NmapProfile.UpdatedAt = profile.UpdatedAt
			}

			// Determine scanner type based on profile name
			// If it's a custom profile (created for custom switches), mark it as custom type
			if strings.HasPrefix(profile.Name, "Custom - ") {
				scanner.Type = "custom"
				// For backward compatibility, also populate CustomSwitches field
				// by joining the profile arguments
				scanner.CustomSwitches = strings.Join([]string(profile.Arguments), " ")
				log.Printf("Repository: Loaded custom scanner with profile: %s", profile.Name)
			} else {
				scanner.Type = "profile"
				scanner.CustomSwitches = ""
				log.Printf("Repository: Loaded profile scanner with profile: %s", profile.Name)
			}
		}
	} else {
		// Fallback - treat as profile-based scanner
		scanner.Type = "profile"
		scanner.CustomSwitches = ""
		scanner.NmapProfileID = nil
		scanner.NmapProfile = nil
		log.Printf("Repository: No profile ID found, treating as profile scanner")
	}

	// Load target-specific data
	return r.loadNmapTargetData(ctx, scanner, nmapMetadata.ID)
}

// createNmapTargetData creates target-specific data for nmap scanners
func (r *scannerRepo) createNmapTargetData(db *gorm.DB, metadataID int64, scanner domain.ScannerDomain) error {
	switch scanner.Target {
	case "IP":
		if scanner.IP == "" {
			return fmt.Errorf("IP address is required for IP target type")
		}
		ipScan := &types.NmapIPScan{
			NmapMetadatasID: metadataID,
			IP:              scanner.IP,
		}
		if err := db.Table("nmap_ip_scans").Create(ipScan).Error; err != nil {
			return fmt.Errorf("error creating nmap IP scan: %v", err)
		}

	case "Network":
		if scanner.IP == "" || scanner.Subnet == 0 {
			return fmt.Errorf("IP address and subnet are required for Network target type")
		}
		networkScan := &types.NmapNetworkScan{
			NmapMetadatasID: metadataID,
			IP:              scanner.IP,
			Subnet:          scanner.Subnet,
		}
		if err := db.Table("nmap_network_scans").Create(networkScan).Error; err != nil {
			return fmt.Errorf("error creating nmap network scan: %v", err)
		}

	case "Range":
		if scanner.StartIP == "" || scanner.EndIP == "" {
			return fmt.Errorf("start IP and end IP are required for Range target type")
		}
		rangeScan := &types.NmapRangeScan{
			NmapMetadatasID: metadataID,
			StartIP:         scanner.StartIP,
			EndIP:           scanner.EndIP,
		}
		if err := db.Table("nmap_range_scans").Create(rangeScan).Error; err != nil {
			return fmt.Errorf("error creating nmap range scan: %v", err)
		}

	default:
		return fmt.Errorf("unsupported target type: %s", scanner.Target)
	}

	log.Printf("Repository: Successfully created Nmap target data for metadata ID: %d", metadataID)
	return nil
}

// loadNmapTargetData loads target-specific data for nmap scanners
func (r *scannerRepo) loadNmapTargetData(ctx context.Context, scanner *domain.ScannerDomain, metadataID int64) error {
	switch scanner.Target {
	case "IP":
		var ipScan types.NmapIPScan
		if err := r.db.WithContext(ctx).Table("nmap_ip_scans").
			Where("nmap_metadatas_id = ?", metadataID).
			First(&ipScan).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return fmt.Errorf("nmap IP scan data not found for metadata ID: %d", metadataID)
			}
			return fmt.Errorf("error loading nmap IP scan: %v", err)
		}
		scanner.IP = ipScan.IP

	case "Network":
		var networkScan types.NmapNetworkScan
		if err := r.db.WithContext(ctx).Table("nmap_network_scans").
			Where("nmap_metadatas_id = ?", metadataID).
			First(&networkScan).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return fmt.Errorf("nmap network scan data not found for metadata ID: %d", metadataID)
			}
			return fmt.Errorf("error loading nmap network scan: %v", err)
		}
		scanner.IP = networkScan.IP
		scanner.Subnet = networkScan.Subnet

	case "Range":
		var rangeScan types.NmapRangeScan
		if err := r.db.WithContext(ctx).Table("nmap_range_scans").
			Where("nmap_metadatas_id = ?", metadataID).
			First(&rangeScan).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return fmt.Errorf("nmap range scan data not found for metadata ID: %d", metadataID)
			}
			return fmt.Errorf("error loading nmap range scan: %v", err)
		}
		scanner.StartIP = rangeScan.StartIP
		scanner.EndIP = rangeScan.EndIP

	default:
		return fmt.Errorf("unsupported target type: %s", scanner.Target)
	}

	log.Printf("Repository: Successfully loaded Nmap target data for scanner ID: %d", scanner.ID)
	return nil
}

// Helper method for creating Switch related data
func (r *scannerRepo) createSwitchData(db *gorm.DB, scannerID int64, scanner domain.ScannerDomain) error {
	// Create asset first
	assetID, err := r.createSwitchAsset(db, scannerID, scanner)
	if err != nil {
		return fmt.Errorf("failed to create switch asset: %w", err)
	}

	// Note: createSwitchAsset already creates the switch_metadata record
	// So we don't need to create it again here
	log.Printf("Switch data created successfully for scanner %d with asset %s", scannerID, assetID.String())

	return nil
}

// Helper method for updating Switch related data
func (r *scannerRepo) updateSwitchData(db *gorm.DB, scanner domain.ScannerDomain) error {
	// Get existing switch metadata using scanner ID
	var switchMetadata types.SwitchMetadata
	err := db.Table("switch_metadata").
		Where("scanner_id = ?", scanner.ID).
		First(&switchMetadata).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// Create new switch data if it doesn't exist
			return r.createSwitchData(db, scanner.ID, scanner)
		}
		return err
	}

	// Update switch metadata
	updateData := map[string]interface{}{
		"username":   scanner.Username,
		"password":   scanner.Password,
		"port":       r.getPortAsInt(scanner.Port),
		"brand":      r.getBrandFromType(scanner.Type),
		"updated_at": time.Now(),
	}

	return db.Table("switch_metadata").Where("id = ?", switchMetadata.ID).Updates(updateData).Error
}

// Helper method for updating Nessus related data
func (r *scannerRepo) updateNessusData(db *gorm.DB, scanner domain.ScannerDomain) error {
	// Get existing Nessus metadata
	var nessusMetadata types.NessusMetadata
	if err := db.Table("nessus_metadata").Where("scanner_id = ?", scanner.ID).First(&nessusMetadata).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// Create new Nessus metadata if it doesn't exist
			return r.createNessusData(db, scanner.ID, scanner)
		}
		return err
	}

	// Update Nessus metadata
	nessusMetadata.URL = scanner.Domain
	nessusMetadata.Username = scanner.Username
	nessusMetadata.Password = scanner.Password
	nessusMetadata.APIKey = scanner.ApiKey

	return db.Table("nessus_metadata").Where("id = ?", nessusMetadata.ID).Updates(nessusMetadata).Error
}

// Helper method to load Switch related data
func (r *scannerRepo) LoadSwitchData(ctx context.Context, scanner *domain.ScannerDomain) error {
	// Load switch metadata using scanner ID
	var switchMetadata types.SwitchMetadata
	if err := r.db.WithContext(ctx).Table("switch_metadata").
		Where("scanner_id = ?", scanner.ID).
		First(&switchMetadata).Error; err != nil {
		return err
	}

	// Load asset data
	var asset types.Assets
	if err := r.db.WithContext(ctx).Table("assets").
		Where("id = ?", switchMetadata.AssetID).
		First(&asset).Error; err != nil {
		return err
	}

	// Load asset IP (management IP)
	var assetIP types.IPs
	if err := r.db.WithContext(ctx).Table("ips").
		Where("asset_id = ?", switchMetadata.AssetID).
		First(&assetIP).Error; err != nil {
		return err
	}

	// Populate scanner fields
	scanner.IP = assetIP.IPAddress // Management IP from asset IPs
	scanner.Port = strconv.Itoa(switchMetadata.Port)
	scanner.Username = switchMetadata.Username
	scanner.Password = switchMetadata.Password
	scanner.Protocol = "SSH" // Default protocol for switches
	scanner.Type = switchMetadata.Brand

	return nil
}

// Create switch asset
func (r *scannerRepo) createSwitchAsset(db *gorm.DB, scannerID int64, scanner domain.ScannerDomain) (uuid.UUID, error) {
	assetID := uuid.New()

	// Create vendor service to handle vendor creation/lookup
	vendorService := NewVendorService(db)

	// Determine vendor name based on scanner type
	vendorName := "Cisco" // Default for switches
	if scanner.Type != "" {
		vendorName = scanner.Type
	}

	// Get or create vendor
	vendorID, err := vendorService.GetOrCreateVendor(vendorName)
	if err != nil {
		return uuid.Nil, fmt.Errorf("failed to get or create vendor: %w", err)
	}

	// Create hostname from IP if not provided
	hostname := fmt.Sprintf("switch-%s", strings.ReplaceAll(scanner.IP, ".", "-"))

	asset := types.Assets{
		ID:          assetID.String(),
		VendorID:    vendorID, // Use the proper vendor ID instead of hardcoding 1
		Name:        scanner.Name,
		Hostname:    hostname,
		Description: fmt.Sprintf("%s switch for scanner: %s", scanner.Type, scanner.Name),
		OSName:      fmt.Sprintf("%s IOS", scanner.Type),
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	if err := db.Table("assets").Create(&asset).Error; err != nil {
		return uuid.Nil, err
	}

	// Create asset IP record
	assetIP := types.IPs{
		ID:         uuid.New().String(),
		AssetID:    assetID.String(),
		IPAddress:  scanner.IP,
		MacAddress: "", // Will be populated during scan
		CreatedAt:  time.Now(),
	}

	if err := db.Table("ips").Create(&assetIP).Error; err != nil {
		return uuid.Nil, err
	}

	// Create switch metadata with scanner ID (updated to use SwitchMetadata)
	switchMetadata := &types.SwitchMetadata{
		ID:        uuid.New().String(),
		ScannerID: scannerID,        // Use the passed scannerID parameter
		AssetID:   assetID.String(), // Link to the created asset
		Username:  scanner.Username,
		Password:  scanner.Password,
		Port:      r.getPortAsInt(scanner.Port),
		Brand:     r.getBrandFromType(scanner.Type),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Use the correct table name for SwitchMetadata
	if err := db.Table("switch_metadata").Create(switchMetadata).Error; err != nil {
		return uuid.Nil, err
	}

	return assetID, nil
}

// Helper methods
func (r *scannerRepo) getPortAsInt(portStr string) int {
	if portStr == "" {
		return 22 // Default SSH port
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return 22
	}
	return port
}

func (r *scannerRepo) getBrandFromType(deviceType string) string {
	switch strings.ToLower(deviceType) {
	case "cisco":
		return "Cisco"
	case "juniper":
		return "Juniper"
	case "huawei":
		return "Huawei"
	case "hp":
		return "HP"
	case "arista":
		return "Arista"
	default:
		return "Cisco" // Default
	}
}

// Transaction-aware helper methods
func (r *scannerRepo) createSwitchDataTx(tx *gorm.DB, scannerID int64, scanner domain.ScannerDomain) error {
	log.Printf("Repository: Creating switch data for scanner ID: %d", scannerID)

	// Create asset first
	assetID, err := r.createSwitchAssetTx(tx, scannerID, scanner)
	if err != nil {
		return fmt.Errorf("failed to create switch asset: %w", err)
	}

	log.Printf("Repository: Successfully created switch data for scanner %d with asset %s", scannerID, assetID.String())
	return nil
}

func (r *scannerRepo) createSwitchAssetTx(tx *gorm.DB, scannerID int64, scanner domain.ScannerDomain) (uuid.UUID, error) {
	assetID := uuid.New()

	// Create vendor service to handle vendor creation/lookup
	vendorService := NewVendorService(tx)

	// Determine vendor name based on scanner type
	vendorName := "Cisco" // Default for switches
	if scanner.Type != "" {
		vendorName = scanner.Type
	}

	// Get or create vendor
	vendorID, err := vendorService.GetOrCreateVendor(vendorName)
	if err != nil {
		return uuid.Nil, fmt.Errorf("failed to get or create vendor: %w", err)
	}

	// Validate required fields
	if scanner.IP == "" {
		return uuid.Nil, fmt.Errorf("IP address is required for switch scanner")
	}
	if scanner.Username == "" {
		return uuid.Nil, fmt.Errorf("username is required for switch scanner")
	}
	if scanner.Password == "" {
		return uuid.Nil, fmt.Errorf("password is required for switch scanner")
	}

	// Create hostname from IP if not provided
	hostname := fmt.Sprintf("switch-%s", strings.ReplaceAll(scanner.IP, ".", "-"))

	asset := types.Assets{
		ID:          assetID.String(),
		VendorID:    vendorID,
		Name:        scanner.Name,
		Hostname:    hostname,
		Description: fmt.Sprintf("%s switch for scanner: %s", scanner.Type, scanner.Name),
		OSName:      fmt.Sprintf("%s IOS", scanner.Type),
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	if err := tx.Table("assets").Create(&asset).Error; err != nil {
		return uuid.Nil, fmt.Errorf("failed to create asset: %w", err)
	}

	// Create asset IP record
	assetIP := types.IPs{
		ID:         uuid.New().String(),
		AssetID:    assetID.String(),
		IPAddress:  scanner.IP,
		MacAddress: "", // Will be populated during scan
		CreatedAt:  time.Now(),
	}

	if err := tx.Table("ips").Create(&assetIP).Error; err != nil {
		return uuid.Nil, fmt.Errorf("failed to create asset IP: %w", err)
	}

	// Create switch metadata
	switchMetadata := &types.SwitchMetadata{
		ID:        uuid.New().String(),
		ScannerID: scannerID,
		AssetID:   assetID.String(),
		Username:  scanner.Username,
		Password:  scanner.Password,
		Port:      r.getPortAsInt(scanner.Port),
		Brand:     r.getBrandFromType(scanner.Type),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if err := tx.Table("switch_metadata").Create(switchMetadata).Error; err != nil {
		return uuid.Nil, fmt.Errorf("failed to create switch metadata: %w", err)
	}

	log.Printf("Repository: Successfully created switch asset %s and metadata for scanner %d", assetID.String(), scannerID)
	return assetID, nil
}

func (r *scannerRepo) createScheduleTx(tx *gorm.DB, scannerID int64, schedule *scannerDomain.Schedule) error {
	log.Printf("Repository: Creating schedule for scanner ID: %d with type: %s", scannerID, schedule.ScheduleType)

	storageSchedule := &types.Schedule{
		ScannerID:      scannerID,
		ScheduleType:   types.ScheduleType(schedule.ScheduleType),
		FrequencyValue: schedule.FrequencyValue,
		FrequencyUnit:  schedule.FrequencyUnit,
		Month:          schedule.Month,
		Week:           schedule.Week,
		Day:            schedule.Day,
		Hour:           schedule.Hour,
		Minute:         schedule.Minute,
		CreatedAt:      schedule.CreatedAt,
	}

	if !schedule.RunTime.IsZero() {
		storageSchedule.RunTime = &schedule.RunTime
	}

	if schedule.NextRunTime != nil {
		storageSchedule.NextRunTime = schedule.NextRunTime
	}

	if schedule.UpdatedAt != nil {
		storageSchedule.UpdatedAt = schedule.UpdatedAt
	}

	return tx.Table("schedules").Create(storageSchedule).Error
}

// Add similar transaction-aware methods for other scanner types
func (r *scannerRepo) createNmapDataTx(tx *gorm.DB, scannerID int64, scanner domain.ScannerDomain) error {
	return r.createNmapData(tx, scannerID, scanner)
}

func (r *scannerRepo) createVcenterDataTx(tx *gorm.DB, scannerID int64, scanner domain.ScannerDomain) error {
	return r.createVcenterData(tx, scannerID, scanner)
}

func (r *scannerRepo) createDomainDataTx(tx *gorm.DB, scannerID int64, scanner domain.ScannerDomain) error {
	return r.createDomainData(tx, scannerID, scanner)
}

func (r *scannerRepo) createFirewallDataTx(tx *gorm.DB, scannerID int64, scanner domain.ScannerDomain) error {
	return r.createFirewallData(tx, scannerID, scanner)
}

func (r *scannerRepo) createNessusDataTx(tx *gorm.DB, scannerID int64, scanner domain.ScannerDomain) error {
	return r.createNessusData(tx, scannerID, scanner)
}

func (r *scannerRepo) CreateSwitchAsset(ctx context.Context, scannerID int64, config scannerDomain.SwitchConfig) (uuid.UUID, error) {
	if r.switchRepo == nil {
		return uuid.Nil, fmt.Errorf("switch repository not available")
	}
	return r.switchRepo.CreateSwitchAsset(ctx, scannerID, config)
}

// GetAssetIDForScanner retrieves the asset ID for a scanner (interface method)
func (r *scannerRepo) GetAssetIDForScanner(ctx context.Context, scannerID int64) (uuid.UUID, error) {
	if r.switchRepo == nil {
		return uuid.Nil, fmt.Errorf("switch repository not available")
	}
	return r.switchRepo.GetAssetIDForScanner(ctx, scannerID)
}

// StoreSwitchScanResult stores switch scan results (interface method)
func (r *scannerRepo) StoreSwitchScanResult(ctx context.Context, result *scannerDomain.SwitchScanResult) error {
	if r.switchRepo == nil {
		return fmt.Errorf("switch repository not available")
	}
	return r.switchRepo.StoreSwitchScanResult(ctx, result)
}

// UpdateAssetWithScanResults updates asset with scan results (interface method)
func (r *scannerRepo) UpdateAssetWithScanResults(ctx context.Context, assetID uuid.UUID, result *scannerDomain.SwitchScanResult) error {
	if r.switchRepo == nil {
		return fmt.Errorf("switch repository not available")
	}
	return r.switchRepo.UpdateAssetWithScanResults(ctx, assetID, result)
}

// LinkAssetToScanJob links an asset to a scan job (interface method)
func (r *scannerRepo) LinkAssetToScanJob(ctx context.Context, assetID uuid.UUID, scanJobID int64) error {
	if r.switchRepo == nil {
		return fmt.Errorf("switch repository not available")
	}
	return r.switchRepo.LinkAssetToScanJob(ctx, assetID, scanJobID)
}

// GetSwitchMetadataByAssetID retrieves switch metadata by asset ID (interface method)
func (r *scannerRepo) GetSwitchMetadataByAssetID(ctx context.Context, assetID uuid.UUID) (*scannerDomain.SwitchMetadata, error) {
	if r.switchRepo == nil {
		return nil, fmt.Errorf("switch repository not available")
	}
	return r.switchRepo.GetSwitchMetadataByAssetID(ctx, assetID)
}

// StoreSwitchMetadata stores switch metadata (interface method)
func (r *scannerRepo) StoreSwitchMetadata(ctx context.Context, metadata *scannerDomain.SwitchMetadata) error {
	if r.switchRepo == nil {
		return fmt.Errorf("switch repository not available")
	}
	return r.switchRepo.StoreSwitchMetadata(ctx, metadata)
}

// UpdateSwitchMetadata updates switch metadata (interface method)
func (r *scannerRepo) UpdateSwitchMetadata(ctx context.Context, metadata *scannerDomain.SwitchMetadata) error {
	if r.switchRepo == nil {
		return fmt.Errorf("switch repository not available")
	}
	return r.switchRepo.UpdateSwitchMetadata(ctx, metadata)
}

// DeleteSwitchDataByAssetID deletes switch data by asset ID (interface method)
func (r *scannerRepo) DeleteSwitchDataByAssetID(ctx context.Context, assetID uuid.UUID) error {
	if r.switchRepo == nil {
		return fmt.Errorf("switch repository not available")
	}
	return r.switchRepo.DeleteSwitchDataByAssetID(ctx, assetID)
}

// StoreInterfaces stores switch interfaces (interface method)
func (r *scannerRepo) StoreInterfaces(ctx context.Context, interfaces []scannerDomain.SwitchInterface, assetID uuid.UUID) error {
	if r.switchRepo == nil {
		return fmt.Errorf("switch repository not available")
	}
	return r.switchRepo.StoreInterfaces(ctx, interfaces, assetID)
}

// StoreVLANs stores switch VLANs (interface method)
func (r *scannerRepo) StoreVLANs(ctx context.Context, vlans []scannerDomain.SwitchVLAN, assetID uuid.UUID) error {
	if r.switchRepo == nil {
		return fmt.Errorf("switch repository not available")
	}
	return r.switchRepo.StoreVLANs(ctx, vlans, assetID)
}

// StoreNeighbors stores switch neighbors (interface method)
func (r *scannerRepo) StoreNeighbors(ctx context.Context, neighbors []scannerDomain.SwitchNeighbor, assetID uuid.UUID) error {
	if r.switchRepo == nil {
		return fmt.Errorf("switch repository not available")
	}
	return r.switchRepo.StoreNeighbors(ctx, neighbors, assetID)
}

// GetSwitchDataByAssetID retrieves switch data by asset ID (interface method)
func (r *scannerRepo) GetSwitchDataByAssetID(ctx context.Context, assetID uuid.UUID) (*scannerDomain.SwitchData, error) {
	if r.switchRepo == nil {
		return nil, fmt.Errorf("switch repository not available")
	}
	return r.switchRepo.GetSwitchDataByAssetID(ctx, assetID)
}
