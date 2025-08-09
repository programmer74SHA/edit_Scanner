package scanner

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	assetDomain "gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/domain"
	assetPort "gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/port"
	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/encrypt"
	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanner/domain"
	scannerPort "gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanner/port"
	scheduler "gitlab.apk-group.net/siem/backend/asset-discovery/internal/scheduler"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/adapter/devices"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/adapter/storage"
	"gorm.io/gorm"
)

var (
	ErrScannerOnCreate     = errors.New("error on creating new scanner")
	ErrScannerOnUpdate     = errors.New("error on updating scanner")
	ErrScannerOnDelete     = errors.New("error on deleting scanner")
	ErrScannerNotFound     = errors.New("scanner not found")
	ErrInvalidScannerInput = errors.New("invalid scanner input")
	ErrScheduleRequired    = errors.New("schedule is required")
)

type scannerService struct {
	repo         scannerPort.Repo // Single unified repository
	firewallRepo *storage.FirewallRepo
	assetRepo    assetPort.Repo
	db           *gorm.DB
	switchRunner *SwitchRunner
}

func NewScannerService(repo scannerPort.Repo, db *gorm.DB) scannerPort.Service {
	service := &scannerService{
		repo:         repo, // This repo now handles all switch operations
		firewallRepo: storage.NewFirewallRepo(db),
		assetRepo:    storage.NewAssetRepo(db),
		db:           db,
	}

	// Initialize switch runner with unified repo
	deviceFactory := devices.NewSwitchDeviceClientFactory()
	cancelManager := NewScanCancelManager()
	service.switchRunner = NewSwitchRunner(repo, deviceFactory, cancelManager)

	return service
}

// calculateNextRunTime calculates the next run time for a schedule based on its type
func (s *scannerService) calculateNextRunTime(schedule domain.Schedule) (nextRunTime time.Time, runTime *time.Time) {
	now := time.Now()

	switch schedule.ScheduleType {
	case domain.ScheduleTypeImmediately:
		// For immediate scans, set next run time to now so they get picked up right away
		nextRunTime = now
		// For immediate schedules, run_time can be NULL since it doesn't have meaning
		runTime = nil
		log.Printf("Service: Immediate schedule - setting next run time to now: %v", nextRunTime)

	case domain.ScheduleTypeRunOnce:
		// For run-once schedules, calculate based on provided time components
		nextRunTime = scheduler.CalculateNextRunTime(schedule, now)
		// For run-once, use the provided RunTime if it's not zero
		if !schedule.RunTime.IsZero() {
			runTime = &schedule.RunTime
		} else {
			runTime = &nextRunTime
		}
		log.Printf("Service: Run-once schedule - calculated next run time: %v", nextRunTime)

	case domain.ScheduleTypePeriodic:
		// For periodic schedules, calculate next occurrence
		nextRunTime = scheduler.CalculateNextRunTime(schedule, now)
		// For periodic, use the provided RunTime if it's not zero, otherwise set to NULL
		if !schedule.RunTime.IsZero() {
			runTime = &schedule.RunTime
		} else {
			runTime = nil // Can be NULL for periodic schedules that don't specify a specific run time
		}
		log.Printf("Service: Periodic schedule - calculated next run time: %v", nextRunTime)

	default:
		// Default to periodic behavior
		log.Printf("Service: Unknown schedule type %s, defaulting to periodic", schedule.ScheduleType)
		schedule.ScheduleType = domain.ScheduleTypePeriodic
		nextRunTime = scheduler.CalculateNextRunTime(schedule, now)
		runTime = nil
	}

	return nextRunTime, runTime
}

// prepareScheduleForPersistence prepares a schedule for database persistence with calculated next run time
func (s *scannerService) prepareScheduleForPersistence(schedule *domain.Schedule, scannerID int64) {
	schedule.ScannerID = scannerID

	// Calculate next run time and runtime
	nextRunTime, runTime := s.calculateNextRunTime(*schedule)

	// Store the calculated values in the schedule for the repository to use
	schedule.NextRunTime = &nextRunTime
	if runTime != nil {
		schedule.RunTime = *runTime
	} else {
		schedule.RunTime = time.Time{} // Zero time will be handled as NULL in repository
	}
}

// createFirewallAsset creates the firewall asset when creating a firewall scanner
func (s *scannerService) createFirewallAsset(ctx context.Context, scanner domain.ScannerDomain) error {
	if scanner.ScanType != domain.ScannerTypeFirewall {
		return nil // Not a firewall scanner, skip asset creation
	}

	log.Printf("Service: Creating firewall asset for scanner: %s (IP: %s)", scanner.Name, scanner.IP)

	// Create asset using asset repository
	hostname := fmt.Sprintf("fortigate-%s", strings.ReplaceAll(scanner.IP, ".", "-"))

	// Create the asset domain object
	assetID := uuid.New()
	asset := assetDomain.AssetDomain{
		ID:          assetID,
		Name:        fmt.Sprintf("FortiGate-%s", scanner.IP),
		Hostname:    hostname,
		Type:        "Firewall Device",
		Description: fmt.Sprintf("FortiGate firewall device for scanner: %s", scanner.Name),
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		AssetIPs:    make([]assetDomain.AssetIP, 0),
	}

	// Add management IP if valid
	if scanner.IP != "" {
		asset.AssetIPs = append(asset.AssetIPs, assetDomain.AssetIP{
			AssetID:    assetID.String(),
			IP:         scanner.IP,
			MACAddress: "", // Empty MAC address for management IP
		})
	}

	// Create the asset
	createdAssetID, err := s.assetRepo.Create(ctx, asset)
	if err != nil {
		log.Printf("Service: Error creating firewall asset: %v", err)
		return fmt.Errorf("failed to create firewall asset: %w", err)
	}

	log.Printf("Service: Successfully created firewall asset with ID: %s for scanner: %s", createdAssetID, scanner.Name)
	return nil
}

// updateFirewallAsset updates the firewall asset when updating a firewall scanner
func (s *scannerService) updateFirewallAsset(ctx context.Context, existingScanner, updatedScanner domain.ScannerDomain) error {
	if updatedScanner.ScanType != domain.ScannerTypeFirewall {
		return nil // Not a firewall scanner, skip asset update
	}

	// Check if IP changed (this would require asset update)
	if existingScanner.IP != updatedScanner.IP {
		log.Printf("Service: Firewall IP changed from %s to %s, updating asset", existingScanner.IP, updatedScanner.IP)

		// For now, we'll just create a new asset. In a more sophisticated implementation,
		// you might want to find and update the existing asset
		if err := s.createFirewallAsset(ctx, updatedScanner); err != nil {
			return err
		}

		log.Printf("Service: Successfully updated firewall asset for scanner: %s", updatedScanner.Name)
	}

	return nil
}

// validateScanner ensures scanner has all required fields based on type and schedule
func (s *scannerService) validateScanner(scanner *domain.ScannerDomain) error {
	// Basic validation for required fields
	if scanner.Name == "" {
		return fmt.Errorf("scanner name is required")
	}

	if scanner.ScanType == "" {
		return fmt.Errorf("scanner type is required")
	}

	// Schedule is required
	if scanner.Schedule == nil {
		return ErrScheduleRequired
	}

	// Set default schedule type if not provided
	if scanner.Schedule.ScheduleType == "" {
		log.Printf("Service: No schedule type provided, defaulting to PERIODIC")
		scanner.Schedule.ScheduleType = domain.ScheduleTypePeriodic
	}

	// Validate scanner configuration based on type
	switch scanner.ScanType {
	case domain.ScannerTypeNmap:
		if err := s.validateNmapScanner(*scanner); err != nil {
			return err
		}

	case domain.ScannerTypeVCenter:
		if err := s.validateVCenterScanner(*scanner); err != nil {
			return err
		}

	case domain.ScannerTypeDomain:
		if err := s.validateDomainScanner(*scanner); err != nil {
			return err
		}

	case domain.ScannerTypeFirewall:
		// Firewall validation is handled in the HTTP layer
		log.Printf("Service: Firewall scanner validation handled in HTTP layer")

	case domain.ScannerTypeSwitch: // Handle both new and legacy types
		if err := s.validateSwitchScanner(scanner); err != nil {
			return err
		}

	case domain.ScannerTypeNessus:
		if err := s.preprocessNessusScanner(scanner); err != nil {
			return err
		}

		if err := s.validateNessusScanner(*scanner); err != nil {
			return err
		}

	default:
		return fmt.Errorf("invalid scanner type: %s", scanner.ScanType)
	}

	// Validate schedule configuration
	if err := s.validateSchedule(*scanner.Schedule); err != nil {
		return err
	}

	return nil
}

// validateNmapScanner validates NMAP-specific configuration
func (s *scannerService) validateNmapScanner(scanner domain.ScannerDomain) error {
	if scanner.Target == "" {
		return fmt.Errorf("NMAP scanner requires target")
	}

	// Determine execution type based on the type field (which should be set by API layer)
	switch scanner.Type {
	case "custom":
		// For custom switches, validate that custom_switches is provided
		if scanner.CustomSwitches == "" {
			return fmt.Errorf("custom_switches is required when using custom mode")
		}

		// Validate the custom switches format
		if err := s.validateCustomSwitches(scanner.CustomSwitches); err != nil {
			return fmt.Errorf("invalid custom switches: %v", err)
		}

		log.Printf("Service: NMAP scanner using custom switches: %s", scanner.CustomSwitches)

	case "profile", "":
		// For profile type (or empty type - default to profile)
		// Validate profile if specified, otherwise ensure default profile exists
		if scanner.NmapProfileID != nil {
			// Validate that the profile exists and is accessible
			profile, err := s.repo.GetNmapProfileByID(context.Background(), *scanner.NmapProfileID)
			if err != nil {
				return fmt.Errorf("error validating NMAP profile: %v", err)
			}
			if profile == nil {
				return fmt.Errorf("NMAP profile with ID %d not found", *scanner.NmapProfileID)
			}
			log.Printf("Service: NMAP scanner using profile: %s (ID: %d)", profile.Name, profile.ID)
		} else {
			// Ensure default profile exists
			defaultProfile, err := s.repo.GetDefaultNmapProfile(context.Background())
			if err != nil {
				return fmt.Errorf("error accessing default NMAP profile: %v", err)
			}
			if defaultProfile == nil {
				return fmt.Errorf("no default NMAP profile found")
			}
			log.Printf("Service: NMAP scanner will use default profile: %s", defaultProfile.Name)
		}

	default:
		return fmt.Errorf("invalid NMAP scanner type: %s. Valid types are: 'profile' or 'custom'", scanner.Type)
	}

	// Validate target-specific fields
	switch scanner.Target {
	case "IP":
		if scanner.IP == "" {
			return fmt.Errorf("NMAP IP scan requires an IP address")
		}
	case "Network":
		if scanner.IP == "" || scanner.Subnet == 0 {
			return fmt.Errorf("NMAP Network scan requires IP and subnet")
		}
		if scanner.Subnet < 1 || scanner.Subnet > 32 {
			return fmt.Errorf("NMAP Network scan subnet must be between 1 and 32")
		}
	case "Range":
		if scanner.StartIP == "" || scanner.EndIP == "" {
			return fmt.Errorf("NMAP Range scan requires start and end IPs")
		}
		// Could add IP format validation here
	default:
		return fmt.Errorf("invalid NMAP target type: %s. Valid types are: IP, Network, Range", scanner.Target)
	}

	return nil
}

// validateCustomSwitches validates custom nmap switches
func (s *scannerService) validateCustomSwitches(switches string) error {
	if switches == "" {
		return fmt.Errorf("custom switches cannot be empty")
	}

	// Split switches by spaces to get individual arguments
	args := strings.Fields(switches)
	if len(args) == 0 {
		return fmt.Errorf("custom switches cannot be empty")
	}

	// Basic validation - check for prohibited arguments
	prohibitedArgs := []string{
		"-oX", "-oN", "-oG", "-oA", // Output formats (handled by system)
		"--script-unsafe",    // Unsafe scripts
		"--script=*exploit*", // Exploit scripts
		"--script=*dos*",     // DoS scripts
	}

	switchesLower := strings.ToLower(switches)
	for _, prohibited := range prohibitedArgs {
		if strings.Contains(switchesLower, strings.ToLower(prohibited)) {
			return fmt.Errorf("prohibited argument: %s", prohibited)
		}
	}

	// Validate specific patterns
	for i, arg := range args {
		// Check for extremely high max-rate (security concern)
		if strings.HasPrefix(arg, "--max-rate=") {
			rateStr := strings.TrimPrefix(arg, "--max-rate=")
			if rate, err := strconv.Atoi(rateStr); err == nil && rate > 10000 {
				return fmt.Errorf("max-rate too high: %d (maximum allowed: 10000)", rate)
			}
		}

		// Check timing templates
		if strings.HasPrefix(arg, "-T") && len(arg) == 3 {
			timing := arg[2:]
			if timing < "0" || timing > "5" {
				return fmt.Errorf("invalid timing template: %s (valid range: 0-5)", timing)
			}
		}

		// Check port specifications
		if arg == "-p" && i+1 < len(args) {
			if err := s.validatePortRange(args[i+1]); err != nil {
				return fmt.Errorf("invalid port range: %v", err)
			}
		}
	}

	return nil
}

// validateVCenterScanner validates VCenter-specific configuration
func (s *scannerService) validateVCenterScanner(scanner domain.ScannerDomain) error {
	if scanner.IP == "" {
		return fmt.Errorf("VCenter scanner requires IP address")
	}
	if scanner.Port == "" {
		return fmt.Errorf("VCenter scanner requires port")
	}
	if scanner.Username == "" {
		return fmt.Errorf("VCenter scanner requires username")
	}
	if scanner.Password == "" {
		return fmt.Errorf("VCenter scanner requires password")
	}
	return nil
}

// validateDomainScanner validates Domain-specific configuration
func (s *scannerService) validateDomainScanner(scanner domain.ScannerDomain) error {
	if scanner.IP == "" {
		return fmt.Errorf("Domain scanner requires IP address")
	}
	if scanner.Port == "" {
		return fmt.Errorf("Domain scanner requires port")
	}
	if scanner.Username == "" {
		return fmt.Errorf("Domain scanner requires username")
	}
	if scanner.Password == "" {
		return fmt.Errorf("Domain scanner requires password")
	}
	if scanner.Domain == "" {
		return fmt.Errorf("Domain scanner requires domain")
	}
	if scanner.AuthenticationType == "" {
		return fmt.Errorf("Domain scanner requires authentication type")
	}
	return nil
}

// validateNessusScanner validates Nessus-specific configuration
func (s *scannerService) validateNessusScanner(scanner domain.ScannerDomain) error {
	nessusURL := scanner.Domain
	if nessusURL == "" {
		nessusURL = scanner.IP
	}

	if nessusURL == "" {
		return fmt.Errorf("Nessus scanner requires URL (domain field) or IP address")
	}

	// Validate authentication method - either API key or username/password
	if scanner.ApiKey == "" && (scanner.Username == "" || scanner.Password == "") {
		return fmt.Errorf("Nessus scanner requires either API key or username/password")
	}

	return nil
}

// validateSchedule validates schedule configuration based on schedule type
func (s *scannerService) validateSchedule(schedule domain.Schedule) error {
	// Validate schedule type
	switch schedule.ScheduleType {
	case domain.ScheduleTypePeriodic:
		// Periodic schedules require frequency settings
		if schedule.FrequencyValue <= 0 || schedule.FrequencyUnit == "" {
			return fmt.Errorf("periodic schedule requires frequency value and unit")
		}

		// Validate frequency unit
		validUnits := []string{"minute", "hour", "day", "week", "month"}
		isValidUnit := false
		for _, unit := range validUnits {
			if schedule.FrequencyUnit == unit {
				isValidUnit = true
				break
			}
		}
		if !isValidUnit {
			return fmt.Errorf("invalid frequency unit: %s. Valid units are: minute, hour, day, week, month", schedule.FrequencyUnit)
		}

	case domain.ScheduleTypeRunOnce:
		// Run-once schedules should have either a RunTime or specific time components
		hasRunTime := !schedule.RunTime.IsZero()
		hasTimeComponents := schedule.Hour >= 0 && schedule.Minute >= 0

		if !hasRunTime && !hasTimeComponents {
			return fmt.Errorf("run-once schedule requires either run_time or specific hour/minute")
		}

	case domain.ScheduleTypeImmediately:
		// Immediate schedules don't require any additional validation
		log.Printf("Immediate schedule validated - no additional requirements")

	default:
		return fmt.Errorf("invalid schedule type: %s. Valid types are: PERIODIC, RUN_ONCE, IMMEDIATELY", schedule.ScheduleType)
	}

	// Additional time validation for schedules that specify time components
	if schedule.Hour >= 0 && (schedule.Hour < 0 || schedule.Hour > 23) {
		return fmt.Errorf("invalid hour value: %d. Valid range is 0-23", schedule.Hour)
	}

	if schedule.Minute >= 0 && (schedule.Minute < 0 || schedule.Minute > 59) {
		return fmt.Errorf("invalid minute value: %d. Valid range is 0-59", schedule.Minute)
	}

	if schedule.Day > 0 && (schedule.Day < 1 || schedule.Day > 7) {
		return fmt.Errorf("invalid day value: %d. Valid range is 1-7", schedule.Day)
	}

	if schedule.Week > 0 && (schedule.Week < 1 || schedule.Week > 52) {
		return fmt.Errorf("invalid week value: %d. Valid range is 1-52", schedule.Week)
	}

	if schedule.Month > 0 && (schedule.Month < 1 || schedule.Month > 12) {
		return fmt.Errorf("invalid month value: %d. Valid range is 1-12", schedule.Month)
	}

	return nil
}

func (s *scannerService) CreateScanner(ctx context.Context, scanner domain.ScannerDomain) (int64, error) {
	log.Printf("Service: Creating scanner: %+v", scanner)

	// Handle NMAP scanner configuration based on profile_id and custom_switches
	if scanner.ScanType == domain.ScannerTypeNmap {
		if scanner.Type == "custom" && scanner.CustomSwitches != "" {
			// Create a custom profile for this scanner
			customProfile, err := s.createCustomNmapProfile(ctx, scanner.Name, scanner.CustomSwitches)
			if err != nil {
				log.Printf("Service: Error creating custom profile: %v", err)
				return 0, fmt.Errorf("failed to create custom profile: %w", err)
			}

			// Set the scanner to use the new custom profile
			scanner.Type = "profile" // Change to profile type
			scanner.NmapProfileID = &customProfile.ID
			scanner.NmapProfile = customProfile
			scanner.CustomSwitches = "" // Clear custom switches since they're now in the profile

			log.Printf("Service: Created custom profile with ID: %d for scanner: %s", customProfile.ID, scanner.Name)
		} else {
			// Existing profile logic remains unchanged
			if err := s.ensureNmapProfileLoaded(ctx, &scanner); err != nil {
				log.Printf("Service: Error ensuring Nmap profile: %v", err)
				return 0, ErrInvalidScannerInput
			}
		}
	}

	// Rest of the existing CreateScanner logic remains unchanged...
	// Validate scanner (includes name, type, schedule checks, and profile validation)
	if err := s.validateScanner(&scanner); err != nil {
		log.Printf("Service: Scanner validation failed: %v", err)
		if errors.Is(err, ErrScheduleRequired) {
			return 0, ErrScheduleRequired
		}
		return 0, ErrInvalidScannerInput
	}

	// Set timestamps
	scanner.CreatedAt = time.Now()
	scanner.UpdatedAt = time.Now()

	// Encrypt passwords for VCenter and Domain scanners
	if scanner.ScanType == domain.ScannerTypeVCenter || scanner.ScanType == domain.ScannerTypeDomain {
		encryptedPassword, err := encrypt.EncryptPassword(scanner.Password)
		if err != nil {
			log.Printf("Service: Error encrypting password: %v", err)
			return 0, ErrScannerOnCreate
		}
		scanner.Password = encryptedPassword
	}

	// Prepare schedule for persistence (calculate next run time)
	if scanner.Schedule != nil {
		s.prepareScheduleForPersistence(scanner.Schedule, 0) // scannerID will be set in repository
	}

	// Create scanner in repository
	scannerID, err := s.repo.Create(ctx, scanner)
	if err != nil {
		log.Printf("Service: Error creating scanner: %v", err)
		return 0, ErrScannerOnCreate
	}

	// Create firewall asset if this is a firewall scanner
	if err := s.createFirewallAsset(ctx, scanner); err != nil {
		log.Printf("Service: Error creating firewall asset: %v", err)
		// Note: We could decide whether this should be a fatal error or not
		// For now, we'll continue since the scanner was created successfully
	}

	log.Printf("Service: Successfully created scanner with ID: %d, type: %s, profile: %v",
		scannerID, scanner.ScanType, scanner.NmapProfileID)
	return scannerID, nil
}

func (s *scannerService) GetScannerByID(ctx context.Context, scannerID int64) (*domain.ScannerDomain, error) {
	log.Printf("Service: Getting scanner with ID: %d", scannerID)

	scanner, err := s.repo.GetByID(ctx, scannerID)
	if err != nil {
		log.Printf("Service: Error from repository: %v", err)
		return nil, err
	}

	if scanner == nil {
		log.Printf("Service: Scanner not found for ID: %d", scannerID)
		return nil, ErrScannerNotFound
	}

	// Ensure Nmap profile is loaded if this is an Nmap scanner
	if scanner.ScanType == domain.ScannerTypeNmap {
		if err := s.ensureNmapProfileLoaded(ctx, scanner); err != nil {
			log.Printf("Service: Error loading Nmap profile: %v", err)
			// Don't fail the entire request, just log the error
		}
	}

	// Decrypt password for VCenter and Domain scanners
	if scanner.ScanType == domain.ScannerTypeVCenter || scanner.ScanType == domain.ScannerTypeDomain {
		decryptedPassword, err := encrypt.DecryptPassword(scanner.Password)
		if err != nil {
			log.Printf("Service: Error decrypting password: %v", err)
			return nil, fmt.Errorf("failed to decrypt password: %w", err)
		}
		scanner.Password = decryptedPassword
	}

	log.Printf("Service: Successfully retrieved scanner: %s (Type: %s)", scanner.Name, scanner.ScanType)
	return scanner, nil
}

func (s *scannerService) UpdateScanner(ctx context.Context, scanner domain.ScannerDomain) error {
	log.Printf("Service: Updating scanner with ID: %d", scanner.ID)

	if scanner.ID == 0 {
		log.Printf("Service: Invalid scanner input - missing ID")
		return ErrInvalidScannerInput
	}

	// Get the existing scanner to determine what fields are being updated
	existingScanner, err := s.repo.GetByID(ctx, scanner.ID)
	if err != nil {
		log.Printf("Service: Error retrieving existing scanner: %v", err)
		return err
	}

	if existingScanner == nil {
		log.Printf("Service: Scanner not found for ID: %d", scanner.ID)
		return ErrScannerNotFound
	}

	// Merge the incoming scanner with existing data
	// Only update fields that are provided (non-zero values)
	updatedScanner := s.mergeScanner(*existingScanner, scanner)

	// Handle NMAP scanner updates with custom switches
	if updatedScanner.ScanType == domain.ScannerTypeNmap {
		// Check if we're switching to custom mode or updating custom switches
		if updatedScanner.Type == "custom" && updatedScanner.CustomSwitches != "" {
			// Create a new custom profile for the updated switches
			customProfile, err := s.createCustomNmapProfile(ctx, updatedScanner.Name, updatedScanner.CustomSwitches)
			if err != nil {
				log.Printf("Service: Error creating custom profile during update: %v", err)
				return fmt.Errorf("failed to create custom profile: %w", err)
			}

			// Set the scanner to use the new custom profile
			updatedScanner.Type = "profile" // Change to profile type
			updatedScanner.NmapProfileID = &customProfile.ID
			updatedScanner.NmapProfile = customProfile
			updatedScanner.CustomSwitches = "" // Clear custom switches since they're now in the profile

			log.Printf("Service: Created new custom profile with ID: %d during scanner update", customProfile.ID)
		} else {
			// Ensure Nmap profile is loaded for non-custom updates
			if err := s.ensureNmapProfileLoaded(ctx, &updatedScanner); err != nil {
				log.Printf("Service: Error ensuring Nmap profile during update: %v", err)
				// Don't fail the entire update, just log the error
			}
		}
	}

	// Validate the updated scanner based on its type
	// Note: Firewall-specific validation is handled in HTTP layer
	if err := s.validateScannerForUpdate(updatedScanner); err != nil {
		log.Printf("Service: Scanner validation failed: %v", err)
		return ErrInvalidScannerInput
	}

	// Set timestamps
	updatedScanner.UpdatedAt = time.Now()
	if existingScanner.CreatedAt.IsZero() {
		updatedScanner.CreatedAt = time.Now()
	} else {
		updatedScanner.CreatedAt = existingScanner.CreatedAt
	}

	// Encrypt password if it's being updated for VCenter or Domain scanners
	if updatedScanner.Password != existingScanner.Password &&
		(updatedScanner.ScanType == domain.ScannerTypeVCenter || updatedScanner.ScanType == domain.ScannerTypeDomain) {
		encryptedPassword, err := encrypt.EncryptPassword(updatedScanner.Password)
		if err != nil {
			log.Printf("Service: Error encrypting password: %v", err)
			return ErrScannerOnUpdate
		}
		updatedScanner.Password = encryptedPassword
	}

	// Prepare schedule for persistence (calculate next run time) if schedule is being updated
	if updatedScanner.Schedule != nil {
		s.prepareScheduleForPersistence(updatedScanner.Schedule, scanner.ID)
	}

	// Update firewall asset if this is a firewall scanner and relevant fields changed
	if err := s.updateFirewallAsset(ctx, *existingScanner, updatedScanner); err != nil {
		log.Printf("Service: Error updating firewall asset: %v", err)
		// Note: We could decide whether this should be a fatal error or not
		// For now, we'll continue since the scanner update is the primary operation
	}

	// Update scanner in repository
	err = s.repo.Update(ctx, updatedScanner)
	if err != nil {
		log.Printf("Service: Error updating scanner: %v", err)
		return ErrScannerOnUpdate
	}

	log.Printf("Service: Successfully updated scanner")
	return nil
}

// mergeScanner merges the incoming scanner updates with the existing scanner
func (s *scannerService) mergeScanner(existing, incoming domain.ScannerDomain) domain.ScannerDomain {
	// Start with the existing scanner
	merged := existing

	// Update fields only if they are provided (non-zero values)
	if incoming.Name != "" {
		merged.Name = incoming.Name
	}
	if incoming.ScanType != "" {
		merged.ScanType = incoming.ScanType
	}
	// Status is always updated (even if false)
	merged.Status = incoming.Status

	if incoming.UserID != "" {
		merged.UserID = incoming.UserID
	}

	// Handle type changes for NMAP scanners
	if incoming.Type != "" {
		merged.Type = incoming.Type

		// If changing to custom type, clear profile-related data
		if incoming.Type == "custom" {
			merged.NmapProfileID = nil
			merged.NmapProfile = nil
		} else if incoming.Type == "profile" {
			// If changing to profile type, clear custom switches
			merged.CustomSwitches = ""
		}
	}

	if incoming.Target != "" {
		merged.Target = incoming.Target
	}
	if incoming.IP != "" {
		merged.IP = incoming.IP
	}
	if incoming.Subnet != 0 {
		merged.Subnet = incoming.Subnet
	}
	if incoming.StartIP != "" {
		merged.StartIP = incoming.StartIP
	}
	if incoming.EndIP != "" {
		merged.EndIP = incoming.EndIP
	}
	if incoming.Port != "" {
		merged.Port = incoming.Port
	}
	if incoming.Username != "" {
		merged.Username = incoming.Username
	}
	if incoming.Password != "" {
		merged.Password = incoming.Password
	}
	if incoming.ApiKey != "" {
		merged.ApiKey = incoming.ApiKey
	}
	if incoming.Domain != "" {
		merged.Domain = incoming.Domain
	}
	if incoming.AuthenticationType != "" {
		merged.AuthenticationType = incoming.AuthenticationType
	}
	if incoming.Protocol != "" {
		merged.Protocol = incoming.Protocol
	}

	// Handle custom switches updates
	if incoming.CustomSwitches != "" {
		merged.CustomSwitches = incoming.CustomSwitches
		// If custom switches are provided, switch to custom mode
		if merged.ScanType == domain.ScannerTypeNmap {
			merged.Type = "custom"
			merged.NmapProfileID = nil
			merged.NmapProfile = nil
		}
	}

	// Handle Nmap profile ID updates
	if incoming.NmapProfileID != nil {
		merged.NmapProfileID = incoming.NmapProfileID
		// Clear the existing profile object so it gets reloaded with the new profile
		merged.NmapProfile = nil
		// If switching to profile mode, clear custom switches and set type
		if merged.ScanType == domain.ScannerTypeNmap {
			merged.Type = "profile"
			merged.CustomSwitches = ""
		}
	}

	// Handle schedule updates
	if incoming.Schedule != nil {
		if merged.Schedule == nil {
			merged.Schedule = incoming.Schedule
		} else {
			// Merge schedule fields
			s.mergeSchedule(merged.Schedule, incoming.Schedule)
		}
	}

	return merged
}

// mergeSchedule merges schedule updates
func (s *scannerService) mergeSchedule(existing, incoming *domain.Schedule) {
	if incoming.ScheduleType != "" {
		existing.ScheduleType = incoming.ScheduleType
	}
	if incoming.FrequencyValue > 0 {
		existing.FrequencyValue = incoming.FrequencyValue
	}
	if incoming.FrequencyUnit != "" {
		existing.FrequencyUnit = incoming.FrequencyUnit
	}
	if !incoming.RunTime.IsZero() {
		existing.RunTime = incoming.RunTime
	}
	if incoming.Month > 0 {
		existing.Month = incoming.Month
	}
	if incoming.Week > 0 {
		existing.Week = incoming.Week
	}
	if incoming.Day > 0 {
		existing.Day = incoming.Day
	}
	if incoming.Hour >= 0 {
		existing.Hour = incoming.Hour
	}
	if incoming.Minute >= 0 {
		existing.Minute = incoming.Minute
	}
	existing.UpdatedAt = &[]time.Time{time.Now()}[0]
}

// validateScannerForUpdate validates scanner configuration for updates
func (s *scannerService) validateScannerForUpdate(scanner domain.ScannerDomain) error {
	// Basic validation
	if scanner.Name == "" {
		return fmt.Errorf("scanner name cannot be empty")
	}
	if scanner.ScanType == "" {
		return fmt.Errorf("scanner type cannot be empty")
	}

	// Validate based on scanner type
	switch scanner.ScanType {
	case domain.ScannerTypeNmap:
		if err := s.validateNmapScanner(scanner); err != nil {
			return err
		}

	case domain.ScannerTypeVCenter:
		if err := s.validateVCenterScanner(scanner); err != nil {
			return err
		}

	case domain.ScannerTypeDomain:
		if err := s.validateDomainScanner(scanner); err != nil {
			return err
		}

	case domain.ScannerTypeFirewall:
		// Firewall validation is handled in the HTTP layer
		log.Printf("Service: Firewall scanner validation handled in HTTP layer")

	case domain.ScannerTypeSwitch:
		if err := s.validateSwitchScanner(&scanner); err != nil {
			return err
		}

	case domain.ScannerTypeNessus:
		if err := s.preprocessNessusScanner(&scanner); err != nil {
			return err
		}

		if err := s.validateNessusScanner(scanner); err != nil {
			return err
		}

	default:
		return fmt.Errorf("invalid scanner type: %s", scanner.ScanType)
	}

	// Validate schedule if present
	if scanner.Schedule != nil {
		if err := s.validateSchedule(*scanner.Schedule); err != nil {
			return err
		}
	}

	return nil
}

func (s *scannerService) DeleteScanner(ctx context.Context, scannerID int64) error {
	log.Printf("Service: Deleting scanner with ID: %d", scannerID)

	// Check if scanner exists
	scanner, err := s.repo.GetByID(ctx, scannerID)
	if err != nil {
		log.Printf("Service: Error checking scanner existence: %v", err)
		return err
	}

	if scanner == nil {
		log.Printf("Service: Scanner not found for ID: %d", scannerID)
		return ErrScannerNotFound
	}

	// Delete scanner in repository
	err = s.repo.Delete(ctx, scannerID)
	if err != nil {
		log.Printf("Service: Error deleting scanner: %v", err)
		return ErrScannerOnDelete
	}

	log.Printf("Service: Successfully deleted scanner")
	return nil
}

func (s *scannerService) DeleteScanners(ctx context.Context, ids []string, filter *domain.ScannerFilter, exclude bool) (int, error) {
	log.Printf("Service: Deleting scanners with ids=%v, filter=%v, exclude=%v", ids, filter, exclude)

	// Special case: "All" in IDs list
	if len(ids) == 1 && ids[0] == "All" {
		// If "All" is specified with filters, use the filters to delete specific scanners
		if filter != nil {
			affected_rows, err := s.repo.DeleteBatch(ctx, domain.DeleteParams{
				Filters: filter,
			})
			return checkDeletedScannersErrors(affected_rows, err)
		}

		// Delete all scanners without filters
		affected_rows, err := s.repo.DeleteBatch(ctx, domain.DeleteParams{})
		return checkDeletedScannersErrors(affected_rows, err)
	}

	// Convert string IDs to int64
	scannerIDs := make([]int64, 0, len(ids))
	for _, id := range ids {
		scannerID, err := strconv.ParseInt(id, 10, 64)
		if err != nil {
			continue // Skip invalid IDs
		}
		scannerIDs = append(scannerIDs, scannerID)
	}

	// Case with both filters and IDs
	if filter != nil {
		if exclude {
			// Delete scanners matching filter except those with the specified IDs
			affected_rows, err := s.repo.DeleteBatch(ctx, domain.DeleteParams{
				Filters: filter,
				IDs:     scannerIDs,
				Exclude: true,
			})
			return checkDeletedScannersErrors(affected_rows, err)
		}

		// Delete scanners that match both specific IDs and filter criteria
		affected_rows, err := s.repo.DeleteBatch(ctx, domain.DeleteParams{
			IDs:     scannerIDs,
			Filters: filter,
			Exclude: false,
		})
		return checkDeletedScannersErrors(affected_rows, err)
	}

	// Simple case: either include or exclude specific IDs
	if exclude {
		if len(scannerIDs) == 0 {
			affected_rows, err := s.repo.DeleteBatch(ctx, domain.DeleteParams{})
			return checkDeletedScannersErrors(affected_rows, err)
		}

		affected_rows, err := s.repo.DeleteBatch(ctx, domain.DeleteParams{
			IDs:     scannerIDs,
			Exclude: true,
		})
		return checkDeletedScannersErrors(affected_rows, err)
	}

	if len(scannerIDs) == 0 {
		return 0, nil
	}

	affected_rows, err := s.repo.DeleteBatch(ctx, domain.DeleteParams{
		IDs: scannerIDs,
	})
	return checkDeletedScannersErrors(affected_rows, err)
}

func checkDeletedScannersErrors(affected_rows int, err error) (int, error) {
	if err != nil {
		log.Printf("Service: Error deleting scanners: %v", err)
		return 0, ErrScannerOnDelete
	}

	log.Printf("Service: Successfully deleted %d scanners", affected_rows)
	if affected_rows == 0 {
		return 0, ErrScannerNotFound
	}

	return affected_rows, nil
}

func (s *scannerService) ListScanners(ctx context.Context, filter domain.ScannerFilter, pagination domain.Pagination) ([]domain.ScannerDomain, int, error) {
	log.Printf("Service: Listing scanners with filter: %+v, pagination: %+v", filter, pagination)

	// Get scanners from repository with filtering, sorting, and pagination
	scanners, totalCount, err := s.repo.List(ctx, filter, pagination)
	if err != nil {
		log.Printf("Service: Error listing scanners: %v", err)
		return nil, 0, err
	}

	// Decrypt passwords for VCenter and Domain scanners
	for i := range scanners {
		if scanners[i].ScanType == domain.ScannerTypeVCenter || scanners[i].ScanType == domain.ScannerTypeDomain {
			decryptedPassword, err := encrypt.DecryptPassword(scanners[i].Password)
			if err != nil {
				log.Printf("Service: Error decrypting password: %v", err)
				return nil, 0, fmt.Errorf("failed to decrypt password: %w", err)
			}
			scanners[i].Password = decryptedPassword
		}
	}

	log.Printf("Service: Successfully listed %d scanners (total: %d)", len(scanners), totalCount)
	return scanners, totalCount, nil
}

func (s *scannerService) UpdateScannerStatus(ctx context.Context, filter domain.ScannerFilter, ids []int64, status bool, exclude bool, updateAll bool) (int, error) {
	log.Printf("Service: Updating scanner status with params: filter=%+v, ids=%v, status=%v, exclude=%v, updateAll=%v",
		filter, ids, status, exclude, updateAll)

	// Create params struct for the new unified method
	params := domain.StatusUpdateParams{
		IDs:       ids,
		Filter:    filter,
		Status:    status,
		Exclude:   exclude,
		UpdateAll: updateAll,
	}

	// Call the unified repository method
	return s.repo.UpdateScannerStatus(ctx, params)
}

// GetScannerTargetDetails returns structured target information for scan jobs
func (s *scannerService) GetScannerTargetDetails(scanType, target, ip string, subnet int64, startIP, endIP string) (targetType, targetIP, targetIPStart, targetIPEnd string) {
	switch scanType {
	case "NMAP":
		targetType = target
		switch target {
		case "IP":
			targetIP = ip
		case "Network":
			if ip != "" && subnet > 0 {
				targetIP = fmt.Sprintf("%s/%d", ip, subnet)
			} else {
				targetIP = ip
			}
		case "Range":
			targetIPStart = startIP
			targetIPEnd = endIP
		}
	case "VCENTER":
		targetType = "ip"
		targetIP = ip
	case "DOMAIN":
		targetType = "ip"
		targetIP = ip
	case "FIREWALL":
		targetType = "ip"
		targetIP = ip
	case "SWITCH":
		targetType = "ip"
		targetIP = ip
	}
	return
}

// GetNmapProfiles retrieves all available Nmap profiles
func (s *scannerService) GetNmapProfiles(ctx context.Context) ([]domain.NmapProfile, error) {
	log.Printf("Service: Getting all Nmap profiles")

	profiles, err := s.repo.GetNmapProfiles(ctx)
	if err != nil {
		log.Printf("Service: Error retrieving Nmap profiles: %v", err)
		return nil, err
	}

	log.Printf("Service: Successfully retrieved %d Nmap profiles", len(profiles))
	return profiles, nil
}

// CreateNmapProfile creates a new Nmap profile
func (s *scannerService) CreateNmapProfile(ctx context.Context, profile domain.NmapProfile) (int64, error) {
	log.Printf("Service: Creating Nmap profile: %s", profile.Name)

	// Set timestamps
	profile.CreatedAt = time.Now()

	// Create profile in repository
	profileID, err := s.repo.CreateNmapProfile(ctx, profile)
	if err != nil {
		log.Printf("Service: Error creating Nmap profile: %v", err)
		return 0, fmt.Errorf("failed to create Nmap profile: %w", err)
	}

	log.Printf("Service: Successfully created Nmap profile with ID: %d", profileID)
	return profileID, nil
}

// createCustomNmapProfile creates a custom Nmap profile for a scanner with custom switches
func (s *scannerService) createCustomNmapProfile(ctx context.Context, scannerName, customSwitches string) (*domain.NmapProfile, error) {
	// Parse custom switches into arguments
	args := strings.Fields(customSwitches)

	// Create a unique profile name
	profileName := fmt.Sprintf("Custom - %s", scannerName)

	// Create the profile
	profile := domain.NmapProfile{
		Name:        profileName,
		Description: stringPtr(fmt.Sprintf("Custom profile for scanner: %s", scannerName)),
		Arguments:   args,
		IsDefault:   false,
		IsSystem:    false,
		CreatedBy:   stringPtr("system"),
	}

	profileID, err := s.CreateNmapProfile(ctx, profile)
	if err != nil {
		return nil, fmt.Errorf("failed to create custom profile: %w", err)
	}

	profile.ID = profileID
	return &profile, nil
}

// Helper function to create string pointers
func stringPtr(s string) *string {
	return &s
}

// GetNmapProfileByID retrieves a specific Nmap profile by ID
func (s *scannerService) GetNmapProfileByID(ctx context.Context, profileID int64) (*domain.NmapProfile, error) {
	log.Printf("Service: Getting Nmap profile with ID: %d", profileID)

	if profileID <= 0 {
		return nil, fmt.Errorf("invalid profile ID: %d", profileID)
	}

	profile, err := s.repo.GetNmapProfileByID(ctx, profileID)
	if err != nil {
		log.Printf("Service: Error retrieving Nmap profile: %v", err)
		return nil, err
	}

	if profile == nil {
		log.Printf("Service: Nmap profile not found for ID: %d", profileID)
		return nil, fmt.Errorf("nmap profile with ID %d not found", profileID)
	}

	log.Printf("Service: Successfully retrieved Nmap profile: %s", profile.Name)
	return profile, nil
}

// GetDefaultNmapProfile retrieves the default Nmap profile
func (s *scannerService) GetDefaultNmapProfile(ctx context.Context) (*domain.NmapProfile, error) {
	log.Printf("Service: Getting default Nmap profile")

	profile, err := s.repo.GetDefaultNmapProfile(ctx)
	if err != nil {
		log.Printf("Service: Error retrieving default Nmap profile: %v", err)
		return nil, err
	}

	if profile == nil {
		log.Printf("Service: Default Nmap profile not found")
		return nil, fmt.Errorf("default nmap profile not found")
	}

	log.Printf("Service: Successfully retrieved default Nmap profile: %s", profile.Name)
	return profile, nil
}

func (s *scannerService) ensureNmapProfileLoaded(ctx context.Context, scanner *domain.ScannerDomain) error {
	if scanner.ScanType != domain.ScannerTypeNmap {
		return nil // Not an Nmap scanner
	}

	// Handle different scanner types
	switch scanner.Type {
	case "custom":
		if scanner.NmapProfile != nil {
			log.Printf("Service: Custom Nmap scanner with profile: %s (ID: %d)", scanner.NmapProfile.Name, scanner.NmapProfile.ID)
			return nil
		}

		// If for some reason the profile isn't loaded but we have a profile ID, load it
		if scanner.NmapProfileID != nil {
			profile, err := s.repo.GetNmapProfileByID(ctx, *scanner.NmapProfileID)
			if err != nil {
				return fmt.Errorf("failed to load custom Nmap profile: %v", err)
			}
			if profile == nil {
				return fmt.Errorf("custom Nmap profile with ID %d not found", *scanner.NmapProfileID)
			}
			scanner.NmapProfile = profile
			return nil
		}

		// If we reach here, it's a custom scanner without any profile info - this shouldn't happen
		log.Printf("Service: Warning - Custom Nmap scanner has no profile information")
		return nil

	case "profile", "":
		// For profile type (or empty type - default to profile)
		// If profile is already loaded, we're done
		if scanner.NmapProfile != nil {
			return nil
		}

		// If no profile ID is set, use the default
		if scanner.NmapProfileID == nil {
			defaultProfile, err := s.repo.GetDefaultNmapProfile(ctx)
			if err != nil {
				return fmt.Errorf("failed to get default Nmap profile: %v", err)
			}
			if defaultProfile == nil {
				return fmt.Errorf("no default Nmap profile found")
			}
			scanner.NmapProfileID = &defaultProfile.ID
			scanner.NmapProfile = defaultProfile
			return nil
		}

		// Load the specified profile
		profile, err := s.repo.GetNmapProfileByID(ctx, *scanner.NmapProfileID)
		if err != nil {
			return fmt.Errorf("failed to load Nmap profile: %v", err)
		}
		if profile == nil {
			return fmt.Errorf("Nmap profile with ID %d not found", *scanner.NmapProfileID)
		}

		scanner.NmapProfile = profile
		return nil

	default:
		return fmt.Errorf("unsupported scanner type: %s", scanner.Type)
	}
}

// preprocessNessusScanner builds Nessus URL from protocol, IP, and port if provided separately
func (s *scannerService) preprocessNessusScanner(scanner *domain.ScannerDomain) error {
	if scanner.Domain != "" {
		return nil
	}

	if scanner.Protocol != "" && scanner.IP != "" {
		port := scanner.Port
		if port == "" {
			port = "8834"
		}

		scanner.Domain = fmt.Sprintf("%s://%s:%s", scanner.Protocol, scanner.IP, port)
		log.Printf("Service: Built Nessus URL: %s from protocol=%s, ip=%s, port=%s",
			scanner.Domain, scanner.Protocol, scanner.IP, port)
	}

	return nil
}

// validatePortRange validates port range specifications
func (s *scannerService) validatePortRange(portSpec string) error {
	// Handle common port specifications
	if portSpec == "-" {
		return fmt.Errorf("scanning all ports (-) is not allowed")
	}

	// Split by commas for multiple ranges
	ranges := strings.Split(portSpec, ",")
	for _, r := range ranges {
		r = strings.TrimSpace(r)

		if strings.Contains(r, "-") {
			// Range specification (e.g., "1-1000")
			parts := strings.Split(r, "-")
			if len(parts) != 2 {
				return fmt.Errorf("invalid port range format: %s", r)
			}

			start, err := strconv.Atoi(parts[0])
			if err != nil {
				return fmt.Errorf("invalid start port: %s", parts[0])
			}

			end, err := strconv.Atoi(parts[1])
			if err != nil {
				return fmt.Errorf("invalid end port: %s", parts[1])
			}

			if start < 1 || start > 65535 || end < 1 || end > 65535 {
				return fmt.Errorf("port numbers must be between 1 and 65535")
			}

			if start > end {
				return fmt.Errorf("start port cannot be greater than end port")
			}

			if end-start > 10000 {
				return fmt.Errorf("port range too large: %d ports (maximum allowed: 10000)", end-start+1)
			}
		} else {
			// Single port
			port, err := strconv.Atoi(r)
			if err != nil {
				return fmt.Errorf("invalid port number: %s", r)
			}

			if port < 1 || port > 65535 {
				return fmt.Errorf("port number must be between 1 and 65535: %d", port)
			}
		}
	}

	return nil
}

// validateSwitchScanner validates business rules for switch scanners
func (s *scannerService) validateSwitchScanner(scanner *domain.ScannerDomain) error {
	// Business logic validation only - API layer handles format validation

	if scanner.IP == "" {
		return fmt.Errorf("IP address is required for switch scanner")
	}

	if scanner.Username == "" {
		return fmt.Errorf("username is required for switch scanner")
	}

	if scanner.Password == "" {
		return fmt.Errorf("password is required for switch scanner")
	}

	return nil
}

func (s *scannerService) ExecuteSwitchScan(ctx context.Context, scanner domain.ScannerDomain, scanJobID int64) error {
	if s.switchRunner == nil {
		return fmt.Errorf("switch runner not initialized")
	}
	return s.switchRunner.ExecuteSwitchScan(ctx, scanner, scanJobID)
}
