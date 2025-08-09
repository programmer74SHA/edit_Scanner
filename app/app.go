package app

import (
	"context"
	"fmt"
	"time"

	"gitlab.apk-group.net/siem/backend/asset-discovery/api/service"
	"gitlab.apk-group.net/siem/backend/asset-discovery/config"
	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset"
	assetPort "gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/port"
	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/firewall"
	firewallPort "gitlab.apk-group.net/siem/backend/asset-discovery/internal/firewall/port"
	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanjob"
	scanJobPort "gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanjob/port"
	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanner"
	scannerDomain "gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanner/domain"
	scannerPort "gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanner/port"
	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/scheduler"
	schedulerPort "gitlab.apk-group.net/siem/backend/asset-discovery/internal/scheduler/port"
	switchService "gitlab.apk-group.net/siem/backend/asset-discovery/internal/switch"
	switchPort "gitlab.apk-group.net/siem/backend/asset-discovery/internal/switch/port"
	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/user"
	userDomain "gitlab.apk-group.net/siem/backend/asset-discovery/internal/user/domain"
	userPort "gitlab.apk-group.net/siem/backend/asset-discovery/internal/user/port"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/adapter/devices"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/adapter/storage"
	appCtx "gitlab.apk-group.net/siem/backend/asset-discovery/pkg/context"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/logger"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/mysql"
	"gorm.io/gorm"
)

type app struct {
	db                  *gorm.DB
	cfg                 config.Config
	assetService        assetPort.Service
	userService         userPort.Service
	scannerService      scannerPort.Service
	schedulerService    schedulerPort.Service
	firewallService     firewallPort.Service
	switchService       switchPort.Service
	schedulerRunner     *scheduler.SchedulerRunner
	nmapScanner         *scanner.NmapRunner
	vcenterScanner      *scanner.VCenterRunner
	domainScanner       *scanner.DomainRunner
	firewallScanner     *scanner.FirewallRunner
	switchScanner       *scanner.SwitchRunner
	nessusScanner       *scanner.NessusRunner
	scannerFactory      *scheduler.ScannerFactory
	apiScannerService   *service.ScannerService
	scanJobService      scanJobPort.Service
	switchCancelManager *scanner.ScanCancelManager
	switchDeviceFactory scannerDomain.SwitchDeviceClientFactory
	// Unified scanner repository - implements the full scanner port.Repo interface
	scannerRepo scannerPort.Repo
	// Specialized switch repository - used internally by the unified repo
	switchRepository *storage.SwitchRepository
}

func (a *app) AssetService(ctx context.Context) assetPort.Service {
	db := appCtx.GetDB(ctx)
	if db == nil {
		if a.assetService == nil {
			a.assetService = a.assetServiceWithDB(a.db)
		}
		return a.assetService
	}
	return a.assetServiceWithDB(db)
}

func (a *app) assetServiceWithDB(db *gorm.DB) assetPort.Service {
	return asset.NewAssetService(storage.NewAssetRepo(db))
}

func (a *app) DB() *gorm.DB {
	return a.db
}

func (a *app) userServiceWithDB(db *gorm.DB) userPort.Service {
	return user.NewUserService(storage.NewUserRepo(db))
}

func (a *app) UserService(ctx context.Context) userPort.Service {
	db := appCtx.GetDB(ctx)
	if db == nil {
		if a.userService == nil {
			a.userService = a.userServiceWithDB(a.db)
		}
		return a.userService
	}
	return a.userServiceWithDB(db)
}

func (a *app) scanJobServiceWithDB(db *gorm.DB) scanJobPort.Service {
	return scanjob.NewScanJobService(
		storage.NewScanJobRepo(db),
		a.assetServiceWithDB(db),
		a.scannerServiceWithDB(db),
	)
}

func (a *app) ScanJobService(ctx context.Context) scanJobPort.Service {
	db := appCtx.GetDB(ctx)
	if db == nil {
		if a.scanJobService == nil {
			a.scanJobService = a.scanJobServiceWithDB(a.db)
		}
		return a.scanJobService
	}
	return a.scanJobServiceWithDB(db)
}

func (a *app) Config() config.Config {
	return a.cfg
}

func (a *app) setDB() error {
	db, err := mysql.NewMysqlConnection(mysql.DBConnOptions{
		Host:     a.cfg.DB.Host,
		Port:     a.cfg.DB.Port,
		Username: a.cfg.DB.Username,
		Password: a.cfg.DB.Password,
		Database: a.cfg.DB.Database,
	})
	if err != nil {
		return err
	}
	mysql.GormMigrations(db)
	mysql.SeedData(db, userDomain.HashPassword)
	a.db = db
	return nil
}

// createUnifiedScannerRepository creates the unified scanner repository for a given database connection
func (a *app) createUnifiedScannerRepository(db *gorm.DB) scannerPort.Repo {
	// Create the specialized switch repository
	assetRepo := storage.NewAssetRepo(db)
	switchRepo := storage.NewSwitchRepository(db, assetRepo)

	// Create the unified scanner repository that includes all scanner operations
	return storage.NewScannerRepository(db, switchRepo)
}

// createSwitchRunner creates a SwitchRunner with unified repository for a given database connection
func (a *app) createSwitchRunner(db *gorm.DB) *scanner.SwitchRunner {
	unifiedRepo := a.createUnifiedScannerRepository(db)

	return scanner.NewSwitchRunner(
		unifiedRepo, // Unified repository that implements the full scanner port.Repo interface
		a.switchDeviceFactory,
		a.switchCancelManager,
	)
}

// switchServiceWithDB creates a switch service with a specific database connection
func (a *app) switchServiceWithDB(db *gorm.DB) switchPort.Service {
	// Get the switch repository that implements both Repository and SwitchDataRepository
	switchRepo := a.GetSwitchRepositoryForDB(db)

	// Create the switch service
	return switchService.NewSwitchService(switchRepo, switchRepo)
}

func (a *app) SwitchService(ctx context.Context) switchPort.Service {
	db := appCtx.GetDB(ctx)
	if db == nil {
		if a.switchService == nil {
			a.switchService = a.switchServiceWithDB(a.db)
		}
		return a.switchService
	}
	return a.switchServiceWithDB(db)
}

func NewApp(cfg config.Config) (AppContainer, error) {
	a := &app{
		cfg: cfg,
	}
	if err := a.setDB(); err != nil {
		return nil, err
	}

	// Initialize asset repository and service
	assetRepo := storage.NewAssetRepo(a.db)
	a.assetService = asset.NewAssetService(assetRepo)

	// Initialize cancel manager for switch operations
	a.switchCancelManager = scanner.NewScanCancelManager()

	// Initialize switch device factory
	a.switchDeviceFactory = devices.NewSwitchDeviceClientFactory()

	// Initialize specialized switch repository for internal use
	a.switchRepository = storage.NewSwitchRepository(a.db, assetRepo)

	// Initialize the unified scanner repository
	a.scannerRepo = storage.NewScannerRepository(a.db, a.switchRepository)

	// Initialize scanners with proper dependencies
	a.nmapScanner = scanner.NewNmapRunner(assetRepo)
	a.vcenterScanner = scanner.NewVCenterRunner(assetRepo)
	a.domainScanner = scanner.NewDomainRunner(assetRepo)
	a.firewallScanner = scanner.NewFirewallRunner(assetRepo, a.db)

	// Create SwitchRunner with unified repository
	a.switchScanner = scanner.NewSwitchRunner(
		a.scannerRepo, // Use unified repository
		a.switchDeviceFactory,
		a.switchCancelManager,
	)

	a.nessusScanner = scanner.NewNessusRunner(assetRepo)

	// Log scanner initialization to help with debugging
	a.logScannerInitialization()

	// Initialize scanner service (internal domain layer) with unified repository
	a.scannerService = scanner.NewScannerService(a.scannerRepo, a.db)

	// Initialize switch service (add this after existing service initialization)
	a.switchService = switchService.NewSwitchService(a.switchRepository, a.switchRepository)

	// Initialize scanner factory and register scanners
	a.scannerFactory = scheduler.NewScannerFactory()
	a.registerScannersInFactory(a.scannerFactory)

	// Initialize scheduler service with scanner factory
	schedulerRepo := storage.NewSchedulerRepo(a.db)
	a.schedulerService = scheduler.NewSchedulerService(
		schedulerRepo,
		a.scannerService,
		a.scannerFactory,
	)

	// Initialize API scanner service (external API layer)
	a.apiScannerService = service.NewScannerService(a.scannerService)

	// Connect the API scanner service to the scheduler service for cancellation
	a.apiScannerService.SetSchedulerService(a.schedulerService)

	// Create the scheduler runner with a 1-minute check interval
	a.schedulerRunner = scheduler.NewSchedulerRunner(a.schedulerService, 1*time.Minute)

	return a, nil
}

// logScannerInitialization logs the initialization status of all scanners
func (a *app) logScannerInitialization() {
	ctx := context.Background()

	scanners := map[string]interface{}{
		"NmapScanner":     a.nmapScanner,
		"VCenterScanner":  a.vcenterScanner,
		"DomainScanner":   a.domainScanner,
		"FirewallScanner": a.firewallScanner,
		"SwitchScanner":   a.switchScanner,
		"NessusScanner":   a.nessusScanner,
	}

	for name, scanner := range scanners {
		if scanner == nil {
			logger.WarnContext(ctx, "%s was not initialized properly", name)
		} else {
			logger.InfoContext(ctx, "%s initialized successfully", name)
		}
	}
}

// registerScannersInFactory registers all scanners in the scanner factory
func (a *app) registerScannersInFactory(factory *scheduler.ScannerFactory) {
	factory.RegisterScanner("NMAP", a.nmapScanner)
	factory.RegisterScanner("VCENTER", a.vcenterScanner)
	factory.RegisterScanner("DOMAIN", a.domainScanner)
	factory.RegisterScanner("FIREWALL", a.firewallScanner)
	factory.RegisterScanner("SWITCH", a.switchScanner)
	factory.RegisterScanner("NESSUS", a.nessusScanner)
}

func NewMustApp(cfg config.Config) AppContainer {
	a, err := NewApp(cfg)
	if err != nil {
		panic(err)
	}
	return a
}

func (a *app) scannerServiceWithDB(db *gorm.DB) scannerPort.Service {
	// Create unified repository for this DB context
	unifiedRepo := a.createUnifiedScannerRepository(db)
	return scanner.NewScannerService(unifiedRepo, db)
}

func (a *app) ScannerService(ctx context.Context) scannerPort.Service {
	db := appCtx.GetDB(ctx)
	if db == nil {
		if a.scannerService == nil {
			a.scannerService = a.scannerServiceWithDB(a.db)
		}
		return a.scannerService
	}
	return a.scannerServiceWithDB(db)
}

func (a *app) schedulerServiceWithDB(db *gorm.DB) schedulerPort.Service {
	// Initialize scanner service for this DB context using unified repository
	unifiedRepo := a.createUnifiedScannerRepository(db)
	scannerService := scanner.NewScannerService(unifiedRepo, db)

	// Get the asset repo for the given DB context
	assetRepo := storage.NewAssetRepo(db)

	// Create scanners for this context
	nmapScanner := scanner.NewNmapRunner(assetRepo)
	vcenterScanner := scanner.NewVCenterRunner(assetRepo)
	domainScanner := scanner.NewDomainRunner(assetRepo)
	firewallScanner := scanner.NewFirewallRunner(assetRepo, db)

	// Create SwitchRunner with unified repository for this context
	switchScanner := a.createSwitchRunner(db)

	nessusScanner := scanner.NewNessusRunner(assetRepo)

	// Create and configure scanner factory for this context
	scannerFactory := scheduler.NewScannerFactory()
	scannerFactory.RegisterScanner("NMAP", nmapScanner)
	scannerFactory.RegisterScanner("VCENTER", vcenterScanner)
	scannerFactory.RegisterScanner("DOMAIN", domainScanner)
	scannerFactory.RegisterScanner("FIREWALL", firewallScanner)
	scannerFactory.RegisterScanner("SWITCH", switchScanner)
	scannerFactory.RegisterScanner("NESSUS", nessusScanner)

	return scheduler.NewSchedulerService(
		storage.NewSchedulerRepo(db),
		scannerService,
		scannerFactory,
	)
}

func (a *app) SchedulerService(ctx context.Context) schedulerPort.Service {
	db := appCtx.GetDB(ctx)
	if db == nil {
		if a.schedulerService == nil {
			a.schedulerService = a.schedulerServiceWithDB(a.db)
		}
		return a.schedulerService
	}
	return a.schedulerServiceWithDB(db)
}

// StartScheduler begins the scheduler runner
func (a *app) StartScheduler() {
	if a.schedulerRunner != nil {
		a.schedulerRunner.Start()
	}
}

// StopScheduler halts the scheduler runner
func (a *app) StopScheduler() {
	if a.schedulerRunner != nil {
		a.schedulerRunner.Stop()
	}
}

// For access from service_getters.go
func (a *app) GetAPIScannerService() *service.ScannerService {
	return a.apiScannerService
}

func (a *app) firewallServiceWithDB(db *gorm.DB) firewallPort.Service {
	return firewall.NewFirewallService(storage.NewFirewallAssetRepo(db))
}

func (a *app) FirewallService(ctx context.Context) firewallPort.Service {
	db := appCtx.GetDB(ctx)
	if db == nil {
		if a.firewallService == nil {
			a.firewallService = a.firewallServiceWithDB(a.db)
		}
		return a.firewallService
	}
	return a.firewallServiceWithDB(db)
}

// GetSwitchRepository returns the specialized switch repository instance
func (a *app) GetSwitchRepository() *storage.SwitchRepository {
	return a.switchRepository
}

// GetSwitchRepositoryForDB creates a switch repository for a specific database connection
func (a *app) GetSwitchRepositoryForDB(db *gorm.DB) *storage.SwitchRepository {
	assetRepo := storage.NewAssetRepo(db)
	return storage.NewSwitchRepository(db, assetRepo)
}

// GetUnifiedScannerRepository returns the unified scanner repository
func (a *app) GetUnifiedScannerRepository() scannerPort.Repo {
	return a.scannerRepo
}

// CreateSwitchRunnerWithRepository creates a switch runner using the unified repository
func (a *app) CreateSwitchRunnerWithRepository(db *gorm.DB) *scanner.SwitchRunner {
	unifiedRepo := a.createUnifiedScannerRepository(db)

	return scanner.NewSwitchRunner(
		unifiedRepo,
		a.switchDeviceFactory,
		a.switchCancelManager,
	)
}

// ValidateConfiguration validates that all required components are properly initialized
func (a *app) ValidateConfiguration() error {
	if a.db == nil {
		return fmt.Errorf("database connection not initialized")
	}

	if a.scannerRepo == nil {
		return fmt.Errorf("unified scanner repository not initialized")
	}

	if a.switchRepository == nil {
		return fmt.Errorf("switch repository not initialized")
	}

	if a.switchDeviceFactory == nil {
		return fmt.Errorf("switch device factory not initialized")
	}

	if a.switchCancelManager == nil {
		return fmt.Errorf("switch cancel manager not initialized")
	}

	if a.switchScanner == nil {
		return fmt.Errorf("switch scanner not initialized")
	}

	if a.switchService == nil {
		return fmt.Errorf("switch service not initialized")
	}

	return nil
}

// GetComponentStatus returns the status of all major components
func (a *app) GetComponentStatus() map[string]bool {
	return map[string]bool{
		"Database":            a.db != nil,
		"AssetService":        a.assetService != nil,
		"ScannerService":      a.scannerService != nil,
		"SchedulerService":    a.schedulerService != nil,
		"SwitchService":       a.switchService != nil,
		"UnifiedScannerRepo":  a.scannerRepo != nil,
		"SwitchRepository":    a.switchRepository != nil,
		"SwitchDeviceFactory": a.switchDeviceFactory != nil,
		"SwitchCancelManager": a.switchCancelManager != nil,
		"NmapScanner":         a.nmapScanner != nil,
		"VCenterScanner":      a.vcenterScanner != nil,
		"DomainScanner":       a.domainScanner != nil,
		"FirewallScanner":     a.firewallScanner != nil,
		"SwitchScanner":       a.switchScanner != nil,
		"NessusScanner":       a.nessusScanner != nil,
		"ScannerFactory":      a.scannerFactory != nil,
		"SchedulerRunner":     a.schedulerRunner != nil,
	}
}
