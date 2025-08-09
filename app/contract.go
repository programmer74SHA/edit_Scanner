package app

import (
	"context"

	"gitlab.apk-group.net/siem/backend/asset-discovery/api/service"
	scanJobPort "gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanjob/port"

	"gitlab.apk-group.net/siem/backend/asset-discovery/config"
	AssetPort "gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/port"
	FirewallPort "gitlab.apk-group.net/siem/backend/asset-discovery/internal/firewall/port"
	ScannerPort "gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanner/port"
	SchedulerPort "gitlab.apk-group.net/siem/backend/asset-discovery/internal/scheduler/port"
	SwitchPort "gitlab.apk-group.net/siem/backend/asset-discovery/internal/switch/port" // Add this import
	UserPort "gitlab.apk-group.net/siem/backend/asset-discovery/internal/user/port"
	"gorm.io/gorm"
)

type AppContainer interface {
	AssetService(ctx context.Context) AssetPort.Service
	UserService(ctx context.Context) UserPort.Service
	ScannerService(ctx context.Context) ScannerPort.Service
	SchedulerService(ctx context.Context) SchedulerPort.Service
	FirewallService(ctx context.Context) FirewallPort.Service
	SwitchService(ctx context.Context) SwitchPort.Service // Add this line
	StartScheduler()
	StopScheduler()
	ScanJobService(ctx context.Context) scanJobPort.Service
	Config() config.Config
	DB() *gorm.DB

	// Method to access the API scanner service
	GetAPIScannerService() *service.ScannerService
}
