package http

import (
	"crypto/tls"
	"fmt"
	"os"

	"github.com/gofiber/fiber/v2"

	"github.com/gofiber/fiber/v2/middleware/helmet"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"gitlab.apk-group.net/siem/backend/asset-discovery/app"
	"gitlab.apk-group.net/siem/backend/asset-discovery/config"
)

func Run(appContainer app.AppContainer, cfg config.ServerConfig) error {
	router := fiber.New(fiber.Config{
		AppName: "APK Asset Discovery",
	})
	router.Use(helmet.New())
	router.Use(TraceMiddleware())
	router.Use(logger.New(logger.Config{
		Format: "[${time}] ${status} - ${latency} ${method} ${path} TraceID: ${locals:traceID}\n",
		Output: os.Stdout,
	}))

	router.Get("/", func(c *fiber.Ctx) error {
		c.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
		return c.SendString("Secure HTTPS server")
	})

	api := router.Group("/api/v1", setUserContext)

	registerAuthAPI(appContainer, cfg, api)
	registerAssetAPI(appContainer, api)
	registerScannerAPI(appContainer, api.Group("/scanners"))
	registerScanJobsAPI(appContainer, api)
	registerFirewallAPI(appContainer, api)
	registerDashboardAPI(appContainer, api)
	registerSwitchAPI(appContainer, api)

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12, // Set minimum TLS version (TLS 1.2)
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
		PreferServerCipherSuites: true, // Server prefers its cipher suites
	}

	router.Server().TLSConfig = tlsConfig
	if !cfg.SslEnabled {
		return router.Listen(fmt.Sprintf(":%d", cfg.HttpPort))
	}
	return router.ListenTLS(fmt.Sprintf(":%d", cfg.HttpPort), cfg.Cert, cfg.Key)

}

func registerAuthAPI(appContainer app.AppContainer, cfg config.ServerConfig, router fiber.Router) {
	userSvcGetter := userServiceGetter(appContainer, cfg)
	router.Post("/sign-up", setTransaction(appContainer.DB()), SignUp(userSvcGetter))
	router.Post("/sign-in", setTransaction(appContainer.DB()), SignIn(userSvcGetter, cfg))
	router.Post("/sign-out", setTransaction(appContainer.DB()), SignOut(userSvcGetter))
}

func registerScannerAPI(appContainer app.AppContainer, router fiber.Router) {
	scannerSvcGetter := scannerServiceGetter(appContainer)

	router.Get("/nmap-profiles", GetNmapProfiles(scannerSvcGetter))
	router.Get("/nmap-profiles/:id", GetNmapProfile(scannerSvcGetter))

	router.Post("/", setTransaction(appContainer.DB()), CreateScanner(scannerSvcGetter))
	router.Get("/:id", GetScanner(scannerSvcGetter))
	router.Get("/", ListScanners(scannerSvcGetter))
	router.Put("/:id", setTransaction(appContainer.DB()), UpdateScanner(scannerSvcGetter))
	router.Delete("/:id", setTransaction(appContainer.DB()), DeleteScanner(scannerSvcGetter))

	router.Post("/delete", setTransaction(appContainer.DB()), DeleteScanners(scannerSvcGetter))
	router.Post("/status", setTransaction(appContainer.DB()), UpdateScannerStatus(scannerSvcGetter))

	router.Post("/:id/run", RunScanNow(scannerSvcGetter))
}

func registerAssetAPI(appContainer app.AppContainer, router fiber.Router) {
	assetSvcGetter := assetServiceGetter(appContainer)

	// Create asset routes group
	assets := router.Group("/assets")

	// Register endpoints
	assets.Get("/", GetAssets(assetSvcGetter))
	assets.Get("/:id", GetAssetByID(assetSvcGetter))
	assets.Get("/os/names", GetDistinctOSNames(assetSvcGetter))
	assets.Post("/", CreateAsset(assetSvcGetter))
	assets.Put("/:id", UpdateAsset(assetSvcGetter))
	assets.Delete("/:id", DeleteAsset(assetSvcGetter))
	assets.Delete("/", DeleteAssets(assetSvcGetter))

	// Export endpoints
	assets.Post("/export/csv", ExportAssets(assetSvcGetter))
}

func registerScanJobsAPI(appContainer app.AppContainer, router fiber.Router) {
	scanJobSvcGetter := scanJobServiceGetter(appContainer)

	// Create scan job routes group
	scanJobs := router.Group("/scan-jobs")

	// Register endpoints
	scanJobs.Get("/", GetScanJobs(scanJobSvcGetter))
	scanJobs.Get("/diff", DiffJobs(scanJobSvcGetter))
	scanJobs.Post("/diff/export/csv", ExportJobDiff(scanJobSvcGetter))
	scanJobs.Get("/:id", GetScanJobByID(scanJobSvcGetter))

	scanJobs.Post("/:id/cancel", CancelScanJob(scanJobSvcGetter))
}

func registerDashboardAPI(appContainer app.AppContainer, router fiber.Router) {
	assetSvcGetter := assetServiceGetter(appContainer)

	dashboard := router.Group("/dashboard")
	dashboard.Get("/asset-count", GetDashboardAssetCount(assetSvcGetter))
	dashboard.Get("/asset-per-scanner", GetDashboardAssetPerScanner(assetSvcGetter))
	dashboard.Get("/logging-completed", GetDashboardLoggingCompleted(assetSvcGetter))
	dashboard.Get("/assets-per-source", GetDashboardAssetsPerSource(assetSvcGetter))
}

func registerFirewallAPI(appContainer app.AppContainer, router fiber.Router) {
	firewallSvcGetter := firewallServiceGetter(appContainer)

	// Create firewall routes group
	firewalls := router.Group("/firewalls")

	// Register endpoints
	firewalls.Post("/", CreateFirewall(firewallSvcGetter))
	firewalls.Get("/", ListFirewalls(firewallSvcGetter))
	firewalls.Get("/:id", GetFirewallByID(firewallSvcGetter))
	firewalls.Put("/:id", UpdateFirewall(firewallSvcGetter))
	firewalls.Delete("/:id", DeleteFirewall(firewallSvcGetter))
	firewalls.Delete("/batch", DeleteFirewallBatch(firewallSvcGetter))
	firewalls.Delete("/", DeleteAllFirewalls(firewallSvcGetter))
}

func registerSwitchAPI(appContainer app.AppContainer, router fiber.Router) {
	switchSvcGetter := switchServiceGetter(appContainer)

	// Create switches routes group
	switches := router.Group("/switches")

	// Main switch endpoints
	switches.Get("/", GetSwitches(switchSvcGetter))
	switches.Get("/stats", GetSwitchStats(switchSvcGetter))
	switches.Get("/:id", GetSwitchByID(switchSvcGetter))
	switches.Get("/scanner/:id", GetSwitchByScannerID(switchSvcGetter))

	// Switch detail endpoints
	switches.Get("/:id/interfaces", GetSwitchInterfaces(switchSvcGetter))
	switches.Get("/:id/vlans", GetSwitchVLANs(switchSvcGetter))
	switches.Get("/:id/neighbors", GetSwitchNeighbors(switchSvcGetter))
}
