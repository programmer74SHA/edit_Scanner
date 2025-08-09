package main

import (
	"flag"
	"os"
	"os/signal"
	"syscall"

	"gitlab.apk-group.net/siem/backend/asset-discovery/api/handlers/http"
	"gitlab.apk-group.net/siem/backend/asset-discovery/app"
	"gitlab.apk-group.net/siem/backend/asset-discovery/config"
	appContext "gitlab.apk-group.net/siem/backend/asset-discovery/pkg/context"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/logger"
)

var configPath = flag.String("config", "config.json", "service configuration file")

func main() {
	flag.Parse()
	if v := os.Getenv("CONFIG_PATH"); len(v) > 0 {
		*configPath = v
	}
	cfg := config.MustReadConfig(*configPath)

	// Initialize global logger early
	if err := logger.InitGlobalLogger(cfg.Logger); err != nil {
		logger.Fatal("Failed to initialize logger: %v", err)
	}

	globalLogger := logger.GetGlobalLogger()
	appContext.SetDefaultLogger(globalLogger.CoreLogger.Logger)

	// Use the new logger for application startup
	coreLogger, err := logger.NewCoreLogger(cfg.Logger)
	if err != nil {
		logger.Fatal("Failed to create core logger: %v", err)
	}

	coreLogger.Info("Starting asset discovery service")
	coreLogger.InfoWithFields("Configuration loaded", map[string]interface{}{
		"config_path": *configPath,
		"log_level":   cfg.Logger.Level,
		"log_output":  cfg.Logger.Output,
	})

	AppContainer := app.NewMustApp(cfg)

	// Set up signal handling for graceful shutdown
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)

	// Start the scheduler
	coreLogger.Info("Starting scheduler...")
	AppContainer.StartScheduler()

	// Handle shutdown signals in a separate goroutine
	go func() {
		sig := <-signalChan
		coreLogger.InfoWithFields("Received shutdown signal", map[string]interface{}{
			"signal": sig.String(),
		})

		// Stop the scheduler
		coreLogger.Info("Stopping scheduler...")
		AppContainer.StopScheduler()

		coreLogger.Info("Graceful shutdown completed")
		// Allow a clean exit if the HTTP server is still running
		os.Exit(0)
	}()

	// Start the HTTP server (this will block until the server exits)
	coreLogger.Info("Starting HTTP server")
	if err := http.Run(AppContainer, cfg.Server); err != nil {
		coreLogger.Fatal("HTTP server failed: %v", err)
	}
}
