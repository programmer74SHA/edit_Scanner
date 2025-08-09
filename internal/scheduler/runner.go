package scheduler

import (
	"context"
	"log"
	"sync"
	"time"

	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/scheduler/port"
)

// SchedulerRunner is responsible for periodically checking and executing scheduled scans
type SchedulerRunner struct {
	service       port.Service
	scheduler     *schedulerService // Reference to concrete implementation
	checkInterval time.Duration
	running       bool
	stopChan      chan struct{}
	wg            sync.WaitGroup
}

// NewSchedulerRunner creates a new scheduler runner
func NewSchedulerRunner(service port.Service, checkInterval time.Duration) *SchedulerRunner {
	// Type assertion to get concrete implementation
	scheduler, ok := service.(*schedulerService)
	if !ok {
		log.Println("Warning: Service is not a schedulerService instance, some functions may not work")
	}

	return &SchedulerRunner{
		service:       service,
		scheduler:     scheduler, // Store concrete implementation
		checkInterval: checkInterval,
		running:       false,
		stopChan:      make(chan struct{}),
	}
}

// Start begins the scheduler runner
func (r *SchedulerRunner) Start() {
	if r.running {
		log.Println("Scheduler Runner: Already running")
		return
	}

	// Check if we have access to concrete implementation
	if r.scheduler == nil {
		log.Println("Scheduler Runner: Cannot start - missing implementation access")
		return
	}

	r.running = true
	r.wg.Add(1)

	log.Printf("Scheduler Runner: Starting with check interval of %s", r.checkInterval)

	go func() {
		defer r.wg.Done()
		ticker := time.NewTicker(r.checkInterval)
		defer ticker.Stop()

		// Run once at startup
		r.checkAndExecuteSchedules()

		for {
			select {
			case <-ticker.C:
				r.checkAndExecuteSchedules()
			case <-r.stopChan:
				log.Println("Scheduler Runner: Stopping")
				return
			}
		}
	}()
}

// Stop halts the scheduler runner
func (r *SchedulerRunner) Stop() {
	if !r.running {
		return
	}

	log.Println("Scheduler Runner: Stopping")
	close(r.stopChan)
	r.wg.Wait()
	r.running = false
}

// checkAndExecuteSchedules checks for due schedules and executes them
func (r *SchedulerRunner) checkAndExecuteSchedules() {
	ctx := context.Background()

	// Ensure we have access to concrete implementation
	if r.scheduler == nil {
		log.Println("Scheduler Runner: Cannot check schedules - missing implementation access")
		return
	}

	log.Println("Scheduler Runner: Checking for due schedules")

	// Using concrete implementation's method
	schedules, err := r.scheduler.GetDueSchedules(ctx)
	if err != nil {
		log.Printf("Scheduler Runner: Error getting due schedules: %v", err)
		return
	}

	log.Printf("Scheduler Runner: Found %d due schedules", len(schedules))

	for _, schedule := range schedules {
		// Using concrete implementation's method
		err := r.scheduler.ExecuteScheduledScan(ctx, schedule)
		if err != nil {
			log.Printf("Scheduler Runner: Error executing schedule for scanner ID %d: %v",
				schedule.Scanner.ID, err)
			continue
		}

		log.Printf("Scheduler Runner: Successfully executed schedule for scanner ID: %d",
			schedule.Scanner.ID)
	}
}
