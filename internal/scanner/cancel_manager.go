package scanner

import (
	"context"
	"log"
	"sync"
)

// ScanCancelManager manages the cancellation of running scans
type ScanCancelManager struct {
	activeScans map[int64]context.CancelFunc
	mu          sync.Mutex
}

// NewScanCancelManager creates a new scan cancellation manager
func NewScanCancelManager() *ScanCancelManager {
	return &ScanCancelManager{
		activeScans: make(map[int64]context.CancelFunc),
	}
}

// RegisterScan registers a scan job with its cancellation function
func (m *ScanCancelManager) RegisterScan(jobID int64, cancel context.CancelFunc) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Store the cancel function for this job
	m.activeScans[jobID] = cancel
	log.Printf("Registered scan job ID %d for cancellation", jobID)
}

// UnregisterScan removes a scan job from tracking
func (m *ScanCancelManager) UnregisterScan(jobID int64) {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.activeScans, jobID)
	log.Printf("Unregistered scan job ID %d", jobID)
}

// CancelScan cancels a running scan job
func (m *ScanCancelManager) CancelScan(jobID int64) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	cancel, exists := m.activeScans[jobID]
	if !exists {
		log.Printf("No active scan found for job ID %d", jobID)
		return false
	}

	// Call the cancel function to stop the scan
	cancel()
	log.Printf("Cancelled scan job ID %d", jobID)

	// Remove from active scans
	delete(m.activeScans, jobID)

	return true
}

// HasActiveScan checks if a scan job is currently active
func (m *ScanCancelManager) HasActiveScan(jobID int64) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	_, exists := m.activeScans[jobID]
	return exists
}
