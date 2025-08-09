package domain

import (
	"time"

	scannerDomain "gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanner/domain"
)

// SwitchInfo represents comprehensive switch information for API responses
type SwitchInfo struct {
	ID                string     `json:"id"`
	ScannerID         int64      `json:"scanner_id"`
	Name              string     `json:"name"`
	Hostname          string     `json:"hostname"`
	IPAddress         string     `json:"ip_address"`
	Brand             string     `json:"brand"`
	Model             string     `json:"model"`
	SoftwareVersion   string     `json:"software_version"`
	SerialNumber      string     `json:"serial_number,omitempty"`
	SystemUptime      string     `json:"system_uptime,omitempty"`
	ManagementIP      string     `json:"management_ip,omitempty"`
	EthernetMAC       string     `json:"ethernet_mac,omitempty"`
	NumberOfPorts     int        `json:"number_of_ports"`
	NumberOfVLANs     int        `json:"number_of_vlans"`
	NumberOfNeighbors int        `json:"number_of_neighbors"`
	Status            string     `json:"status"` // online, offline, scanning, error
	LastScanTime      *time.Time `json:"last_scan_time,omitempty"`
	LastScanStatus    string     `json:"last_scan_status,omitempty"` // success, failed, in_progress
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`

	// Optional detailed data (for individual switch requests)
	Interfaces []scannerDomain.SwitchInterface `json:"interfaces,omitempty"`
	VLANs      []scannerDomain.SwitchVLAN      `json:"vlans,omitempty"`
	Neighbors  []scannerDomain.SwitchNeighbor  `json:"neighbors,omitempty"`
	SystemInfo *scannerDomain.SwitchSystemInfo `json:"system_info,omitempty"`
}

// SwitchListResponse represents the response for listing switches
type SwitchListResponse struct {
	Switches []SwitchInfo `json:"switches"`
	Count    int          `json:"count"`
	Success  bool         `json:"success"`
}

// SwitchDetailResponse represents the response for individual switch details
type SwitchDetailResponse struct {
	Switch  SwitchInfo `json:"switch"`
	Success bool       `json:"success"`
	Error   string     `json:"error,omitempty"`
}

// SwitchFilter represents filters for switch listing
type SwitchFilter struct {
	Name      string `json:"name,omitempty"`
	Brand     string `json:"brand,omitempty"`
	IPAddress string `json:"ip_address,omitempty"`
	Status    string `json:"status,omitempty"`
	ScannerID *int64 `json:"scanner_id,omitempty"`
}

// SwitchListRequest represents request parameters for listing switches
type SwitchListRequest struct {
	Filter SwitchFilter `json:"filter"`
	Limit  int          `json:"limit,omitempty"`
	Page   int          `json:"page,omitempty"`
	Sort   string       `json:"sort,omitempty"`  // field to sort by
	Order  string       `json:"order,omitempty"` // asc or desc
}
