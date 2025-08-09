package nessus

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"
)

// FlexibleInt64 is a type that can unmarshal from string, int64, or date string JSON values
type FlexibleInt64 int64

// UnmarshalJSON implements json.Unmarshaler interface
func (f *FlexibleInt64) UnmarshalJSON(data []byte) error {
	// Try to unmarshal as int64 first
	var i int64
	if err := json.Unmarshal(data, &i); err == nil {
		*f = FlexibleInt64(i)
		return nil
	}

	// If that fails, try to unmarshal as string
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}

	// Try to parse as int64 string first
	if i, err := strconv.ParseInt(s, 10, 64); err == nil {
		*f = FlexibleInt64(i)
		return nil
	}

	// If that fails, try to parse as date string
	// Common Nessus date formats
	dateFormats := []string{
		"Mon Jan 2 15:04:05 2006",
		"Mon Jan 02 15:04:05 2006",
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05Z",
		"2006-01-02T15:04:05.000Z",
		time.RFC3339,
		time.RFC1123,
	}

	for _, format := range dateFormats {
		if t, err := time.Parse(format, s); err == nil {
			*f = FlexibleInt64(t.Unix())
			return nil
		}
	}

	// If all parsing attempts fail, return an error
	return fmt.Errorf("cannot parse '%s' as int64 or date", s)
}

// Int64 returns the int64 value
func (f FlexibleInt64) Int64() int64 {
	return int64(f)
}

// Ptr returns a pointer to the int64 value
func (f FlexibleInt64) Ptr() *int64 {
	i := int64(f)
	return &i
}

// FlexibleFloat64 is a type that can unmarshal from string or float64 JSON values
type FlexibleFloat64 float64

// UnmarshalJSON implements json.Unmarshaler interface
func (f *FlexibleFloat64) UnmarshalJSON(data []byte) error {
	// Try to unmarshal as float64 first
	var val float64
	if err := json.Unmarshal(data, &val); err == nil {
		*f = FlexibleFloat64(val)
		return nil
	}

	// If that fails, try to unmarshal as string
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}

	// Handle empty/null strings
	if s == "" || s == "null" {
		*f = FlexibleFloat64(0)
		return nil
	}

	// Try to parse as float64 string
	if val, err := strconv.ParseFloat(s, 64); err == nil {
		*f = FlexibleFloat64(val)
		return nil
	}

	// If all parsing attempts fail, return an error
	return fmt.Errorf("cannot parse '%s' as float64", s)
}

// Float64 returns the float64 value
func (f FlexibleFloat64) Float64() float64 {
	return float64(f)
}

// Ptr returns a pointer to the float64 value
func (f FlexibleFloat64) Ptr() *float64 {
	val := float64(f)
	return &val
}

// Response structures for Nessus API

type FoldersResponse struct {
	Folders []Folder `json:"folders"`
}

type Folder struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	Type        string `json:"type"`
	DefaultTag  int    `json:"default_tag"`
	Custom      int    `json:"custom"`
	UnreadCount int    `json:"unread_count"`
}

type ScannersResponse struct {
	Scanners []Scanner `json:"scanners"`
}

type Scanner struct {
	ID       int    `json:"id"`
	Name     string `json:"name"`
	Status   string `json:"status"`
	Type     string `json:"type"`
	Platform string `json:"platform"`
}

type ScansResponse struct {
	Folders []ScanFolder `json:"folders"`
	Scans   []Scan       `json:"scans"`
}

type ScanFolder struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	Type        string `json:"type"`
	DefaultTag  int    `json:"default_tag"`
	Custom      int    `json:"custom"`
	UnreadCount int    `json:"unread_count"`
}

type Scan struct {
	ID                   int    `json:"id"`
	UUID                 string `json:"uuid"`
	Name                 string `json:"name"`
	Status               string `json:"status"`
	FolderID             int    `json:"folder_id"`
	Read                 bool   `json:"read"`
	LastModificationDate int64  `json:"last_modification_date"`
	CreationDate         int64  `json:"creation_date"`
	StartTime            *int64 `json:"start_time"`
	EndTime              *int64 `json:"end_time"`
	Enabled              bool   `json:"enabled"`
	UserPermissions      int    `json:"user_permissions"`
	Shared               bool   `json:"shared"`
	Owner                string `json:"owner"`
	OwnerID              int    `json:"owner_id"`
	ScheduleUUID         string `json:"schedule_uuid"`
	Timezone             string `json:"timezone"`
	Control              bool   `json:"control"`
	Type                 string `json:"type"`
}

type ScanDetails struct {
	Info            ScanInfo            `json:"info"`
	Hosts           []Host              `json:"hosts"`
	Vulnerabilities []VulnerabilityInfo `json:"vulnerabilities"`
	History         []HistoryEntry      `json:"history"`
}

type ScanInfo struct {
	ObjectID         int                    `json:"object_id"`
	EditAllowed      bool                   `json:"edit_allowed"`
	Status           string                 `json:"status"`
	Policy           string                 `json:"policy"`
	Owner            string                 `json:"owner"`
	ScanStart        *int64                 `json:"scan_start"`
	ScanEnd          *int64                 `json:"scan_end"`
	ScannerStart     *int64                 `json:"scanner_start"`
	ScannerEnd       *int64                 `json:"scanner_end"`
	Targets          string                 `json:"targets"`
	Name             string                 `json:"name"`
	UUID             string                 `json:"uuid"`
	Notes            string                 `json:"notes"`
	Control          bool                   `json:"control"`
	Timestamp        int64                  `json:"timestamp"`
	HasAuditTrail    bool                   `json:"hasaudittrail"`
	ScanType         string                 `json:"scan_type"`
	HostCount        int                    `json:"hostcount"`
	TotalChecks      int                    `json:"totalchecks"`
	Acls             []interface{}          `json:"acls"`
	Remediation      []RemediationInfo      `json:"remediation"`
	ComplianceCounts map[string]interface{} `json:"compliance"`
	VulnCounts       map[string]interface{} `json:"vulnerability_counts"`
}

type Host struct {
	HostID              int    `json:"host_id"`
	HostIndex           int    `json:"host_index"`
	Hostname            string `json:"hostname"`
	Progress            string `json:"progress"`
	Critical            int    `json:"critical"`
	High                int    `json:"high"`
	Medium              int    `json:"medium"`
	Low                 int    `json:"low"`
	Info                int    `json:"info"`
	TotalChecks         int    `json:"totalchecks"`
	NumChecks           int    `json:"numchecks"`
	ScanProgressTotal   int    `json:"scanprogresstotal"`
	ScanProgressCurrent int    `json:"scanprogresscurrent"`
	Score               int    `json:"score"`
}

type VulnerabilityInfo struct {
	PluginID      int    `json:"plugin_id"`
	PluginName    string `json:"plugin_name"`
	PluginFamily  string `json:"plugin_family"`
	Count         int    `json:"count"`
	VulnIndex     int    `json:"vuln_index"`
	SeverityIndex int    `json:"severity_index"`
	Severity      int    `json:"severity"`
}

type HistoryEntry struct {
	HistoryID            int    `json:"history_id"`
	UUID                 string `json:"uuid"`
	OwnerID              int    `json:"owner_id"`
	Status               string `json:"status"`
	CreationDate         int64  `json:"creation_date"`
	LastModificationDate int64  `json:"last_modification_date"`
}

type RemediationInfo struct {
	Value       string `json:"value"`
	Remediation string `json:"remediation"`
	Hosts       int    `json:"hosts"`
	Vulns       int    `json:"vulns"`
}

type HostDetails struct {
	Info            HostInfo            `json:"info"`
	Vulnerabilities []HostVulnerability `json:"vulnerabilities"`
	Compliance      []HostCompliance    `json:"compliance"`
}

type HostInfo struct {
	HostStart                *FlexibleInt64 `json:"host_start"`
	HostEnd                  *FlexibleInt64 `json:"host_end"`
	HostIP                   string         `json:"host-ip"`
	HostFQDN                 *string        `json:"host_fqdn"`
	Hostname                 string         `json:"hostname"`
	OperatingSystem          string         `json:"operating-system"`
	MACAddress               *string        `json:"mac-address"`
	NetBIOSName              *string        `json:"netbios-name"`
	SystemType               *string        `json:"system-type"`
	HostUUID                 string         `json:"host_uuid"`
	ScanTime                 int64          `json:"scan_time"`
	Policy                   string         `json:"policy"`
	InterfaceList            string         `json:"interface_list"`
	TracerouteHopCount       *int           `json:"traceroute_hop_count"`
	CredentialsPort          *int           `json:"credentialed_scan_port"`
	BIOSUuid                 *string        `json:"bios-uuid"`
	LastAuthenticated        *FlexibleInt64 `json:"last_authenticated_scan_time"`
	LastUnauthenticated      *FlexibleInt64 `json:"last_unauthenticated_scan_time"`
	LastAuthenticatedResults *string        `json:"last_authenticated_results"`
}

type HostVulnerability struct {
	PluginID      int              `json:"plugin_id"`
	PluginName    string           `json:"plugin_name"`
	PluginFamily  string           `json:"plugin_family"`
	Count         int              `json:"count"`
	VulnIndex     int              `json:"vuln_index"`
	SeverityIndex int              `json:"severity_index"`
	Severity      int              `json:"severity"`
	HostID        int              `json:"host_id"`
	Score         *FlexibleFloat64 `json:"score"`
	VPRScore      *FlexibleFloat64 `json:"vpr_score"`
	CPE           *string          `json:"cpe"`
	Offline       bool             `json:"offline"`
	Snoozed       int              `json:"snoozed"`
}

type HostCompliance struct {
	PluginID      int    `json:"plugin_id"`
	PluginName    string `json:"plugin_name"`
	PluginFamily  string `json:"plugin_family"`
	Count         int    `json:"count"`
	SeverityIndex int    `json:"severity_index"`
	Severity      int    `json:"severity"`
	HostID        int    `json:"host_id"`
}

type PluginOutput struct {
	Info    PluginOutputInfo     `json:"info"`
	Outputs []PluginOutputDetail `json:"outputs"`
}

type PluginOutputInfo struct {
	PluginDetails PluginOutputDetails `json:"plugindescription"`
}

type PluginOutputDetails struct {
	PluginID   int    `json:"pluginid"`
	PluginName string `json:"pluginname"`
	Severity   string `json:"severity"`
}

type PluginOutputDetail struct {
	PluginOutput string                 `json:"plugin_output"`
	Hosts        string                 `json:"hosts"`
	Severity     int                    `json:"severity"`
	Ports        map[string]interface{} `json:"ports"`
}

type PluginDetails struct {
	PluginName   string            `json:"pluginname"`
	PluginID     int               `json:"pluginid"`
	PluginFamily string            `json:"pluginfamily"`
	Attributes   []PluginAttribute `json:"attributes"`
}

type PluginAttribute struct {
	AttributeName  string `json:"attribute_name"`
	AttributeValue string `json:"attribute_value"`
}
