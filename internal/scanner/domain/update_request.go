package domain

import "time"

// ScannerUpdateRequest encapsulates all possible fields that can be updated for a scanner
// This structure is designed for future use when implementing more sophisticated update mechanisms
// Currently, the service uses direct ScannerDomain objects for updates

type ScannerUpdateRequest struct {
	ID                 int64
	Name               string
	ScanType           string
	Status             *bool // Pointer to distinguish between false and not set
	UserID             string
	Type               string
	Target             string
	IP                 string
	Subnet             int64
	StartIP            string
	EndIP              string
	Port               string
	Username           string
	Password           string
	Domain             string
	AuthenticationType string
	Protocol           string
	Schedule           *Schedule
}

// HasField checks if a specific field should be updated
func (r ScannerUpdateRequest) HasField(field string) bool {
	switch field {
	case "name":
		return r.Name != ""
	case "scan_type":
		return r.ScanType != ""
	case "status":
		return r.Status != nil
	case "user_id":
		return r.UserID != ""
	case "type":
		return r.Type != ""
	case "target":
		return r.Target != ""
	case "ip":
		return r.IP != ""
	case "subnet":
		return r.Subnet != 0
	case "start_ip":
		return r.StartIP != ""
	case "end_ip":
		return r.EndIP != ""
	case "port":
		return r.Port != ""
	case "username":
		return r.Username != ""
	case "password":
		return r.Password != ""
	case "domain":
		return r.Domain != ""
	case "authentication_type":
		return r.AuthenticationType != ""
	case "protocol":
		return r.Protocol != ""
	case "schedule":
		return r.Schedule != nil
	default:
		return false
	}
}

// ApplyTo applies the update request fields to an existing scanner domain object
func (r ScannerUpdateRequest) ApplyTo(scanner *ScannerDomain) {
	if r.HasField("name") {
		scanner.Name = r.Name
	}
	if r.HasField("scan_type") {
		scanner.ScanType = r.ScanType
	}
	if r.HasField("status") {
		scanner.Status = *r.Status
	}
	if r.HasField("user_id") {
		scanner.UserID = r.UserID
	}
	if r.HasField("type") {
		scanner.Type = r.Type
	}
	if r.HasField("target") {
		scanner.Target = r.Target
	}
	if r.HasField("ip") {
		scanner.IP = r.IP
	}
	if r.HasField("subnet") {
		scanner.Subnet = r.Subnet
	}
	if r.HasField("start_ip") {
		scanner.StartIP = r.StartIP
	}
	if r.HasField("end_ip") {
		scanner.EndIP = r.EndIP
	}
	if r.HasField("port") {
		scanner.Port = r.Port
	}
	if r.HasField("username") {
		scanner.Username = r.Username
	}
	if r.HasField("password") {
		scanner.Password = r.Password
	}
	if r.HasField("domain") {
		scanner.Domain = r.Domain
	}
	if r.HasField("authentication_type") {
		scanner.AuthenticationType = r.AuthenticationType
	}
	if r.HasField("protocol") {
		scanner.Protocol = r.Protocol
	}
	if r.HasField("schedule") {
		// Merge schedule updates with existing schedule
		if scanner.Schedule != nil && r.Schedule != nil {
			mergeSchedule(scanner.Schedule, r.Schedule)
		} else if r.Schedule != nil {
			scanner.Schedule = r.Schedule
		}
	}

	// Always update the updated_at timestamp
	scanner.UpdatedAt = time.Now()
}

// mergeSchedule merges updates from the new schedule into the existing schedule
func mergeSchedule(existing *Schedule, updates *Schedule) {
	if updates.ScheduleType != "" {
		existing.ScheduleType = updates.ScheduleType
	}
	if updates.FrequencyValue > 0 {
		existing.FrequencyValue = updates.FrequencyValue
	}
	if updates.FrequencyUnit != "" {
		existing.FrequencyUnit = updates.FrequencyUnit
	}
	if !updates.RunTime.IsZero() {
		existing.RunTime = updates.RunTime
	}
	if updates.Month > 0 {
		existing.Month = updates.Month
	}
	if updates.Week > 0 {
		existing.Week = updates.Week
	}
	if updates.Day > 0 {
		existing.Day = updates.Day
	}
	if updates.Hour >= 0 {
		existing.Hour = updates.Hour
	}
	if updates.Minute >= 0 {
		existing.Minute = updates.Minute
	}
	existing.UpdatedAt = &[]time.Time{time.Now()}[0]
}
