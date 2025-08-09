package mapper

import (
	"database/sql"
	"strings"
	"time"
)

func ToNullTime(t time.Time) sql.NullTime {
	return sql.NullTime{
		Time:  t,
		Valid: !t.IsZero(),
	}
}

// NormalizeProtocol normalizes protocol values to valid database enum values
// Maps service names and protocol strings to 'TCP' or 'UDP'
func NormalizeProtocol(protocol string) string {
	if protocol == "" {
		return "TCP"
	}

	normalizedProtocol := strings.ToUpper(strings.TrimSpace(protocol))

	switch normalizedProtocol {
	case "TCP", "TCP/IP":
		return "TCP"
	case "UDP", "UDP/IP":
		return "UDP"
	}

	// Common TCP services
	tcpServices := map[string]bool{
		"SSH":        true,
		"HTTP":       true,
		"HTTPS":      true,
		"FTP":        true,
		"TELNET":     true,
		"SMTP":       true,
		"POP3":       true,
		"IMAP":       true,
		"LDAP":       true,
		"LDAPS":      true,
		"MYSQL":      true,
		"POSTGRES":   true,
		"MSSQL":      true,
		"ORACLE":     true,
		"RDP":        true,
		"VNC":        true,
		"SMB":        true,
		"CIFS":       true,
		"NFS":        true,
		"REDIS":      true,
		"MONGODB":    true,
		"ELASTIC":    true,
		"KIBANA":     true,
		"KAFKA":      true,
		"ZOOKEEPER":  true,
		"CONSUL":     true,
		"ETCD":       true,
		"GRAFANA":    true,
		"PROMETHEUS": true,
	}

	// Common UDP services
	udpServices := map[string]bool{
		"DNS":      true,
		"DHCP":     true,
		"TFTP":     true,
		"NTP":      true,
		"SNMP":     true,
		"SYSLOG":   true,
		"RADIUS":   true,
		"KERBEROS": true,
	}

	if tcpServices[normalizedProtocol] {
		return "TCP"
	}

	if udpServices[normalizedProtocol] {
		return "UDP"
	}

	return "TCP"
}
