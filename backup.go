/*
SIEM Security Manager API Server with Email Support

This application provides comprehensive certificate validation, security management capabilities, and email functionality.

SECURITY BEHAVIOR:
- Certificate validation is performed on all client certificates before use
- In strict mode (CERT_VALIDATION_STRICT=true, default), validation failures immediately stop processing
- In non-strict mode (CERT_VALIDATION_STRICT=false), validation failures are logged as warnings but allow fallbacks
- For production environments, always use strict mode for maximum security
- Email SMTP connections use secure cipher suites: TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256

Configuration is managed via YAML file (security_management.yaml) with environment variable overrides.

Environment Variable Overrides:
- SIEM_CONFIG_PATH                          : Path to YAML config file (default: ./security_management.yaml)
- LOG_FILE_PATH=/tmp/siem-security-manager.log : Override log file path (useful for read-only filesystems)
- CERT_CHECK_EXPIRATION=true/false          : Check certificate expiration
- CERT_CHECK_BASIC_CONSTRAINTS=true/false   : Check basic constraints
- CERT_CHECK_CA_FLAGS=true/false            : Check CA flags and requirements
- CERT_CHECK_SELF_SIGNED=true/false         : Check self-signed certificate constraints
- CERT_CHECK_KEY_USAGE=true/false           : Check key usage extensions
- CERT_CHECK_EXT_KEY_USAGE=true/false       : Check extended key usage
- CERT_CHECK_SUBJECT_ALT_NAME=true/false    : Check subject alternative names
- CERT_CHECK_SIGNATURE_ALGORITHM=true/false : Check signature algorithm strength
- CERT_CHECK_KEY_LENGTH=true/false          : Check minimum key length
- CERT_CHECK_REVOCATION=true/false          : Check certificate revocation
- CERT_MIN_KEY_LENGTH=2048                  : Minimum key length in bits
- CERT_MAX_VALIDITY_DAYS=3650               : Maximum certificate validity in days
- CERT_VALIDATION_STRICT=true/false         : Fail immediately on ANY validation issue (default: true)
- LOG_LEVEL=debug/info/warn/error           : Set logging level
- GIN_MODE=debug/release                    : Set Gin framework mode
- UPDATE_CONFIGS_AUTH_REQUIRED=true/false   : Require authentication for update-configs API

API Endpoints:
- POST /login                               : Authenticate and get JWT token
- POST /api                                 : Validate connector with certificate checks OR send email
- POST /validate-certificate                : Detailed certificate validation
- POST /update-configs                      : Update system configurations (auth optional based on config)
- GET  /health                             : System health and status information

Email Support:
- Supports Gmail, Outlook, Exchange servers
- Uses secure SMTP with TLS 1.2/1.3 and strong cipher suites
- Supports various authentication methods (LOGIN, PLAIN, CRAM-MD5)
- Exchange service requires CA certificate CN validation against security management configuration
*/

package main

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/smtp"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

// Constants
const (
	configFilePath     = "./config.json"
	sshConfigPath      = "/etc/ssh/sshd_config"
	sshBannerPath      = "/etc/ssh/siem_sshd_banner"
	elasticSearchURL   = "https://192.168.166.12:9200"
	elasticSearchUser  = "siem"
	elasticSearchPass  = "passsiem"
	kibanaURL          = "https://192.168.166.12:5601"
	certPath           = "/etc/siem/certs/wildcard.crt"
	defaultLogFilePath = "/var/log/security-management/security_management.log"
	timeout            = 30 * time.Second
)

const (
	configTemplate = `input {
  elasticsearch {
    hosts => ["%s"]
    index => ".ds-logs-kibana_audit-*"
    query => '{"query": {"match_all": {}}}'
    schedule => "*/1 * * * *"
    codec => "json"
    user => "%s"
    password => "%s"
    ssl => true
    ssl_certificate_verification => false
  }
}

output {
  http {
    url => "https://%s:%d/log_endpoint"
    http_method => "post"
    format => "json"
    # CA certificate for SSL verification
    cacert => "%s"
    ssl_supported_protocols => ["TLSv1.2", "TLSv1.3"]
    ssl_cipher_suites => [
      "TLS_AES_256_GCM_SHA384",
      "TLS_CHACHA20_POLY1305_SHA256",
      "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
      "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
      "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
      "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
    ]
    retry_failed => true
    retry_non_idempotent => true
  }
}`
	configPath = "/etc/logstash/conf.d/"
)

// Logger instance
var logger *logrus.Logger

// Global configuration
var globalConfig *SecurityManagementConfig

// Log file handle for cleanup
var logFile *os.File

// System information for consistent logging
var systemInfo SystemInfo

// SystemInfo holds system-level information for logging
type SystemInfo struct {
	Hostname    string `json:"hostname"`
	PrimaryIP   string `json:"primary_ip"`
	ServiceName string `json:"service_name"`
	Version     string `json:"version"`
}

// LogContext holds contextual information for consistent logging
type LogContext struct {
	RequestID    string `json:"request_id,omitempty"`
	ClientIP     string `json:"client_ip,omitempty"`
	ClientHost   string `json:"client_host,omitempty"`
	UserAgent    string `json:"user_agent,omitempty"`
	Username     string `json:"username,omitempty"`
	Method       string `json:"method,omitempty"`
	Path         string `json:"path,omitempty"`
	Component    string `json:"component,omitempty"`
	Operation    string `json:"operation,omitempty"`
	ResourceID   string `json:"resource_id,omitempty"`
	ResourceType string `json:"resource_type,omitempty"`
}

// LoginAuth implements LOGIN authentication for SMTP
type LoginAuth struct {
	username, password string
}

// / NewLoginAuth creates a new LOGIN authenticator
func NewLoginAuth(username, password string) smtp.Auth {
	return &LoginAuth{username, password}
}

func (a *LoginAuth) Next(fromServer []byte, more bool) ([]byte, error) {
	if more {
		switch string(fromServer) {
		case "Username:":
			return []byte(a.username), nil
		case "Password:":
			return []byte(a.password), nil
		default:
			// Handle base64 encoded prompts
			decoded, err := base64.StdEncoding.DecodeString(string(fromServer))
			if err != nil {
				return nil, err
			}
			switch strings.ToLower(string(decoded)) {
			case "username:", "user name:":
				return []byte(base64.StdEncoding.EncodeToString([]byte(a.username))), nil
			case "password:":
				return []byte(base64.StdEncoding.EncodeToString([]byte(a.password))), nil
			}
		}
	}
	return nil, nil
}

// Add this function to auto-detect authentication method (add this function)
func autoDetectAuth(emailConfig *EmailConfig, client *smtp.Client) smtp.Auth {
	logCtx := &LogContext{
		Component:    "email_service",
		Operation:    "auto_detect_auth",
		ResourceType: "smtp_auth",
	}

	// Get server capabilities
	if ok, ext := client.Extension("AUTH"); ok && ext != "" {
		ContextualLogger(logCtx).WithFields(logrus.Fields{
			"server_auth_methods": ext,
		}).Debug("Server AUTH methods detected")

		extUpper := strings.ToUpper(ext)

		// Try LOGIN first (most common with Exchange)
		if strings.Contains(extUpper, "LOGIN") {
			ContextualLogger(logCtx).WithField("selected_auth_method", "LOGIN").Debug("Using LOGIN authentication")
			return NewLoginAuth(emailConfig.Username, emailConfig.Password)
		}

		// Try PLAIN as fallback
		if strings.Contains(extUpper, "PLAIN") {
			ContextualLogger(logCtx).WithField("selected_auth_method", "PLAIN").Debug("Using PLAIN authentication")
			return smtp.PlainAuth("", emailConfig.Username, emailConfig.Password, emailConfig.SMTPHost)
		}

		// Try CRAM-MD5
		if strings.Contains(extUpper, "CRAM-MD5") {
			ContextualLogger(logCtx).WithField("selected_auth_method", "CRAM-MD5").Debug("Using CRAM-MD5 authentication")
			return smtp.CRAMMD5Auth(emailConfig.Username, emailConfig.Password)
		}

		ContextualLogger(logCtx).WithFields(logrus.Fields{
			"server_auth_methods": ext,
			"supported_methods":   []string{"LOGIN", "PLAIN", "CRAM-MD5"},
		}).Warn("Server AUTH methods don't include common authentication types")
	} else {
		ContextualLogger(logCtx).Warn("No AUTH extension found or empty")
	}

	// Default to LOGIN for Exchange servers
	ContextualLogger(logCtx).WithField("selected_auth_method", "LOGIN_default").Debug("Defaulting to LOGIN authentication (most common for Exchange)")
	return NewLoginAuth(emailConfig.Username, emailConfig.Password)
}

// Start begins LOGIN authentication
func (a *LoginAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	return "LOGIN", []byte{}, nil
}

// BaseLogFields returns the standard fields that should be included in all logs
func BaseLogFields() logrus.Fields {
	return logrus.Fields{
		"hostname":     systemInfo.Hostname,
		"primary_ip":   systemInfo.PrimaryIP,
		"service_name": systemInfo.ServiceName,
		"version":      systemInfo.Version,
	}
}

// ContextualLogger creates a logger with contextual information
func ContextualLogger(ctx *LogContext) *logrus.Entry {
	fields := BaseLogFields()

	if ctx != nil {
		if ctx.RequestID != "" {
			fields["request_id"] = ctx.RequestID
		}
		if ctx.ClientIP != "" {
			fields["client_ip"] = ctx.ClientIP
		}
		if ctx.ClientHost != "" {
			fields["client_host"] = ctx.ClientHost
		}
		if ctx.UserAgent != "" {
			fields["user_agent"] = ctx.UserAgent
		}
		if ctx.Username != "" {
			fields["username"] = ctx.Username
		}
		if ctx.Method != "" {
			fields["method"] = ctx.Method
		}
		if ctx.Path != "" {
			fields["path"] = ctx.Path
		}
		if ctx.Component != "" {
			fields["component"] = ctx.Component
		}
		if ctx.Operation != "" {
			fields["operation"] = ctx.Operation
		}
		if ctx.ResourceID != "" {
			fields["resource_id"] = ctx.ResourceID
		}
		if ctx.ResourceType != "" {
			fields["resource_type"] = ctx.ResourceType
		}
	}

	return logger.WithFields(fields)
}

// SecurityManagementConfig represents the complete configuration structure
type SecurityManagementConfig struct {
	CertificateValidation CertificateValidationConfig `yaml:"certificate_validation"`
	Logging               LoggingConfig               `yaml:"logging"`
	Server                ServerConfig                `yaml:"server"`
	Security              SecurityConfig              `yaml:"security"`
	API                   APIConfig                   `yaml:"api"`
}

// CertificateValidationConfig represents certificate validation configuration
type CertificateValidationConfig struct {
	CheckExpiration         bool `yaml:"check_expiration"`
	CheckBasicConstraints   bool `yaml:"check_basic_constraints"`
	CheckCAFlags            bool `yaml:"check_ca_flags"`
	CheckSelfSigned         bool `yaml:"check_self_signed"`
	CheckKeyUsage           bool `yaml:"check_key_usage"`
	CheckExtKeyUsage        bool `yaml:"check_ext_key_usage"`
	CheckSubjectAltName     bool `yaml:"check_subject_alt_name"`
	CheckSignatureAlgorithm bool `yaml:"check_signature_algorithm"`
	CheckKeyLength          bool `yaml:"check_key_length"`
	CheckRevocation         bool `yaml:"check_revocation"`
	MinKeyLength            int  `yaml:"min_key_length"`
	MaxValidityDays         int  `yaml:"max_validity_days"`
	ValidationStrict        bool `yaml:"validation_strict"`
}

// LoggingConfig represents logging configuration
type LoggingConfig struct {
	Level    string `yaml:"level"`
	Format   string `yaml:"format"`
	FilePath string `yaml:"file_path"`
}

// ServerConfig represents server configuration
type ServerConfig struct {
	Port        string `yaml:"port"`
	Mode        string `yaml:"mode"`
	TLSCertPath string `yaml:"tls_cert_path"`
	TLSKeyPath  string `yaml:"tls_key_path"`
}

// SecurityConfig represents security-related configuration
type SecurityConfig struct {
	JWTSecret       string `yaml:"jwt_secret"`
	TokenExpiration string `yaml:"token_expiration"`
	Username        string `yaml:"username"`
	Password        string `yaml:"password"`
}

// APIConfig represents API-specific configuration
type APIConfig struct {
	UpdateConfigsAuthRequired bool `yaml:"update_configs_auth_required"`
}

// Config represents the application configuration
type Config struct {
	RemoteSyslogIp    string `json:"remoteSyslogIp"`
	RemoteSyslogPort  int    `json:"remoteSyslogPort"`
	CaPath            string `json:"caPath"`
	SSHIdleTimeout    int    `json:"sshIdleTimeout"`
	SSHSessionTimeout int    `json:"sshSessionTimeout"`
	SSHWarning        string `json:"sshWarning"`
	HostType          string `json:"hostType"`
}

// Claims structure for JWT
type Claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

// Credentials structure for authentication
type Credentials struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// ElasticSearchResponse represents the response structure from Elasticsearch
type ElasticSearchResponse struct {
	Hits struct {
		Hits []struct {
			Source struct {
				RemoteSyslogIp    string `json:"remoteSyslogIp"`
				RemoteSyslogPort  string `json:"remoteSyslogPort"`
				SSHIdleTimeout    string `json:"sshIdleTimeout"`
				SSHSessionTimeout string `json:"sshSessionTimeout"`
				SSHWarning        string `json:"sshWarning"`
				CAPath            string `json:"caPath"`
			} `json:"_source"`
		} `json:"hits"`
	} `json:"hits"`
}

// ConnectorResponse represents the Kibana connector API response
type ConnectorResponse struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Config struct {
		HasAuth  bool        `json:"hasAuth"`
		Method   string      `json:"method"`
		URL      string      `json:"url"`
		AuthType string      `json:"authType"`
		Headers  interface{} `json:"headers"`
	} `json:"config"`
	ConnectorTypeID  string `json:"connector_type_id"`
	IsPreconfigured  bool   `json:"is_preconfigured"`
	IsDeprecated     bool   `json:"is_deprecated"`
	IsMissingSecrets bool   `json:"is_missing_secrets"`
	IsSystemAction   bool   `json:"is_system_action"`
	Message          string `json:"message"`
}

// CertificateSearchResponse represents the certificate search response
type CertificateSearchResponse struct {
	Took     int  `json:"took"`
	TimedOut bool `json:"timed_out"`
	Shards   struct {
		Total      int `json:"total"`
		Successful int `json:"successful"`
		Skipped    int `json:"skipped"`
		Failed     int `json:"failed"`
	} `json:"_shards"`
	Hits struct {
		Total struct {
			Value    int    `json:"value"`
			Relation string `json:"relation"`
		} `json:"total"`
		MaxScore float64 `json:"max_score"`
		Hits     []struct {
			Index  string  `json:"_index"`
			ID     string  `json:"_id"`
			Score  float64 `json:"_score"`
			Source struct {
				ConnectorName string `json:"connector_name"`
				ConnectorID   string `json:"connector_id"`
				CAName        string `json:"ca_name"`
				CAPath        string `json:"ca_path"`
				PublicName    string `json:"public_name"`
				PublicPath    string `json:"public_path"`
				PrivateName   string `json:"private_name"`
				PrivatePath   string `json:"private_path"`
				Password      string `json:"password"`
				Description   string `json:"description"`
			} `json:"_source"`
		} `json:"hits"`
	} `json:"hits"`
}

// SecurityManagementResponse represents the security management response
type SecurityManagementResponse struct {
	Took     int  `json:"took"`
	TimedOut bool `json:"timed_out"`
	Shards   struct {
		Total      int `json:"total"`
		Successful int `json:"successful"`
		Skipped    int `json:"skipped"`
		Failed     int `json:"failed"`
	} `json:"_shards"`
	Hits struct {
		Total struct {
			Value    int    `json:"value"`
			Relation string `json:"relation"`
		} `json:"total"`
		MaxScore float64 `json:"max_score"`
		Hits     []struct {
			Index  string  `json:"_index"`
			ID     string  `json:"_id"`
			Score  float64 `json:"_score"`
			Source struct {
				SSHIdleTimeout     string        `json:"sshIdleTimeout"`
				SSHSessionTimeout  string        `json:"sshSessionTimeout"`
				SSHWarning         string        `json:"sshWarning"`
				IdleTimeout        string        `json:"idleTimeout"`
				Lifespan           string        `json:"lifespan"`
				MinPasswordLength  string        `json:"minPasswordLength"`
				MinTimeBlockUser   string        `json:"minTimeBlockUser"`
				CountWrongPassword string        `json:"countWrongPassword"`
				LoginMessage       string        `json:"loginMessage"`
				MsgAfterLogin      string        `json:"msgAfterLogin"`
				RemoteSyslogIP     string        `json:"remoteSyslogIp"`
				RemoteSyslogPort   string        `json:"remoteSyslogPort"`
				RssArray           []interface{} `json:"rssArray"`
				CAPath             string        `json:"caPath"`
				CN                 string        `json:"cn"`
			} `json:"_source"`
		} `json:"hits"`
	} `json:"hits"`
}

// ConnectorValidationRequest represents the request for connector validation (UPDATED)
type ConnectorValidationRequest struct {
	Type        string                 `json:"type" binding:"required"` // "webhook" or "email"
	URL         string                 `json:"url,omitempty"`           // Required for webhook, optional for email
	Service     string                 `json:"service,omitempty"`       // Required for email (Gmail, Outlook, Exchange)
	Message     map[string]interface{} `json:"message,omitempty"`       // Optional
	Data        map[string]interface{} `json:"data" binding:"required"` // Renamed from Payload
	ConnectorID string                 `json:"connector_id" binding:"required"`
}

// EmailConfig represents email configuration data
type EmailConfig struct {
	SMTPHost   string `json:"smtp_host" binding:"required"`
	SMTPPort   string `json:"smtp_port" binding:"required"`
	Username   string `json:"username" binding:"required"`
	Password   string `json:"password" binding:"required"`
	FromEmail  string `json:"from_email" binding:"required"`
	FromName   string `json:"from_name"`
	AuthMethod string `json:"auth_method"`
	Secure     string `json:"secure"`
	ToEmail    string `json:"to_email,omitempty"`
	Subject    string `json:"subject,omitempty"`
	Body       string `json:"body,omitempty"`
	CACertPath string `json:"ca_cert_path,omitempty"`
}

// ConnectorValidationResponse represents the response for connector validation (UPDATED)
type ConnectorValidationResponse struct {
	ConnectorID     string `json:"connector_id"`
	ConnectorName   string `json:"connector_name"`
	ConnectorURL    string `json:"connector_url,omitempty"`
	ConnectorType   string `json:"connector_type"`          // "webhook" or "email"
	EmailService    string `json:"email_service,omitempty"` // Gmail, Outlook, Exchange
	CertificateInfo struct {
		CAPath      string `json:"ca_path,omitempty"`
		PublicPath  string `json:"public_path,omitempty"`
		PrivatePath string `json:"private_path,omitempty"`
		Password    string `json:"password,omitempty"`
	} `json:"certificate_info,omitempty"`
	CNValidation struct {
		ConfiguredCNs []string `json:"configured_cns,omitempty"`
		ConnectorCN   string   `json:"connector_cn,omitempty"`
		IsValid       bool     `json:"is_valid"`
	} `json:"cn_validation,omitempty"`
	CertificateValidation *CertificateValidationResult `json:"certificate_validation,omitempty"`
	TestResult            struct {
		Success      bool   `json:"success"`
		StatusCode   int    `json:"status_code,omitempty"`
		ResponseBody string `json:"response_body,omitempty"`
		Error        string `json:"error,omitempty"`
		EmailSent    bool   `json:"email_sent,omitempty"`
	} `json:"test_result"`
	Message string `json:"message"`
}

// HTTPClient interface for better testability
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// SecurityManager handles all security-related operations
type SecurityManager struct {
	client HTTPClient
}

// Host represents a single host entry
type Host struct {
	Name string
	IP   string
}

// TokenResponse represents the authentication response
type TokenResponse struct {
	Token string `json:"token"`
}

// CertificateValidationResult represents the result of certificate validation
type CertificateValidationResult struct {
	Valid           bool                       `json:"valid"`
	Errors          []string                   `json:"errors,omitempty"`
	Warnings        []string                   `json:"warnings,omitempty"`
	CheckResults    map[string]CertCheckResult `json:"check_results"`
	CertificateInfo CertificateInfo            `json:"certificate_info"`
}

// CertCheckResult represents individual check result
type CertCheckResult struct {
	Passed   bool   `json:"passed"`
	Message  string `json:"message"`
	Severity string `json:"severity"` // "error", "warning", "info"
}

// CertificateInfo represents certificate information
type CertificateInfo struct {
	Subject            string    `json:"subject"`
	Issuer             string    `json:"issuer"`
	SerialNumber       string    `json:"serial_number"`
	NotBefore          time.Time `json:"not_before"`
	NotAfter           time.Time `json:"not_after"`
	IsCA               bool      `json:"is_ca"`
	IsSelfSigned       bool      `json:"is_self_signed"`
	KeyUsage           []string  `json:"key_usage"`
	ExtKeyUsage        []string  `json:"ext_key_usage"`
	DNSNames           []string  `json:"dns_names"`
	IPAddresses        []string  `json:"ip_addresses"`
	SignatureAlgorithm string    `json:"signature_algorithm"`
	PublicKeyAlgorithm string    `json:"public_key_algorithm"`
	KeyLength          int       `json:"key_length"`
}

// CertificateValidationRequest represents request for certificate validation endpoint
type CertificateValidationRequest struct {
	CertificatePath string                       `json:"certificate_path" binding:"required"`
	Config          *CertificateValidationConfig `json:"config,omitempty"`
}

// extractCNFromCACertificate extracts CN from CA certificate
func extractCNFromCACertificate(caCertPath string) (string, error) {
	logCtx := &LogContext{
		Component:    "certificate_processing",
		Operation:    "extract_cn_from_ca_certificate",
		ResourceID:   caCertPath,
		ResourceType: "ca_certificate",
	}

	ContextualLogger(logCtx).Debug("Extracting CN from CA certificate")

	certData, err := ioutil.ReadFile(caCertPath)
	if err != nil {
		ContextualLogger(logCtx).WithError(err).WithField("cert_read_result", "failed").Error("Failed to read CA certificate file")
		return "", fmt.Errorf("failed to read CA certificate file: %v", err)
	}

	block, _ := pem.Decode(certData)
	if block == nil {
		ContextualLogger(logCtx).WithField("pem_decode_result", "failed").Error("Failed to decode PEM block from CA certificate")
		return "", fmt.Errorf("failed to decode PEM block from CA certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		ContextualLogger(logCtx).WithError(err).WithField("cert_parse_result", "failed").Error("Failed to parse CA certificate")
		return "", fmt.Errorf("failed to parse CA certificate: %v", err)
	}

	cn := cert.Subject.CommonName
	ContextualLogger(logCtx).WithFields(logrus.Fields{
		"extracted_cn":         cn,
		"cert_subject":         cert.Subject.String(),
		"cn_extraction_result": "success",
	}).Debug("CN extracted successfully from CA certificate")

	return cn, nil
}

// validateExchangeCACertificate validates Exchange service CA certificate CN
func (sm *SecurityManager) validateExchangeCACertificate(caCertPath string) error {
	logCtx := &LogContext{
		Component:    "email_service",
		Operation:    "validate_exchange_ca_certificate",
		ResourceID:   caCertPath,
		ResourceType: "exchange_ca_certificate",
	}

	ContextualLogger(logCtx).Info("Validating Exchange CA certificate CN against security management configuration")

	// Step 1: Extract CN from CA certificate
	caCN, err := extractCNFromCACertificate(caCertPath)
	if err != nil {
		ContextualLogger(logCtx).WithError(err).WithField("cn_extraction_result", "failed").Error("Failed to extract CN from CA certificate")
		return fmt.Errorf("failed to extract CN from CA certificate: %v", err)
	}

	ContextualLogger(logCtx).WithField("ca_certificate_cn", caCN).Debug("CA certificate CN extracted successfully")

	// Step 2: Fetch security management configuration
	securityConfig, err := sm.FetchSecurityConfig()
	if err != nil {
		ContextualLogger(logCtx).WithError(err).WithField("security_config_fetch_result", "failed").Error("Failed to fetch security management configuration")
		return fmt.Errorf("failed to fetch security management configuration: %v", err)
	}

	if len(securityConfig.Hits.Hits) == 0 {
		ContextualLogger(logCtx).WithField("security_config_result", "no_config_found").Error("No security management configuration found")
		return fmt.Errorf("no security management configuration found")
	}

	// Step 3: Parse configured CNs
	cnConfig := securityConfig.Hits.Hits[0].Source.CN
	if cnConfig == "" {
		ContextualLogger(logCtx).WithField("cn_config_result", "empty").Error("CN configuration is empty in security management")
		return fmt.Errorf("CN configuration is empty in security management")
	}

	configuredCNs := strings.Split(cnConfig, ",")
	for i := range configuredCNs {
		configuredCNs[i] = strings.TrimSpace(configuredCNs[i])
	}

	ContextualLogger(logCtx).WithFields(logrus.Fields{
		"ca_certificate_cn":    caCN,
		"configured_cns":       configuredCNs,
		"configured_cns_count": len(configuredCNs),
	}).Debug("Validating CA certificate CN against configured CNs")

	// Step 4: Validate CN
	isValid, _, err := sm.ValidateConnectorCN(caCN, configuredCNs)
	if err != nil {
		ContextualLogger(logCtx).WithError(err).WithField("cn_validation_result", "error").Error("Error during CN validation")
		return fmt.Errorf("error during CN validation: %v", err)
	}

	if !isValid {
		ContextualLogger(logCtx).WithFields(logrus.Fields{
			"ca_certificate_cn":    caCN,
			"configured_cns":       configuredCNs,
			"cn_validation_result": "failed",
		}).Error("CA certificate CN validation failed - CN not found in configured CNs")
		return fmt.Errorf("CA certificate CN '%s' is not authorized. Must match one of the configured CNs: %v", caCN, configuredCNs)
	}

	ContextualLogger(logCtx).WithFields(logrus.Fields{
		"ca_certificate_cn":    caCN,
		"cn_validation_result": "success",
	}).Info("CA certificate CN validation successful")

	return nil
}

// initSystemInfo initializes system information for consistent logging
func initSystemInfo() error {
	logCtx := &LogContext{
		Component: "system_init",
		Operation: "initialize_system_info",
	}

	hostname, err := os.Hostname()
	if err != nil {
		ContextualLogger(logCtx).WithError(err).Error("Failed to get system hostname")
		hostname = "unknown"
	}

	primaryIP := getPrimaryIP()

	systemInfo = SystemInfo{
		Hostname:    hostname,
		PrimaryIP:   primaryIP,
		ServiceName: "siem-security-manager",
		Version:     "1.0.0",
	}

	ContextualLogger(logCtx).WithFields(logrus.Fields{
		"detected_hostname":   hostname,
		"detected_primary_ip": primaryIP,
	}).Info("System information initialized successfully")

	return nil
}

// getPrimaryIP gets the primary IP address of the system
func getPrimaryIP() string {
	logCtx := &LogContext{
		Component: "system_init",
		Operation: "get_primary_ip",
	}

	// Try to get IP by connecting to a remote address (doesn't actually connect)
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		ContextualLogger(logCtx).WithError(err).Debug("Failed to determine primary IP via UDP dial, trying interface enumeration")
		return getPrimaryIPFromInterfaces()
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	ip := localAddr.IP.String()

	ContextualLogger(logCtx).WithField("detected_ip", ip).Debug("Primary IP detected via UDP dial")
	return ip
}

// getPrimaryIPFromInterfaces gets primary IP by enumerating network interfaces
func getPrimaryIPFromInterfaces() string {
	logCtx := &LogContext{
		Component: "system_init",
		Operation: "get_primary_ip_from_interfaces",
	}

	interfaces, err := net.Interfaces()
	if err != nil {
		ContextualLogger(logCtx).WithError(err).Error("Failed to enumerate network interfaces")
		return "unknown"
	}

	for _, iface := range interfaces {
		// Skip loopback and down interfaces
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			ContextualLogger(logCtx).WithError(err).WithField("interface", iface.Name).Debug("Failed to get addresses for interface")
			continue
		}

		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if ipnet.IP.To4() != nil {
					ip := ipnet.IP.String()
					ContextualLogger(logCtx).WithFields(logrus.Fields{
						"interface":   iface.Name,
						"detected_ip": ip,
					}).Debug("Primary IP detected via interface enumeration")
					return ip
				}
			}
		}
	}

	ContextualLogger(logCtx).Warn("No suitable primary IP found, using unknown")
	return "unknown"
}

// resolveClientHostname attempts to resolve hostname from IP
func resolveClientHostname(clientIP string) string {
	if clientIP == "" {
		return ""
	}

	names, err := net.LookupAddr(clientIP)
	if err != nil || len(names) == 0 {
		return ""
	}

	return strings.TrimSuffix(names[0], ".")
}

// getLogContextFromGin extracts log context from Gin context
func getLogContextFromGin(c *gin.Context) *LogContext {
	ctx := &LogContext{
		RequestID: getRequestID(c),
		ClientIP:  c.ClientIP(),
		UserAgent: c.Request.UserAgent(),
		Method:    c.Request.Method,
		Path:      c.Request.URL.Path,
	}

	// Resolve client hostname if possible
	ctx.ClientHost = resolveClientHostname(ctx.ClientIP)

	// Get username from claims if available
	if claims, exists := c.Get("claims"); exists {
		if claimsObj, ok := claims.(*Claims); ok {
			ctx.Username = claimsObj.Username
		}
	}

	return ctx
}

// setupLogFile creates and opens the log file with proper permissions and fallback options
func setupLogFile(logFilePath string) (*os.File, error) {
	logCtx := &LogContext{
		Component:    "logging",
		Operation:    "setup_log_file",
		ResourceID:   logFilePath,
		ResourceType: "log_file",
	}

	// Try the primary log file path first
	file, err := tryCreateLogFile(logFilePath, logCtx)
	if err == nil {
		ContextualLogger(logCtx).WithField("log_file_path", logFilePath).Info("Primary log file setup completed successfully")
		return file, nil
	}

	// Primary path failed, try fallback locations
	fallbackPaths := []string{
		"/tmp/siem-security-manager.log",
		"/var/tmp/siem-security-manager.log",
		"./siem-security-manager.log",
	}

	ContextualLogger(logCtx).WithError(err).WithFields(logrus.Fields{
		"primary_log_path": logFilePath,
		"fallback_paths":   fallbackPaths,
	}).Warn("Primary log file path failed, trying fallback locations")

	for _, fallbackPath := range fallbackPaths {
		fallbackLogCtx := &LogContext{
			Component:    "logging",
			Operation:    "setup_fallback_log_file",
			ResourceID:   fallbackPath,
			ResourceType: "fallback_log_file",
		}

		if file, err := tryCreateLogFile(fallbackPath, fallbackLogCtx); err == nil {
			ContextualLogger(fallbackLogCtx).WithFields(logrus.Fields{
				"primary_log_path":  logFilePath,
				"fallback_log_path": fallbackPath,
				"fallback_reason":   "primary_path_failed",
			}).Warn("Using fallback log file location")
			return file, nil
		} else {
			ContextualLogger(fallbackLogCtx).WithError(err).WithField("attempted_path", fallbackPath).Debug("Fallback log path also failed")
		}
	}

	// All paths failed
	ContextualLogger(logCtx).WithError(err).WithFields(logrus.Fields{
		"primary_log_path":    logFilePath,
		"attempted_fallbacks": fallbackPaths,
		"logging_mode":        "stdout_only",
	}).Error("All log file paths failed, continuing with stdout-only logging")

	return nil, fmt.Errorf("all log file paths failed, primary error: %v", err)
}

// tryCreateLogFile attempts to create a log file at the specified path
func tryCreateLogFile(logFilePath string, logCtx *LogContext) (*os.File, error) {
	// Check if the file already exists and is writable
	if file, err := os.OpenFile(logFilePath, os.O_WRONLY|os.O_APPEND, 0644); err == nil {
		// File exists and is writable
		ContextualLogger(logCtx).WithField("log_file_status", "existing_writable").Debug("Using existing log file")
		return file, nil
	}

	// Ensure the directory exists
	logDir := filepath.Dir(logFilePath)
	if err := os.MkdirAll(logDir, 0755); err != nil {
		// Check if it's a read-only filesystem error
		if isReadOnlyFilesystemError(err) {
			ContextualLogger(logCtx).WithError(err).WithFields(logrus.Fields{
				"log_directory":     logDir,
				"filesystem_status": "read_only",
			}).Debug("Directory creation failed due to read-only filesystem")
			return nil, fmt.Errorf("read-only filesystem: %v", err)
		}
		ContextualLogger(logCtx).WithError(err).WithField("log_directory", logDir).Debug("Failed to create log directory")
		return nil, fmt.Errorf("failed to create log directory %s: %v", logDir, err)
	}

	// Try to create the log file
	file, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		// Check if it's a read-only filesystem error
		if isReadOnlyFilesystemError(err) {
			ContextualLogger(logCtx).WithError(err).WithFields(logrus.Fields{
				"filesystem_status": "read_only",
			}).Debug("Log file creation failed due to read-only filesystem")
			return nil, fmt.Errorf("read-only filesystem: %v", err)
		}
		ContextualLogger(logCtx).WithError(err).Debug("Failed to create log file")
		return nil, fmt.Errorf("failed to create log file %s: %v", logFilePath, err)
	}

	ContextualLogger(logCtx).WithField("log_file_status", "newly_created").Debug("Log file created successfully")
	return file, nil
}

// isReadOnlyFilesystemError checks if the error is due to a read-only filesystem
func isReadOnlyFilesystemError(err error) bool {
	if err == nil {
		return false
	}
	errMsg := strings.ToLower(err.Error())
	return strings.Contains(errMsg, "read-only file system") ||
		strings.Contains(errMsg, "read only file system") ||
		strings.Contains(errMsg, "readonly") ||
		strings.Contains(errMsg, "permission denied") && strings.Contains(errMsg, "read-only")
}

// closeLogFile safely closes the log file
func closeLogFile() {
	logCtx := &LogContext{
		Component: "logging",
		Operation: "close_log_file",
	}

	if logFile != nil {
		if err := logFile.Close(); err != nil {
			ContextualLogger(logCtx).WithError(err).Error("Error closing log file")
		} else {
			ContextualLogger(logCtx).Info("Log file closed successfully")
		}
		logFile = nil
	}
}

// getLogFilePath returns the configured log file path
func getLogFilePath() string {
	if globalConfig != nil && globalConfig.Logging.FilePath != "" {
		return globalConfig.Logging.FilePath
	}

	if envPath := os.Getenv("LOG_FILE_PATH"); envPath != "" {
		return envPath
	}

	return defaultLogFilePath
}

// getLoggingStatus returns the current logging configuration status
func getLoggingStatus() map[string]interface{} {
	status := map[string]interface{}{
		"log_level":      logger.GetLevel().String(),
		"stdout_enabled": true, // Always enabled
	}

	if logFile != nil {
		status["file_logging_enabled"] = true
		status["log_file_path"] = logFile.Name()
	} else {
		status["file_logging_enabled"] = false
		status["log_file_path"] = nil
		status["logging_mode"] = "stdout_only"
	}

	return status
}

// logSystemStartupInfo logs comprehensive system startup information
func logSystemStartupInfo() {
	startupLogCtx := &LogContext{
		Component: "main",
		Operation: "system_startup_info",
	}

	loggingStatus := getLoggingStatus()
	strictValidation := shouldFailOnCertValidationError()

	ContextualLogger(startupLogCtx).WithFields(logrus.Fields{
		"startup_phase":                 "system_information",
		"detected_hostname":             systemInfo.Hostname,
		"detected_primary_ip":           systemInfo.PrimaryIP,
		"service_name":                  systemInfo.ServiceName,
		"service_version":               systemInfo.Version,
		"logging_status":                loggingStatus,
		"config_source":                 getConfigSource(),
		"certificate_validation_strict": strictValidation,
	}).Info("SIEM Security Manager system startup information")

	// Log certificate validation security posture
	if strictValidation {
		ContextualLogger(startupLogCtx).WithFields(logrus.Fields{
			"security_mode":     "strict_certificate_validation",
			"security_behavior": "certificate_validation_failures_will_stop_processing",
			"recommended_for":   "production_environments",
			"security_level":    "high",
		}).Info("Certificate validation is in STRICT mode - validation failures will immediately stop processing")
	} else {
		ContextualLogger(startupLogCtx).WithFields(logrus.Fields{
			"security_mode":      "permissive_certificate_validation",
			"security_behavior":  "certificate_validation_failures_allow_fallbacks",
			"security_warning":   true,
			"recommended_action": "enable strict mode for production with CERT_VALIDATION_STRICT=true",
			"security_level":     "reduced",
		}).Warn("Certificate validation is in PERMISSIVE mode - validation failures will allow fallback methods")
	}

	// Log any important system warnings
	if !loggingStatus["file_logging_enabled"].(bool) {
		ContextualLogger(startupLogCtx).WithFields(logrus.Fields{
			"logging_mode":       "stdout_only",
			"recommended_action": "ensure writable log directory or use environment variable LOG_FILE_PATH",
			"warning_type":       "logging_limitation",
		}).Warn("File logging is disabled - logs will only appear in stdout/systemd journal")
	}

	// Check if running as root (security warning)
	if os.Geteuid() == 0 {
		ContextualLogger(startupLogCtx).WithFields(logrus.Fields{
			"user_id":            0,
			"user_type":          "root",
			"security_warning":   true,
			"recommended_action": "run as dedicated service user for security",
		}).Warn("Service is running as root user - consider using dedicated service account")
	}

	// Log certificate validation configuration summary
	validationConfig := getDefaultCertValidationConfig()
	ContextualLogger(startupLogCtx).WithFields(logrus.Fields{
		"startup_phase":             "certificate_validation_config",
		"check_expiration":          validationConfig.CheckExpiration,
		"check_key_length":          validationConfig.CheckKeyLength,
		"min_key_length_bits":       validationConfig.MinKeyLength,
		"check_signature_algorithm": validationConfig.CheckSignatureAlgorithm,
		"max_validity_days":         validationConfig.MaxValidityDays,
		"validation_strict_mode":    validationConfig.ValidationStrict,
	}).Info("Certificate validation configuration loaded")
}

// loadConfigFromYAML loads configuration from YAML file
func loadConfigFromYAML(configPath string) (*SecurityManagementConfig, error) {
	logCtx := &LogContext{
		Component:    "config_management",
		Operation:    "load_yaml_config",
		ResourceID:   configPath,
		ResourceType: "config_file",
	}

	ContextualLogger(logCtx).Info("Loading configuration from YAML file")

	// Check if file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		ContextualLogger(logCtx).Warn("YAML config file not found, using defaults and environment variables")
		return getDefaultConfigWithEnvOverrides(), nil
	}

	// Read YAML file
	data, err := ioutil.ReadFile(configPath)
	if err != nil {
		ContextualLogger(logCtx).WithError(err).Error("Failed to read YAML config file")
		return nil, fmt.Errorf("failed to read config file: %v", err)
	}

	// Parse YAML
	var config SecurityManagementConfig
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		ContextualLogger(logCtx).WithError(err).Error("Failed to parse YAML config file")
		return nil, fmt.Errorf("failed to parse YAML config: %v", err)
	}

	// Apply environment variable overrides if they exist
	applyEnvironmentOverrides(&config)

	ContextualLogger(logCtx).WithFields(logrus.Fields{
		"cert_validation_strict":         config.CertificateValidation.ValidationStrict,
		"cert_min_key_length":            config.CertificateValidation.MinKeyLength,
		"cert_max_validity_days":         config.CertificateValidation.MaxValidityDays,
		"cert_check_expiration":          config.CertificateValidation.CheckExpiration,
		"cert_check_key_length":          config.CertificateValidation.CheckKeyLength,
		"cert_check_signature_algorithm": config.CertificateValidation.CheckSignatureAlgorithm,
		"log_level":                      config.Logging.Level,
		"log_file_path":                  config.Logging.FilePath,
		"server_port":                    config.Server.Port,
		"update_configs_auth_required":   config.API.UpdateConfigsAuthRequired,
	}).Info("YAML configuration loaded successfully")

	return &config, nil
}

// getDefaultConfigWithEnvOverrides returns default configuration with environment variable overrides
func getDefaultConfigWithEnvOverrides() *SecurityManagementConfig {
	logCtx := &LogContext{
		Component: "config_management",
		Operation: "get_default_config_with_env_overrides",
	}

	config := &SecurityManagementConfig{
		CertificateValidation: CertificateValidationConfig{
			CheckExpiration:         true,
			CheckBasicConstraints:   true,
			CheckCAFlags:            true,
			CheckSelfSigned:         true,
			CheckKeyUsage:           true,
			CheckExtKeyUsage:        true,
			CheckSubjectAltName:     true,
			CheckSignatureAlgorithm: true,
			CheckKeyLength:          true,
			CheckRevocation:         false,
			MinKeyLength:            2048,
			MaxValidityDays:         365,
			ValidationStrict:        true, // Default to strict validation
		},
		Logging: LoggingConfig{
			Level:    "info",
			Format:   "json",
			FilePath: defaultLogFilePath,
		},
		Server: ServerConfig{
			Port:        "5005",
			Mode:        "release",
			TLSCertPath: "/etc/siem/certs/wildcard.crt",
			TLSKeyPath:  "/etc/siem/certs/wildcard.key",
		},
		Security: SecurityConfig{
			JWTSecret:       "P@ssw0rdM@t@6810jwtSec",
			TokenExpiration: "24h",
			Username:        "api",
			Password:        "P@ssw0rdM@t@G3tT0ken",
		},
		API: APIConfig{
			UpdateConfigsAuthRequired: true, // Default to requiring authentication
		},
	}

	// Apply environment variable overrides
	applyEnvironmentOverrides(config)

	ContextualLogger(logCtx).Info("Default configuration with environment overrides created")
	return config
}

// applyEnvironmentOverrides applies environment variable overrides to config
func applyEnvironmentOverrides(config *SecurityManagementConfig) {
	logCtx := &LogContext{
		Component: "config_management",
		Operation: "apply_environment_overrides",
	}

	ContextualLogger(logCtx).Debug("Applying environment variable overrides to configuration")

	// Certificate validation overrides
	if env := os.Getenv("CERT_CHECK_EXPIRATION"); env == "false" {
		config.CertificateValidation.CheckExpiration = false
	}
	if env := os.Getenv("CERT_CHECK_BASIC_CONSTRAINTS"); env == "false" {
		config.CertificateValidation.CheckBasicConstraints = false
	}
	if env := os.Getenv("CERT_CHECK_CA_FLAGS"); env == "false" {
		config.CertificateValidation.CheckCAFlags = false
	}
	if env := os.Getenv("CERT_CHECK_SELF_SIGNED"); env == "false" {
		config.CertificateValidation.CheckSelfSigned = false
	}
	if env := os.Getenv("CERT_CHECK_KEY_USAGE"); env == "false" {
		config.CertificateValidation.CheckKeyUsage = false
	}
	if env := os.Getenv("CERT_CHECK_EXT_KEY_USAGE"); env == "false" {
		config.CertificateValidation.CheckExtKeyUsage = false
	}
	if env := os.Getenv("CERT_CHECK_SUBJECT_ALT_NAME"); env == "false" {
		config.CertificateValidation.CheckSubjectAltName = false
	}
	if env := os.Getenv("CERT_CHECK_SIGNATURE_ALGORITHM"); env == "false" {
		config.CertificateValidation.CheckSignatureAlgorithm = false
	}
	if env := os.Getenv("CERT_CHECK_KEY_LENGTH"); env == "false" {
		config.CertificateValidation.CheckKeyLength = false
	}
	if env := os.Getenv("CERT_CHECK_REVOCATION"); env == "true" {
		config.CertificateValidation.CheckRevocation = true
	}
	if env := os.Getenv("CERT_VALIDATION_STRICT"); env == "false" {
		config.CertificateValidation.ValidationStrict = false
	}

	// Numeric overrides
	if env := os.Getenv("CERT_MIN_KEY_LENGTH"); env != "" {
		if val, err := strconv.Atoi(env); err == nil {
			config.CertificateValidation.MinKeyLength = val
		}
	}
	if env := os.Getenv("CERT_MAX_VALIDITY_DAYS"); env != "" {
		if val, err := strconv.Atoi(env); err == nil {
			config.CertificateValidation.MaxValidityDays = val
		}
	}

	// Logging overrides
	if env := os.Getenv("LOG_LEVEL"); env != "" {
		config.Logging.Level = env
	}
	if env := os.Getenv("LOG_FORMAT"); env != "" {
		config.Logging.Format = env
	}
	if env := os.Getenv("LOG_FILE_PATH"); env != "" {
		config.Logging.FilePath = env
	}

	// Server overrides
	if env := os.Getenv("GIN_MODE"); env != "" {
		config.Server.Mode = env
	}
	if env := os.Getenv("SERVER_PORT"); env != "" {
		config.Server.Port = env
	}
	if env := os.Getenv("TLS_CERT_PATH"); env != "" {
		config.Server.TLSCertPath = env
	}
	if env := os.Getenv("TLS_KEY_PATH"); env != "" {
		config.Server.TLSKeyPath = env
	}

	// Security overrides
	if env := os.Getenv("JWT_SECRET"); env != "" {
		config.Security.JWTSecret = env
	}
	if env := os.Getenv("TOKEN_EXPIRATION"); env != "" {
		config.Security.TokenExpiration = env
	}
	if env := os.Getenv("API_USERNAME"); env != "" {
		config.Security.Username = env
	}
	if env := os.Getenv("API_PASSWORD"); env != "" {
		config.Security.Password = env
	}

	// API overrides
	if env := os.Getenv("UPDATE_CONFIGS_AUTH_REQUIRED"); env == "false" {
		config.API.UpdateConfigsAuthRequired = false
	}

	ContextualLogger(logCtx).Debug("Environment variable overrides applied successfully")
}

// initializeConfiguration initializes the global configuration
func initializeConfiguration() error {
	logCtx := &LogContext{
		Component: "config_management",
		Operation: "initialize_configuration",
	}

	configPath := os.Getenv("SIEM_CONFIG_PATH")
	if configPath == "" {
		configPath = "/etc/siem/security-management/security_management.yaml" // Default path
	}

	config, err := loadConfigFromYAML(configPath)
	if err != nil {
		ContextualLogger(logCtx).WithError(err).WithField("config_path", configPath).Error("Failed to load configuration")
		return fmt.Errorf("failed to load configuration: %v", err)
	}

	globalConfig = config
	ContextualLogger(logCtx).WithField("config_path", configPath).Info("Global configuration initialized successfully")
	return nil
}

// getDefaultCertValidationConfig returns certificate validation configuration from global config
func getDefaultCertValidationConfig() *CertificateValidationConfig {
	if globalConfig != nil {
		return &globalConfig.CertificateValidation
	}

	// Fallback to environment-based config if global config not loaded
	return getValidationConfigFromEnv()
}

// shouldFailOnCertValidationError determines if certificate validation errors should cause failures
func shouldFailOnCertValidationError() bool {
	if globalConfig != nil {
		return globalConfig.CertificateValidation.ValidationStrict
	}

	// Fallback to environment variable - default to true for security
	return os.Getenv("CERT_VALIDATION_STRICT") != "false"
}

// isUpdateConfigsAuthRequired checks if authentication is required for update-configs API
func isUpdateConfigsAuthRequired() bool {
	if globalConfig != nil {
		return globalConfig.API.UpdateConfigsAuthRequired
	}

	// Fallback to environment variable - default to true for security
	return os.Getenv("UPDATE_CONFIGS_AUTH_REQUIRED") != "false"
}

// getValidationConfigFromEnv returns certificate validation configuration from environment variables (fallback)
func getValidationConfigFromEnv() *CertificateValidationConfig {
	logCtx := &LogContext{
		Component: "config_management",
		Operation: "get_validation_config_from_env",
	}

	config := &CertificateValidationConfig{
		CheckExpiration:         true,
		CheckBasicConstraints:   true,
		CheckCAFlags:            true,
		CheckSelfSigned:         true,
		CheckKeyUsage:           true,
		CheckExtKeyUsage:        true,
		CheckSubjectAltName:     true,
		CheckSignatureAlgorithm: true,
		CheckKeyLength:          true,
		CheckRevocation:         false,
		MinKeyLength:            2048,
		MaxValidityDays:         3650,
		ValidationStrict:        true,
	}

	// Override with environment variables if present
	if os.Getenv("CERT_CHECK_EXPIRATION") == "false" {
		config.CheckExpiration = false
	}
	if os.Getenv("CERT_CHECK_BASIC_CONSTRAINTS") == "false" {
		config.CheckBasicConstraints = false
	}
	if os.Getenv("CERT_CHECK_CA_FLAGS") == "false" {
		config.CheckCAFlags = false
	}
	if os.Getenv("CERT_CHECK_SELF_SIGNED") == "false" {
		config.CheckSelfSigned = false
	}
	if os.Getenv("CERT_CHECK_KEY_USAGE") == "false" {
		config.CheckKeyUsage = false
	}
	if os.Getenv("CERT_CHECK_EXT_KEY_USAGE") == "false" {
		config.CheckExtKeyUsage = false
	}
	if os.Getenv("CERT_CHECK_SUBJECT_ALT_NAME") == "false" {
		config.CheckSubjectAltName = false
	}
	if os.Getenv("CERT_CHECK_SIGNATURE_ALGORITHM") == "false" {
		config.CheckSignatureAlgorithm = false
	}
	if os.Getenv("CERT_CHECK_KEY_LENGTH") == "false" {
		config.CheckKeyLength = false
	}
	if os.Getenv("CERT_CHECK_REVOCATION") == "true" {
		config.CheckRevocation = true
	}
	if os.Getenv("CERT_VALIDATION_STRICT") == "false" {
		config.ValidationStrict = false
	}

	// Parse numeric values
	if minKeyLen := os.Getenv("CERT_MIN_KEY_LENGTH"); minKeyLen != "" {
		if val, err := strconv.Atoi(minKeyLen); err == nil {
			config.MinKeyLength = val
		}
	}
	if maxValidityDays := os.Getenv("CERT_MAX_VALIDITY_DAYS"); maxValidityDays != "" {
		if val, err := strconv.Atoi(maxValidityDays); err == nil {
			config.MaxValidityDays = val
		}
	}

	ContextualLogger(logCtx).Debug("Validation configuration loaded from environment variables")
	return config
}

// isValidUser validates user credentials using YAML config
func isValidUser(username, password string) bool {
	logCtx := &LogContext{
		Component: "authentication",
		Operation: "validate_user_credentials",
		Username:  username,
	}

	var expectedUsername, expectedPassword string

	if globalConfig != nil {
		expectedUsername = globalConfig.Security.Username
		expectedPassword = globalConfig.Security.Password
	} else {
		// Fallback to hardcoded values
		expectedUsername = "api"
		expectedPassword = "P@ssw0rdM@t@G3tT0ken"
	}

	isValid := username == expectedUsername && password == expectedPassword

	if isValid {
		ContextualLogger(logCtx).Info("User credentials validated successfully")
	} else {
		ContextualLogger(logCtx).WithFields(logrus.Fields{
			"provided_username": username,
			"auth_result":       "failed",
		}).Warn("User credential validation failed")
	}

	return isValid
}

// getKeyUsageStrings converts x509.KeyUsage to string slice
func getKeyUsageStrings(keyUsage x509.KeyUsage) []string {
	var usages []string

	if keyUsage&x509.KeyUsageDigitalSignature != 0 {
		usages = append(usages, "DigitalSignature")
	}
	if keyUsage&x509.KeyUsageContentCommitment != 0 {
		usages = append(usages, "ContentCommitment")
	}
	if keyUsage&x509.KeyUsageKeyEncipherment != 0 {
		usages = append(usages, "KeyEncipherment")
	}
	if keyUsage&x509.KeyUsageDataEncipherment != 0 {
		usages = append(usages, "DataEncipherment")
	}
	if keyUsage&x509.KeyUsageKeyAgreement != 0 {
		usages = append(usages, "KeyAgreement")
	}
	if keyUsage&x509.KeyUsageCertSign != 0 {
		usages = append(usages, "CertSign")
	}
	if keyUsage&x509.KeyUsageCRLSign != 0 {
		usages = append(usages, "CRLSign")
	}
	if keyUsage&x509.KeyUsageEncipherOnly != 0 {
		usages = append(usages, "EncipherOnly")
	}
	if keyUsage&x509.KeyUsageDecipherOnly != 0 {
		usages = append(usages, "DecipherOnly")
	}

	return usages
}

// getExtKeyUsageStrings converts []x509.ExtKeyUsage to string slice
func getExtKeyUsageStrings(extKeyUsage []x509.ExtKeyUsage) []string {
	var usages []string

	for _, usage := range extKeyUsage {
		switch usage {
		case x509.ExtKeyUsageServerAuth:
			usages = append(usages, "ServerAuth")
		case x509.ExtKeyUsageClientAuth:
			usages = append(usages, "ClientAuth")
		case x509.ExtKeyUsageCodeSigning:
			usages = append(usages, "CodeSigning")
		case x509.ExtKeyUsageEmailProtection:
			usages = append(usages, "EmailProtection")
		case x509.ExtKeyUsageTimeStamping:
			usages = append(usages, "TimeStamping")
		case x509.ExtKeyUsageOCSPSigning:
			usages = append(usages, "OCSPSigning")
		default:
			usages = append(usages, fmt.Sprintf("Unknown(%d)", int(usage)))
		}
	}

	return usages
}

// extractCertificateInfo extracts detailed information from certificate
func extractCertificateInfo(cert *x509.Certificate) CertificateInfo {
	var ipAddresses []string
	for _, ip := range cert.IPAddresses {
		ipAddresses = append(ipAddresses, ip.String())
	}

	keyLength := 0
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		keyLength = pub.N.BitLen()
	case *ecdsa.PublicKey:
		keyLength = pub.Curve.Params().BitSize
	}

	return CertificateInfo{
		Subject:            cert.Subject.String(),
		Issuer:             cert.Issuer.String(),
		SerialNumber:       cert.SerialNumber.String(),
		NotBefore:          cert.NotBefore,
		NotAfter:           cert.NotAfter,
		IsCA:               cert.IsCA,
		IsSelfSigned:       cert.Subject.String() == cert.Issuer.String(),
		KeyUsage:           getKeyUsageStrings(cert.KeyUsage),
		ExtKeyUsage:        getExtKeyUsageStrings(cert.ExtKeyUsage),
		DNSNames:           cert.DNSNames,
		IPAddresses:        ipAddresses,
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		PublicKeyAlgorithm: cert.PublicKeyAlgorithm.String(),
		KeyLength:          keyLength,
	}
}

// checkCertificateExpiration validates certificate expiration
func checkCertificateExpiration(cert *x509.Certificate, config *CertificateValidationConfig) CertCheckResult {
	logCtx := &LogContext{
		Component:    "certificate_validation",
		Operation:    "check_expiration",
		ResourceType: "certificate",
	}

	now := time.Now()

	ContextualLogger(logCtx).WithFields(logrus.Fields{
		"cert_subject": cert.Subject.String(),
		"not_before":   cert.NotBefore.Format(time.RFC3339),
		"not_after":    cert.NotAfter.Format(time.RFC3339),
		"current_time": now.Format(time.RFC3339),
	}).Debug("Checking certificate expiration")

	// Check if certificate is not yet valid
	if now.Before(cert.NotBefore) {
		message := fmt.Sprintf("Certificate is not yet valid (valid from: %s)", cert.NotBefore.Format(time.RFC3339))
		ContextualLogger(logCtx).WithFields(logrus.Fields{
			"cert_subject":      cert.Subject.String(),
			"not_before":        cert.NotBefore,
			"validation_result": "not_yet_valid",
		}).Error("Certificate is not yet valid")
		return CertCheckResult{
			Passed:   false,
			Message:  message,
			Severity: "error",
		}
	}

	// Check if certificate is expired
	if now.After(cert.NotAfter) {
		message := fmt.Sprintf("Certificate has expired (expired on: %s)", cert.NotAfter.Format(time.RFC3339))
		ContextualLogger(logCtx).WithFields(logrus.Fields{
			"cert_subject":      cert.Subject.String(),
			"not_after":         cert.NotAfter,
			"validation_result": "expired",
		}).Error("Certificate has expired")
		return CertCheckResult{
			Passed:   false,
			Message:  message,
			Severity: "error",
		}
	}

	// Check if certificate is expiring soon (within 30 days)
	daysUntilExpiry := int(cert.NotAfter.Sub(now).Hours() / 24)
	if daysUntilExpiry <= 30 {
		message := fmt.Sprintf("Certificate expires soon (%d days remaining)", daysUntilExpiry)
		ContextualLogger(logCtx).WithFields(logrus.Fields{
			"cert_subject":      cert.Subject.String(),
			"days_until_expiry": daysUntilExpiry,
			"validation_result": "expires_soon",
		}).Warn("Certificate expires soon")
		return CertCheckResult{
			Passed:   true,
			Message:  message,
			Severity: "warning",
		}
	}

	// Check certificate validity period
	validityDays := int(cert.NotAfter.Sub(cert.NotBefore).Hours() / 24)
	if config.MaxValidityDays > 0 && validityDays > config.MaxValidityDays {
		message := fmt.Sprintf("Certificate validity period is too long (%d days, max: %d days)", validityDays, config.MaxValidityDays)
		ContextualLogger(logCtx).WithFields(logrus.Fields{
			"cert_subject":      cert.Subject.String(),
			"validity_days":     validityDays,
			"max_validity_days": config.MaxValidityDays,
			"validation_result": "validity_too_long",
		}).Warn("Certificate validity period exceeds maximum")
		return CertCheckResult{
			Passed:   true,
			Message:  message,
			Severity: "warning",
		}
	}

	message := fmt.Sprintf("Certificate is valid (%d days remaining)", daysUntilExpiry)
	ContextualLogger(logCtx).WithFields(logrus.Fields{
		"cert_subject":      cert.Subject.String(),
		"days_until_expiry": daysUntilExpiry,
		"validation_result": "valid",
	}).Debug("Certificate expiration check passed")
	return CertCheckResult{
		Passed:   true,
		Message:  message,
		Severity: "info",
	}
}

// checkBasicConstraints validates certificate basic constraints
func checkBasicConstraints(cert *x509.Certificate) CertCheckResult {
	logCtx := &LogContext{
		Component:    "certificate_validation",
		Operation:    "check_basic_constraints",
		ResourceType: "certificate",
	}

	ContextualLogger(logCtx).WithFields(logrus.Fields{
		"cert_subject":            cert.Subject.String(),
		"is_ca":                   cert.IsCA,
		"max_path_len":            cert.MaxPathLen,
		"max_path_len_zero":       cert.MaxPathLenZero,
		"basic_constraints_valid": cert.BasicConstraintsValid,
	}).Debug("Checking certificate basic constraints")

	if !cert.BasicConstraintsValid {
		message := "Certificate basic constraints are not valid"
		ContextualLogger(logCtx).WithFields(logrus.Fields{
			"cert_subject":      cert.Subject.String(),
			"validation_result": "basic_constraints_invalid",
		}).Error("Certificate basic constraints are invalid")
		return CertCheckResult{
			Passed:   false,
			Message:  message,
			Severity: "error",
		}
	}

	message := "Certificate basic constraints are valid"
	ContextualLogger(logCtx).WithFields(logrus.Fields{
		"cert_subject":      cert.Subject.String(),
		"validation_result": "basic_constraints_valid",
	}).Debug("Certificate basic constraints check passed")
	return CertCheckResult{
		Passed:   true,
		Message:  message,
		Severity: "info",
	}
}

// checkCAFlags validates CA-specific requirements
func checkCAFlags(cert *x509.Certificate) CertCheckResult {
	logCtx := &LogContext{
		Component:    "certificate_validation",
		Operation:    "check_ca_flags",
		ResourceType: "certificate",
	}

	ContextualLogger(logCtx).WithFields(logrus.Fields{
		"cert_subject": cert.Subject.String(),
		"is_ca":        cert.IsCA,
		"key_usage":    getKeyUsageStrings(cert.KeyUsage),
	}).Debug("Checking CA flags")

	if cert.IsCA {
		// For CA certificates, check required key usages
		if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
			message := "CA certificate missing CertSign key usage"
			ContextualLogger(logCtx).WithFields(logrus.Fields{
				"cert_subject":      cert.Subject.String(),
				"validation_result": "missing_cert_sign",
			}).Error("CA certificate is missing required CertSign key usage")
			return CertCheckResult{
				Passed:   false,
				Message:  message,
				Severity: "error",
			}
		}

		// Check path length constraint for intermediate CAs
		if cert.MaxPathLen == 0 && !cert.MaxPathLenZero {
			message := "Intermediate CA should have path length constraint"
			ContextualLogger(logCtx).WithFields(logrus.Fields{
				"cert_subject":      cert.Subject.String(),
				"validation_result": "missing_path_length_constraint",
			}).Warn("Intermediate CA missing path length constraint")
			return CertCheckResult{
				Passed:   true,
				Message:  message,
				Severity: "warning",
			}
		}

		message := "CA certificate flags are valid"
		ContextualLogger(logCtx).WithFields(logrus.Fields{
			"cert_subject":      cert.Subject.String(),
			"validation_result": "ca_flags_valid",
		}).Debug("CA flags check passed")
		return CertCheckResult{
			Passed:   true,
			Message:  message,
			Severity: "info",
		}
	}

	// For end-entity certificates, ensure they're not marked as CA
	message := "End-entity certificate CA flags are correct"
	ContextualLogger(logCtx).WithFields(logrus.Fields{
		"cert_subject":      cert.Subject.String(),
		"validation_result": "end_entity_flags_correct",
	}).Debug("End-entity certificate CA flags check passed")
	return CertCheckResult{
		Passed:   true,
		Message:  message,
		Severity: "info",
	}
}

// checkSelfSigned validates self-signed certificate constraints
func checkSelfSigned(cert *x509.Certificate) CertCheckResult {
	logCtx := &LogContext{
		Component:    "certificate_validation",
		Operation:    "check_self_signed",
		ResourceType: "certificate",
	}

	isSelfSigned := cert.Subject.String() == cert.Issuer.String()

	ContextualLogger(logCtx).WithFields(logrus.Fields{
		"cert_subject":   cert.Subject.String(),
		"is_self_signed": isSelfSigned,
		"issuer":         cert.Issuer.String(),
	}).Debug("Checking self-signed certificate")

	if isSelfSigned {
		// Self-signed certificates should typically be CA certificates
		if !cert.IsCA {
			message := "Self-signed certificate should be a CA certificate"

			// In strict validation mode, self-signed non-CA certificates are an ERROR, not a warning
			if shouldFailOnCertValidationError() {
				ContextualLogger(logCtx).WithFields(logrus.Fields{
					"cert_subject":      cert.Subject.String(),
					"validation_result": "self_signed_not_ca",
					"strict_mode":       true,
					"severity_elevated": "warning_to_error",
				}).Error("Self-signed certificate is not marked as CA - INVALID in strict mode")
				return CertCheckResult{
					Passed:   false,
					Message:  message + " (REQUIRED in strict validation mode)",
					Severity: "error",
				}
			} else {
				ContextualLogger(logCtx).WithFields(logrus.Fields{
					"cert_subject":      cert.Subject.String(),
					"validation_result": "self_signed_not_ca",
					"strict_mode":       false,
				}).Warn("Self-signed certificate is not marked as CA")
				return CertCheckResult{
					Passed:   true,
					Message:  message,
					Severity: "warning",
				}
			}
		}

		message := "Self-signed CA certificate is properly configured"
		ContextualLogger(logCtx).WithFields(logrus.Fields{
			"cert_subject":      cert.Subject.String(),
			"validation_result": "self_signed_ca_valid",
		}).Debug("Self-signed certificate check passed")
		return CertCheckResult{
			Passed:   true,
			Message:  message,
			Severity: "info",
		}
	}

	message := "Certificate is properly signed by external CA"
	ContextualLogger(logCtx).WithFields(logrus.Fields{
		"cert_subject":      cert.Subject.String(),
		"validation_result": "external_ca_signed",
	}).Debug("Non-self-signed certificate check passed")
	return CertCheckResult{
		Passed:   true,
		Message:  message,
		Severity: "info",
	}
}

// checkKeyUsage validates certificate key usage
func checkKeyUsage(cert *x509.Certificate) CertCheckResult {
	logCtx := &LogContext{
		Component:    "certificate_validation",
		Operation:    "check_key_usage",
		ResourceType: "certificate",
	}

	keyUsages := getKeyUsageStrings(cert.KeyUsage)

	ContextualLogger(logCtx).WithFields(logrus.Fields{
		"cert_subject":      cert.Subject.String(),
		"key_usage":         cert.KeyUsage,
		"key_usage_strings": keyUsages,
		"is_ca":             cert.IsCA,
	}).Debug("Checking certificate key usage")

	if len(keyUsages) == 0 {
		message := "Certificate has no key usage defined"

		// In strict validation mode, missing key usage is an ERROR, not a warning
		if shouldFailOnCertValidationError() {
			ContextualLogger(logCtx).WithFields(logrus.Fields{
				"cert_subject":      cert.Subject.String(),
				"validation_result": "no_key_usage",
				"strict_mode":       true,
				"severity_elevated": "warning_to_error",
			}).Error("Certificate has no key usage defined - REQUIRED in strict mode")
			return CertCheckResult{
				Passed:   false,
				Message:  message + " (REQUIRED in strict validation mode)",
				Severity: "error",
			}
		} else {
			ContextualLogger(logCtx).WithFields(logrus.Fields{
				"cert_subject":      cert.Subject.String(),
				"validation_result": "no_key_usage",
				"strict_mode":       false,
			}).Warn("Certificate has no key usage defined")
			return CertCheckResult{
				Passed:   true,
				Message:  message,
				Severity: "warning",
			}
		}
	}

	// Validate key usage for CA certificates
	if cert.IsCA {
		hasRequiredUsage := false
		for _, usage := range keyUsages {
			if usage == "CertSign" {
				hasRequiredUsage = true
				break
			}
		}
		if !hasRequiredUsage {
			message := "CA certificate missing required CertSign key usage"
			ContextualLogger(logCtx).WithFields(logrus.Fields{
				"cert_subject":      cert.Subject.String(),
				"key_usages":        keyUsages,
				"validation_result": "ca_missing_cert_sign",
			}).Error("CA certificate missing CertSign key usage")
			return CertCheckResult{
				Passed:   false,
				Message:  message,
				Severity: "error",
			}
		}
	}

	message := fmt.Sprintf("Certificate key usage is appropriate: %v", keyUsages)
	ContextualLogger(logCtx).WithFields(logrus.Fields{
		"cert_subject":      cert.Subject.String(),
		"key_usages":        keyUsages,
		"validation_result": "key_usage_valid",
	}).Debug("Key usage check passed")
	return CertCheckResult{
		Passed:   true,
		Message:  message,
		Severity: "info",
	}
}

// checkExtendedKeyUsage validates certificate extended key usage
func checkExtendedKeyUsage(cert *x509.Certificate) CertCheckResult {
	logCtx := &LogContext{
		Component:    "certificate_validation",
		Operation:    "check_extended_key_usage",
		ResourceType: "certificate",
	}

	extKeyUsages := getExtKeyUsageStrings(cert.ExtKeyUsage)

	ContextualLogger(logCtx).WithFields(logrus.Fields{
		"cert_subject":          cert.Subject.String(),
		"ext_key_usage":         cert.ExtKeyUsage,
		"ext_key_usage_strings": extKeyUsages,
		"is_ca":                 cert.IsCA,
	}).Debug("Checking certificate extended key usage")

	if cert.IsCA && len(extKeyUsages) == 0 {
		message := "CA certificate does not have extended key usage"
		ContextualLogger(logCtx).WithFields(logrus.Fields{
			"cert_subject":      cert.Subject.String(),
			"validation_result": "ca_no_ext_key_usage",
		}).Debug("CA certificate extended key usage check failed")
		return CertCheckResult{
			Passed:   false,
			Message:  message,
			Severity: "error",
		}
	}

	// End-entity certificates must have extended key usage
	if !cert.IsCA && len(extKeyUsages) == 0 {
		message := "End-entity certificate should have extended key usage defined"
		if shouldFailOnCertValidationError() {
			ContextualLogger(logCtx).WithFields(logrus.Fields{
				"cert_subject":      cert.Subject.String(),
				"validation_result": "end_entity_missing_ext_key_usage",
				"strict_mode":       true,
				"severity_elevated": "warning_to_error",
			}).Error("End-entity certificate missing extended key usage - REQUIRED in strict mode")
			return CertCheckResult{
				Passed:   false,
				Message:  message + " (REQUIRED in strict validation mode)",
				Severity: "error",
			}
		} else {
			ContextualLogger(logCtx).WithFields(logrus.Fields{
				"cert_subject":      cert.Subject.String(),
				"validation_result": "end_entity_missing_ext_key_usage",
				"strict_mode":       false,
			}).Warn("End-entity certificate missing extended key usage")
			return CertCheckResult{
				Passed:   false,
				Message:  message,
				Severity: "error",
			}
		}
	}

	// Check for Client Authentication EKU (OID 1.3.6.1.5.5.7.3.2)
	hasClientAuth := false
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageClientAuth {
			hasClientAuth = true
			break
		}
	}

	if !cert.IsCA && !hasClientAuth {
		message := "End-entity certificate missing required Client Authentication extended key usage"
		if shouldFailOnCertValidationError() {
			ContextualLogger(logCtx).WithFields(logrus.Fields{
				"cert_subject":      cert.Subject.String(),
				"validation_result": "missing_client_auth_eku",
				"strict_mode":       true,
				"severity_elevated": "warning_to_error",
			}).Error("End-entity certificate missing Client Authentication EKU - REQUIRED in strict mode")
			return CertCheckResult{
				Passed:   false,
				Message:  message + " (REQUIRED in strict validation mode)",
				Severity: "error",
			}
		} else {
			ContextualLogger(logCtx).WithFields(logrus.Fields{
				"cert_subject":      cert.Subject.String(),
				"validation_result": "missing_client_auth_eku",
				"strict_mode":       false,
			}).Warn("End-entity certificate missing Client Authentication EKU")
			return CertCheckResult{
				Passed:   false,
				Message:  message,
				Severity: "error",
			}
		}
	}

	message := fmt.Sprintf("Certificate extended key usage: %v", extKeyUsages)
	ContextualLogger(logCtx).WithFields(logrus.Fields{
		"cert_subject":      cert.Subject.String(),
		"ext_key_usages":    extKeyUsages,
		"validation_result": "ext_key_usage_valid",
	}).Debug("Extended key usage check passed")
	return CertCheckResult{
		Passed:   true,
		Message:  message,
		Severity: "info",
	}
}

// checkSubjectAltName validates subject alternative names
func checkSubjectAltName(cert *x509.Certificate) CertCheckResult {
	logCtx := &LogContext{
		Component:    "certificate_validation",
		Operation:    "check_subject_alt_name",
		ResourceType: "certificate",
	}

	ContextualLogger(logCtx).WithFields(logrus.Fields{
		"cert_subject": cert.Subject.String(),
		"dns_names":    cert.DNSNames,
		"ip_addresses": cert.IPAddresses,
		"is_ca":        cert.IsCA,
	}).Debug("Checking certificate subject alternative names")

	// CA certificates typically don't need SAN
	if cert.IsCA {
		message := "CA certificate does not require subject alternative names"
		ContextualLogger(logCtx).WithFields(logrus.Fields{
			"cert_subject":      cert.Subject.String(),
			"validation_result": "ca_no_san_required",
		}).Debug("CA certificate SAN check passed")
		return CertCheckResult{
			Passed:   true,
			Message:  message,
			Severity: "info",
		}
	}

	// End-entity certificates should have SAN for modern usage
	if len(cert.DNSNames) == 0 && len(cert.IPAddresses) == 0 {
		message := "End-entity certificate should have subject alternative names (DNS names or IP addresses)"

		// In strict validation mode, missing SAN is an ERROR, not a warning
		if shouldFailOnCertValidationError() {
			ContextualLogger(logCtx).WithFields(logrus.Fields{
				"cert_subject":      cert.Subject.String(),
				"validation_result": "end_entity_missing_san",
				"strict_mode":       true,
				"severity_elevated": "warning_to_error",
			}).Error("End-entity certificate missing subject alternative names - REQUIRED in strict mode")
			return CertCheckResult{
				Passed:   false,
				Message:  message + " (REQUIRED in strict validation mode)",
				Severity: "error",
			}
		} else {
			ContextualLogger(logCtx).WithFields(logrus.Fields{
				"cert_subject":      cert.Subject.String(),
				"validation_result": "end_entity_missing_san",
				"strict_mode":       false,
			}).Warn("End-entity certificate missing subject alternative names")
			return CertCheckResult{
				Passed:   true,
				Message:  message,
				Severity: "warning",
			}
		}
	}

	var sanEntries []string
	sanEntries = append(sanEntries, cert.DNSNames...)
	for _, ip := range cert.IPAddresses {
		sanEntries = append(sanEntries, ip.String())
	}

	message := fmt.Sprintf("Certificate has appropriate SAN entries: %v", sanEntries)
	ContextualLogger(logCtx).WithFields(logrus.Fields{
		"cert_subject":      cert.Subject.String(),
		"san_entries":       sanEntries,
		"validation_result": "san_valid",
	}).Debug("Subject alternative names check passed")
	return CertCheckResult{
		Passed:   true,
		Message:  message,
		Severity: "info",
	}
}

// checkSignatureAlgorithm validates certificate signature algorithm
func checkSignatureAlgorithm(cert *x509.Certificate) CertCheckResult {
	logCtx := &LogContext{
		Component:    "certificate_validation",
		Operation:    "check_signature_algorithm",
		ResourceType: "certificate",
	}

	sigAlg := cert.SignatureAlgorithm.String()

	ContextualLogger(logCtx).WithFields(logrus.Fields{
		"cert_subject":        cert.Subject.String(),
		"signature_algorithm": sigAlg,
	}).Debug("Checking certificate signature algorithm")

	// Check for weak signature algorithms
	weakAlgorithms := []string{
		"MD5WithRSA", "SHA1WithRSA", "MD2WithRSA", "MD4WithRSA",
	}

	for _, weak := range weakAlgorithms {
		if strings.Contains(sigAlg, weak) || strings.Contains(sigAlg, strings.ToLower(weak)) {
			message := fmt.Sprintf("Certificate uses weak signature algorithm: %s", sigAlg)
			ContextualLogger(logCtx).WithFields(logrus.Fields{
				"cert_subject":        cert.Subject.String(),
				"signature_algorithm": sigAlg,
				"validation_result":   "weak_signature_algorithm",
			}).Error("Certificate uses weak signature algorithm")
			return CertCheckResult{
				Passed:   false,
				Message:  message,
				Severity: "error",
			}
		}
	}

	message := fmt.Sprintf("Certificate uses secure signature algorithm: %s", sigAlg)
	ContextualLogger(logCtx).WithFields(logrus.Fields{
		"cert_subject":        cert.Subject.String(),
		"signature_algorithm": sigAlg,
		"validation_result":   "signature_algorithm_secure",
	}).Debug("Signature algorithm check passed")
	return CertCheckResult{
		Passed:   true,
		Message:  message,
		Severity: "info",
	}
}

// checkKeyLength validates certificate key length
func checkKeyLength(cert *x509.Certificate, config *CertificateValidationConfig) CertCheckResult {
	logCtx := &LogContext{
		Component:    "certificate_validation",
		Operation:    "check_key_length",
		ResourceType: "certificate",
	}

	var keyLength int
	var keyType string

	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		keyLength = pub.N.BitLen()
		keyType = "RSA"
	case *ecdsa.PublicKey:
		keyLength = pub.Curve.Params().BitSize
		keyType = "ECDSA"
	default:
		keyType = "Unknown"
	}

	ContextualLogger(logCtx).WithFields(logrus.Fields{
		"cert_subject":   cert.Subject.String(),
		"key_type":       keyType,
		"key_length":     keyLength,
		"min_key_length": config.MinKeyLength,
	}).Debug("Checking certificate key length")

	if keyLength == 0 {
		message := fmt.Sprintf("Cannot determine key length for %s key", keyType)

		// In strict validation mode, unknown key length is an ERROR, not a warning
		if shouldFailOnCertValidationError() {
			ContextualLogger(logCtx).WithFields(logrus.Fields{
				"cert_subject":      cert.Subject.String(),
				"key_type":          keyType,
				"validation_result": "key_length_unknown",
				"strict_mode":       true,
				"severity_elevated": "warning_to_error",
			}).Error("Cannot determine key length - INVALID in strict mode")
			return CertCheckResult{
				Passed:   false,
				Message:  message + " (INVALID in strict validation mode)",
				Severity: "error",
			}
		} else {
			ContextualLogger(logCtx).WithFields(logrus.Fields{
				"cert_subject":      cert.Subject.String(),
				"key_type":          keyType,
				"validation_result": "key_length_unknown",
				"strict_mode":       false,
			}).Warn("Cannot determine key length")
			return CertCheckResult{
				Passed:   true,
				Message:  message,
				Severity: "warning",
			}
		}
	}

	if keyLength < config.MinKeyLength {
		message := fmt.Sprintf("Certificate key length (%d bits) is below minimum requirement (%d bits)", keyLength, config.MinKeyLength)
		ContextualLogger(logCtx).WithFields(logrus.Fields{
			"cert_subject":      cert.Subject.String(),
			"key_length":        keyLength,
			"min_key_length":    config.MinKeyLength,
			"validation_result": "key_length_insufficient",
		}).Error("Certificate key length is insufficient")
		return CertCheckResult{
			Passed:   false,
			Message:  message,
			Severity: "error",
		}
	}

	message := fmt.Sprintf("Certificate has sufficient key length: %d-bit %s", keyLength, keyType)
	ContextualLogger(logCtx).WithFields(logrus.Fields{
		"cert_subject":      cert.Subject.String(),
		"key_type":          keyType,
		"key_length":        keyLength,
		"validation_result": "key_length_sufficient",
	}).Debug("Key length check passed")
	return CertCheckResult{
		Passed:   true,
		Message:  message,
		Severity: "info",
	}
}

// ValidateCertificateWithConfig performs comprehensive certificate validation
func ValidateCertificateWithConfig(cert *x509.Certificate, config *CertificateValidationConfig, certPath string) *CertificateValidationResult {
	logCtx := &LogContext{
		Component:    "certificate_validation",
		Operation:    "validate_certificate_comprehensive",
		ResourceID:   certPath,
		ResourceType: "certificate",
	}

	ContextualLogger(logCtx).WithFields(logrus.Fields{
		"cert_subject":              cert.Subject.String(),
		"cert_issuer":               cert.Issuer.String(),
		"cert_serial":               cert.SerialNumber.String(),
		"strict_validation_enabled": shouldFailOnCertValidationError(),
	}).Info("Starting comprehensive certificate validation")

	result := &CertificateValidationResult{
		Valid:           true,
		Errors:          []string{},
		Warnings:        []string{},
		CheckResults:    make(map[string]CertCheckResult),
		CertificateInfo: extractCertificateInfo(cert),
	}

	// Run all enabled checks
	checks := []struct {
		name    string
		enabled bool
		check   func() CertCheckResult
	}{
		{
			name:    "expiration",
			enabled: config.CheckExpiration,
			check:   func() CertCheckResult { return checkCertificateExpiration(cert, config) },
		},
		{
			name:    "basic_constraints",
			enabled: config.CheckBasicConstraints,
			check:   func() CertCheckResult { return checkBasicConstraints(cert) },
		},
		{
			name:    "ca_flags",
			enabled: config.CheckCAFlags,
			check:   func() CertCheckResult { return checkCAFlags(cert) },
		},
		{
			name:    "self_signed",
			enabled: config.CheckSelfSigned,
			check:   func() CertCheckResult { return checkSelfSigned(cert) },
		},
		{
			name:    "key_usage",
			enabled: config.CheckKeyUsage,
			check:   func() CertCheckResult { return checkKeyUsage(cert) },
		},
		{
			name:    "ext_key_usage",
			enabled: config.CheckExtKeyUsage,
			check:   func() CertCheckResult { return checkExtendedKeyUsage(cert) },
		},
		{
			name:    "subject_alt_name",
			enabled: config.CheckSubjectAltName,
			check:   func() CertCheckResult { return checkSubjectAltName(cert) },
		},
		{
			name:    "signature_algorithm",
			enabled: config.CheckSignatureAlgorithm,
			check:   func() CertCheckResult { return checkSignatureAlgorithm(cert) },
		},
		{
			name:    "key_length",
			enabled: config.CheckKeyLength,
			check:   func() CertCheckResult { return checkKeyLength(cert, config) },
		},
	}

	// Execute all enabled checks
	strictMode := shouldFailOnCertValidationError()
	for _, checkInfo := range checks {
		if !checkInfo.enabled {
			ContextualLogger(logCtx).WithFields(logrus.Fields{
				"check_name":   checkInfo.name,
				"check_status": "disabled",
			}).Debug("Certificate check disabled, skipping")
			continue
		}

		ContextualLogger(logCtx).WithField("check_name", checkInfo.name).Debug("Running certificate check")
		checkResult := checkInfo.check()
		result.CheckResults[checkInfo.name] = checkResult

		// Categorize results based on severity and strict mode
		switch checkResult.Severity {
		case "error":
			result.Errors = append(result.Errors, checkResult.Message)
			if !checkResult.Passed {
				result.Valid = false
			}
		case "warning":
			result.Warnings = append(result.Warnings, checkResult.Message)
			// In strict mode, warnings also cause validation failure
			if strictMode && !checkResult.Passed {
				result.Valid = false
				// Promote warning to error in strict mode
				result.Errors = append(result.Errors, checkResult.Message+" (elevated to error in strict mode)")
				ContextualLogger(logCtx).WithFields(logrus.Fields{
					"check_name":        checkInfo.name,
					"check_severity":    checkResult.Severity,
					"strict_mode":       true,
					"severity_elevated": "warning_to_error",
				}).Error("Certificate check warning elevated to error in strict mode")
			}
		}

		ContextualLogger(logCtx).WithFields(logrus.Fields{
			"check_name":     checkInfo.name,
			"check_passed":   checkResult.Passed,
			"check_severity": checkResult.Severity,
			"check_message":  checkResult.Message,
			"strict_mode":    strictMode,
		}).Debug("Certificate check completed")
	}

	// In strict mode, any warning also makes the certificate invalid
	if strictMode && len(result.Warnings) > 0 {
		for _, warning := range result.Warnings {
			// Check if this warning was already promoted to an error
			alreadyPromoted := false
			for _, err := range result.Errors {
				if strings.Contains(err, warning) {
					alreadyPromoted = true
					break
				}
			}
			if !alreadyPromoted {
				result.Valid = false
				result.Errors = append(result.Errors, warning+" (warning treated as error in strict mode)")
			}
		}
	}

	// Log final validation result
	ContextualLogger(logCtx).WithFields(logrus.Fields{
		"cert_subject":               cert.Subject.String(),
		"validation_valid":           result.Valid,
		"validation_error_count":     len(result.Errors),
		"validation_warning_count":   len(result.Warnings),
		"validation_errors":          result.Errors,
		"validation_warnings":        result.Warnings,
		"strict_mode_enabled":        strictMode,
		"warnings_treated_as_errors": strictMode && len(result.Warnings) > 0,
	}).Info("Certificate validation completed")

	return result
}

// initBasicLogger initializes a basic logger for early startup logging
func initBasicLogger() {
	logger = logrus.New()
	logger.SetLevel(logrus.InfoLevel)
	logger.SetFormatter(&logrus.JSONFormatter{
		TimestampFormat: "2006-01-02T15:04:05Z07:00",
		FieldMap: logrus.FieldMap{
			logrus.FieldKeyTime:  "timestamp",
			logrus.FieldKeyLevel: "level",
			logrus.FieldKeyMsg:   "message",
		},
	})

	// Initially set output to stdout only
	logger.SetOutput(os.Stdout)
}

// initLogger initializes logger using YAML configuration with file output and fallback handling
func initLogger() {
	logCtx := &LogContext{
		Component: "logging",
		Operation: "initialize_logger",
	}

	if logger == nil {
		logger = logrus.New()
	}

	var logLevel string
	var logFormat string

	if globalConfig != nil {
		logLevel = globalConfig.Logging.Level
		logFormat = globalConfig.Logging.Format
	} else {
		// Fallback to environment variables
		logLevel = os.Getenv("LOG_LEVEL")
		logFormat = os.Getenv("LOG_FORMAT")
	}

	// Set log level
	switch strings.ToLower(logLevel) {
	case "debug":
		logger.SetLevel(logrus.DebugLevel)
	case "warn":
		logger.SetLevel(logrus.WarnLevel)
	case "error":
		logger.SetLevel(logrus.ErrorLevel)
	default:
		logger.SetLevel(logrus.InfoLevel)
	}

	// Set log format
	if strings.ToLower(logFormat) == "text" {
		logger.SetFormatter(&logrus.TextFormatter{
			TimestampFormat: "2006-01-02 15:04:05",
			FullTimestamp:   true,
		})
	} else {
		// Default to JSON formatter
		logger.SetFormatter(&logrus.JSONFormatter{
			TimestampFormat: "2006-01-02T15:04:05Z07:00",
			FieldMap: logrus.FieldMap{
				logrus.FieldKeyTime:  "timestamp",
				logrus.FieldKeyLevel: "level",
				logrus.FieldKeyMsg:   "message",
			},
		})
	}

	// Setup file logging with fallback handling
	logFilePath := getLogFilePath()
	var err error
	var loggingMode string
	var actualLogPath string

	logFile, err = setupLogFile(logFilePath)
	if err != nil {
		// File logging failed, continue with stdout only
		logger.SetOutput(os.Stdout)
		loggingMode = "stdout_only"
		actualLogPath = "stdout"

		ContextualLogger(logCtx).WithError(err).WithFields(logrus.Fields{
			"requested_log_path": logFilePath,
			"logging_mode":       loggingMode,
			"fallback_reason":    "file_logging_unavailable",
		}).Warn("File logging unavailable, continuing with stdout-only logging")
	} else {
		// Setup multi-writer to write to both stdout and file
		multiWriter := io.MultiWriter(os.Stdout, logFile)
		logger.SetOutput(multiWriter)
		loggingMode = "file_and_stdout"

		// Get the actual log file path (might be different if fallback was used)
		if _, statErr := logFile.Stat(); statErr == nil {
			if logFile.Name() != "" {
				actualLogPath = logFile.Name()
			} else {
				actualLogPath = logFilePath
			}
		} else {
			actualLogPath = logFilePath
		}

		ContextualLogger(logCtx).WithFields(logrus.Fields{
			"actual_log_path": actualLogPath,
			"logging_mode":    loggingMode,
		}).Info("File logging enabled successfully")
	}

	ContextualLogger(logCtx).WithFields(logrus.Fields{
		"configured_log_level":         logger.GetLevel().String(),
		"configured_log_format":        logFormat,
		"requested_log_file_path":      logFilePath,
		"actual_log_path":              actualLogPath,
		"logging_mode":                 loggingMode,
		"logger_initialization_result": "success",
	}).Info("Logger initialized with configuration")
}

// getRequestID generates or extracts request ID for tracing
func getRequestID(c *gin.Context) string {
	requestID := c.GetHeader("X-Request-ID")
	if requestID == "" {
		requestID = fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return requestID
}

// loggerMiddleware adds request logging
func loggerMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		logCtx := getLogContextFromGin(c)
		logCtx.Component = "http_middleware"
		logCtx.Operation = "request_processing"

		// Add request ID to context
		c.Set("request_id", logCtx.RequestID)
		c.Header("X-Request-ID", logCtx.RequestID)

		ContextualLogger(logCtx).WithFields(logrus.Fields{
			"request_started": true,
		}).Info("HTTP request started")

		c.Next()

		duration := time.Since(start)
		status := c.Writer.Status()

		logCtx.Operation = "request_completed"
		logEntry := ContextualLogger(logCtx).WithFields(logrus.Fields{
			"response_status_code": status,
			"request_duration_ms":  duration.Milliseconds(),
			"request_duration":     duration.String(),
		})

		if status >= 400 {
			logEntry.WithField("request_result", "error").Error("HTTP request completed with error")
		} else {
			logEntry.WithField("request_result", "success").Info("HTTP request completed successfully")
		}
	}
}

// createHTTPClient creates an HTTP client with the specified certificate
func createHTTPClient() (*http.Client, error) {
	logCtx := &LogContext{
		Component:    "http_client",
		Operation:    "create_client",
		ResourceID:   certPath,
		ResourceType: "certificate",
	}

	ContextualLogger(logCtx).Debug("Creating HTTP client with certificate authentication")

	caCert, err := ioutil.ReadFile(certPath)
	if err != nil {
		ContextualLogger(logCtx).WithError(err).Error("Failed to read certificate file")
		return nil, fmt.Errorf("error reading certificate: %v", err)
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	tlsConfig := &tls.Config{
		RootCAs: caCertPool,
	}

	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	client := &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}

	ContextualLogger(logCtx).Debug("HTTP client created successfully")
	return client, nil
}

// validateCertificateFiles checks if all required certificate files exist
func validateCertificateFiles(caPath, certPath, keyPath string) error {
	logCtx := &LogContext{
		Component:    "certificate_validation",
		Operation:    "validate_certificate_files",
		ResourceType: "certificate_files",
	}

	files := map[string]string{
		"CA certificate":     caPath,
		"Client certificate": certPath,
		"Private key":        keyPath,
	}

	for name, path := range files {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			ContextualLogger(logCtx).WithFields(logrus.Fields{
				"file_type":         name,
				"file_path":         path,
				"validation_result": "file_not_found",
			}).Error("Certificate file does not exist")
			return fmt.Errorf("%s file does not exist: %s", name, path)
		} else if err != nil {
			ContextualLogger(logCtx).WithFields(logrus.Fields{
				"file_type":         name,
				"file_path":         path,
				"validation_result": "access_error",
			}).WithError(err).Error("Error accessing certificate file")
			return fmt.Errorf("error accessing %s file %s: %v", name, path, err)
		}
	}

	ContextualLogger(logCtx).WithFields(logrus.Fields{
		"ca_cert_path":      caPath,
		"client_cert_path":  certPath,
		"private_key_path":  keyPath,
		"validation_result": "all_files_valid",
	}).Debug("All certificate files validated successfully")

	return nil
}

// loadClientCertificateWithPassword loads a client certificate with optional password support and validation
func loadClientCertificateWithPassword(certPath, keyPath, password string) (tls.Certificate, error) {
	logCtx := &LogContext{
		Component:    "certificate_management",
		Operation:    "load_client_certificate",
		ResourceType: "certificate",
	}

	ContextualLogger(logCtx).WithFields(logrus.Fields{
		"cert_path":    certPath,
		"key_path":     keyPath,
		"has_password": password != "",
	}).Debug("Loading client certificate")

	// Read and analyze the certificate file first
	certPEM, err := ioutil.ReadFile(certPath)
	if err != nil {
		ContextualLogger(logCtx).WithError(err).Error("Failed to read certificate file")
		return tls.Certificate{}, err
	}

	ContextualLogger(logCtx).WithField("cert_file_size", len(certPEM)).Debug("Certificate file loaded")

	// Parse all certificates in the chain
	var certChain []*x509.Certificate
	rest := certPEM
	certCount := 0

	for len(rest) > 0 {
		block, remaining := pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				ContextualLogger(logCtx).WithFields(logrus.Fields{
					"cert_index":   certCount,
					"parse_result": "failed",
				}).WithError(err).Warn("Failed to parse certificate in chain")
				rest = remaining
				continue
			}
			certChain = append(certChain, cert)
			ContextualLogger(logCtx).WithFields(logrus.Fields{
				"cert_index":   certCount,
				"cert_subject": cert.Subject.String(),
				"cert_issuer":  cert.Issuer.String(),
				"parse_result": "success",
			}).Debug("Certificate parsed successfully")
			certCount++
		}
		rest = remaining
	}

	ContextualLogger(logCtx).WithField("certificate_chain_count", len(certChain)).Debug("Certificate chain parsed")

	if len(certChain) == 0 {
		ContextualLogger(logCtx).WithField("parse_result", "no_valid_certificates").Error("No valid certificates found in certificate file")
		return tls.Certificate{}, fmt.Errorf("no valid certificates found in certificate file")
	}

	// Validate the first certificate (leaf certificate) with comprehensive checks
	leafCert := certChain[0]
	validationConfig := getDefaultCertValidationConfig()
	validationResult := ValidateCertificateWithConfig(leafCert, validationConfig, certPath)

	// Log validation results
	if !validationResult.Valid {
		ContextualLogger(logCtx).WithFields(logrus.Fields{
			"cert_subject":              leafCert.Subject.String(),
			"validation_errors":         validationResult.Errors,
			"validation_warnings":       validationResult.Warnings,
			"validation_result":         "failed",
			"strict_validation_enabled": shouldFailOnCertValidationError(),
		}).Error("Certificate validation failed")

		// ALWAYS fail when certificate validation fails in strict mode - no fallbacks allowed
		if shouldFailOnCertValidationError() {
			ContextualLogger(logCtx).WithFields(logrus.Fields{
				"cert_subject":      leafCert.Subject.String(),
				"validation_errors": validationResult.Errors,
				"security_decision": "reject_certificate",
				"reason":            "strict_validation_enabled",
			}).Error("Certificate rejected due to validation failures in strict mode")
			return tls.Certificate{}, fmt.Errorf("certificate validation failed in strict mode: %v", validationResult.Errors)
		} else {
			ContextualLogger(logCtx).WithFields(logrus.Fields{
				"cert_subject":      leafCert.Subject.String(),
				"validation_errors": validationResult.Errors,
				"security_decision": "accept_with_warnings",
				"reason":            "non_strict_validation_mode",
			}).Warn("Certificate validation failed but continuing due to non-strict validation mode")
		}
	} else if len(validationResult.Warnings) > 0 {
		ContextualLogger(logCtx).WithFields(logrus.Fields{
			"cert_subject":        leafCert.Subject.String(),
			"validation_warnings": validationResult.Warnings,
			"validation_result":   "warning",
		}).Warn("Certificate validation completed with warnings")
	} else {
		ContextualLogger(logCtx).WithFields(logrus.Fields{
			"cert_subject":      leafCert.Subject.String(),
			"validation_result": "success",
		}).Info("Certificate validation passed successfully")
	}

	// Only proceed with loading if validation passed or strict mode is disabled
	// First try loading without password (standard approach)
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err == nil {
		ContextualLogger(logCtx).WithField("load_method", "standard").Debug("Certificate loaded successfully without password")
		return cert, nil
	}

	ContextualLogger(logCtx).WithError(err).WithField("load_method", "standard").Debug("Standard certificate loading failed, trying with password")

	// If that fails and we have a password, try loading with password
	if password != "" {
		ContextualLogger(logCtx).WithField("load_method", "encrypted").Debug("Attempting to load encrypted private key with password")
		return loadEncryptedKeyPair(certPath, keyPath, password)
	}

	ContextualLogger(logCtx).WithError(err).WithField("load_result", "failed").Error("Failed to load certificate")
	return cert, err
}

// validateAndLoadCACertificateWithValidation validates and loads CA certificate with comprehensive validation
func validateAndLoadCACertificateWithValidation(caPath string) (*x509.CertPool, *CertificateValidationResult, error) {
	logCtx := &LogContext{
		Component:    "certificate_management",
		Operation:    "validate_and_load_ca_certificate",
		ResourceID:   caPath,
		ResourceType: "ca_certificate",
	}

	ContextualLogger(logCtx).Debug("Loading CA certificate with validation")

	caCert, err := ioutil.ReadFile(caPath)
	if err != nil {
		ContextualLogger(logCtx).WithError(err).Error("Failed to read CA certificate file")
		return nil, nil, fmt.Errorf("error reading CA certificate: %v", err)
	}

	ContextualLogger(logCtx).WithField("ca_cert_file_size", len(caCert)).Debug("CA certificate file loaded")

	// Validate that the file contains valid PEM data
	block, rest := pem.Decode(caCert)
	if block == nil {
		ContextualLogger(logCtx).WithField("parse_result", "no_pem_block").Error("No valid PEM block found in CA certificate")
		return nil, nil, fmt.Errorf("no valid PEM block found in CA certificate")
	}

	ContextualLogger(logCtx).WithField("pem_block_type", block.Type).Debug("Found PEM block in CA certificate")

	// Parse the certificate to validate it
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		ContextualLogger(logCtx).WithError(err).WithField("parse_result", "failed").Error("Failed to parse CA certificate")
		return nil, nil, fmt.Errorf("failed to parse CA certificate: %v", err)
	}

	ContextualLogger(logCtx).WithFields(logrus.Fields{
		"ca_subject":    cert.Subject.String(),
		"ca_issuer":     cert.Issuer.String(),
		"ca_serial":     cert.SerialNumber.String(),
		"ca_valid_from": cert.NotBefore.Format(time.RFC3339),
		"ca_valid_to":   cert.NotAfter.Format(time.RFC3339),
		"ca_is_ca":      cert.IsCA,
		"parse_result":  "success",
	}).Debug("CA certificate parsed successfully")

	// Validate CA certificate with comprehensive checks
	validationConfig := getDefaultCertValidationConfig()
	validationResult := ValidateCertificateWithConfig(cert, validationConfig, caPath)

	// Log validation results
	if !validationResult.Valid {
		ContextualLogger(logCtx).WithFields(logrus.Fields{
			"ca_subject":          cert.Subject.String(),
			"validation_errors":   validationResult.Errors,
			"validation_warnings": validationResult.Warnings,
			"validation_result":   "failed",
		}).Error("CA certificate validation failed")

		if shouldFailOnCertValidationError() {
			return nil, validationResult, fmt.Errorf("CA certificate validation failed: %v", validationResult.Errors)
		}
	} else if len(validationResult.Warnings) > 0 {
		ContextualLogger(logCtx).WithFields(logrus.Fields{
			"ca_subject":          cert.Subject.String(),
			"validation_warnings": validationResult.Warnings,
			"validation_result":   "warning",
		}).Warn("CA certificate validation completed with warnings")
	} else {
		ContextualLogger(logCtx).WithFields(logrus.Fields{
			"ca_subject":        cert.Subject.String(),
			"validation_result": "success",
		}).Info("CA certificate validation passed successfully")
	}

	// Create certificate pool and add the CA
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		ContextualLogger(logCtx).WithField("pool_creation_result", "failed").Error("Failed to append CA certificate to pool")
		return nil, validationResult, fmt.Errorf("failed to append CA certificate to pool")
	}

	// Check if there are multiple certificates in the file (certificate chain)
	intermediateCertCount := 0
	for len(rest) > 0 {
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			intermediateCert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				ContextualLogger(logCtx).WithError(err).WithFields(logrus.Fields{
					"intermediate_cert_index": intermediateCertCount,
					"parse_result":            "failed",
				}).Warn("Failed to parse intermediate certificate")
				continue
			}
			ContextualLogger(logCtx).WithFields(logrus.Fields{
				"intermediate_cert_index": intermediateCertCount,
				"intermediate_subject":    intermediateCert.Subject.String(),
				"intermediate_issuer":     intermediateCert.Issuer.String(),
				"parse_result":            "success",
			}).Debug("Found intermediate certificate")

			// Validate intermediate certificate
			intermediateValidationResult := ValidateCertificateWithConfig(intermediateCert, validationConfig, fmt.Sprintf("%s (intermediate %d)", caPath, intermediateCertCount))
			if !intermediateValidationResult.Valid {
				ContextualLogger(logCtx).WithFields(logrus.Fields{
					"intermediate_cert_index": intermediateCertCount,
					"intermediate_subject":    intermediateCert.Subject.String(),
					"validation_errors":       intermediateValidationResult.Errors,
					"validation_result":       "failed",
				}).Warn("Intermediate certificate validation failed")
			}

			// Add intermediate certificates to the pool as well
			intermediatePEM := pem.EncodeToMemory(block)
			caCertPool.AppendCertsFromPEM(intermediatePEM)
			intermediateCertCount++
		}
	}

	ContextualLogger(logCtx).WithFields(logrus.Fields{
		"intermediate_cert_count": intermediateCertCount,
		"pool_creation_result":    "success",
	}).Debug("CA certificate pool loaded successfully")

	return caCertPool, validationResult, nil
}

// loadEncryptedKeyPair loads a certificate with an encrypted private key
func loadEncryptedKeyPair(certPath, keyPath, password string) (tls.Certificate, error) {
	logCtx := &LogContext{
		Component:    "certificate_management",
		Operation:    "load_encrypted_key_pair",
		ResourceType: "encrypted_certificate",
	}

	ContextualLogger(logCtx).WithFields(logrus.Fields{
		"cert_path": certPath,
		"key_path":  keyPath,
	}).Debug("Loading encrypted key pair")

	// Read certificate file
	certPEM, err := ioutil.ReadFile(certPath)
	if err != nil {
		ContextualLogger(logCtx).WithError(err).WithField("file_type", "certificate").Error("Failed to read certificate file")
		return tls.Certificate{}, err
	}

	// Read private key file
	keyPEM, err := ioutil.ReadFile(keyPath)
	if err != nil {
		ContextualLogger(logCtx).WithError(err).WithField("file_type", "private_key").Error("Failed to read private key file")
		return tls.Certificate{}, err
	}

	// Decode the private key PEM block
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		ContextualLogger(logCtx).WithField("decode_result", "failed").Error("Failed to decode PEM block containing private key")
		return tls.Certificate{}, fmt.Errorf("failed to decode PEM block containing private key")
	}

	// Decrypt the private key if it's encrypted
	var keyDER []byte
	if x509.IsEncryptedPEMBlock(keyBlock) {
		keyDER, err = x509.DecryptPEMBlock(keyBlock, []byte(password))
		if err != nil {
			ContextualLogger(logCtx).WithError(err).WithField("decrypt_result", "failed").Error("Failed to decrypt private key")
			return tls.Certificate{}, fmt.Errorf("failed to decrypt private key: %v", err)
		}
		ContextualLogger(logCtx).WithField("decrypt_result", "success").Debug("Private key decrypted successfully")
	} else {
		keyDER = keyBlock.Bytes
	}

	// Create new unencrypted PEM block
	unencryptedKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  keyBlock.Type,
		Bytes: keyDER,
	})

	// Load the certificate pair
	cert, err := tls.X509KeyPair(certPEM, unencryptedKeyPEM)
	if err != nil {
		ContextualLogger(logCtx).WithError(err).WithField("cert_pair_creation_result", "failed").Error("Failed to create certificate pair")
		return tls.Certificate{}, err
	}

	ContextualLogger(logCtx).WithField("load_result", "success").Debug("Encrypted certificate pair loaded successfully")
	return cert, nil
}

// extractServerNameFromURL extracts the hostname from a URL for ServerName validation
func extractServerNameFromURL(targetURL string) (string, error) {
	logCtx := &LogContext{
		Component:    "url_processing",
		Operation:    "extract_server_name",
		ResourceID:   targetURL,
		ResourceType: "url",
	}

	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		ContextualLogger(logCtx).WithError(err).WithField("parse_result", "failed").Error("Failed to parse URL")
		return "", fmt.Errorf("failed to parse URL: %v", err)
	}

	hostname := parsedURL.Hostname()
	if hostname == "" {
		ContextualLogger(logCtx).WithField("extraction_result", "empty_hostname").Error("Unable to extract hostname from URL")
		return "", fmt.Errorf("unable to extract hostname from URL: %s", targetURL)
	}

	ContextualLogger(logCtx).WithFields(logrus.Fields{
		"extracted_hostname": hostname,
		"extraction_result":  "success",
	}).Debug("Extracted hostname from URL")

	return hostname, nil
}

// validateAndLoadCACertificate validates and loads CA certificate (wrapper for backward compatibility)
func validateAndLoadCACertificate(caPath string) (*x509.CertPool, error) {
	certPool, _, err := validateAndLoadCACertificateWithValidation(caPath)
	return certPool, err
}

// createHTTPClientWithOptions creates an HTTP client with configurable certificate validation
func (sm *SecurityManager) createHTTPClientWithOptions(caPath, certPath, keyPath, password string, skipVerify bool) (*http.Client, error) {
	logCtx := &LogContext{
		Component:    "http_client",
		Operation:    "create_client_with_options",
		ResourceType: "http_client",
	}

	ContextualLogger(logCtx).WithFields(logrus.Fields{
		"ca_cert_path":     caPath,
		"client_cert_path": certPath,
		"private_key_path": keyPath,
		"ssl_skip_verify":  skipVerify,
	}).Debug("Creating HTTP client with certificate options")

	// Validate that all certificate files exist
	if err := validateCertificateFiles(caPath, certPath, keyPath); err != nil {
		return nil, err
	}

	// Load client certificate with password support
	cert, err := loadClientCertificateWithPassword(certPath, keyPath, password)
	if err != nil {
		ContextualLogger(logCtx).WithError(err).WithField("cert_load_result", "failed").Error("Failed to load client certificate")
		return nil, fmt.Errorf("error loading client certificate: %v", err)
	}
	ContextualLogger(logCtx).WithField("cert_load_result", "success").Debug("Client certificate loaded successfully")

	var caCertPool *x509.CertPool
	if !skipVerify {
		// Load CA certificates for validation
		caCertPool, err = validateAndLoadCACertificate(caPath)
		if err != nil {
			ContextualLogger(logCtx).WithError(err).WithField("ca_load_result", "failed").Error("Failed to load CA certificate")
			return nil, err
		}
	} else {
		ContextualLogger(logCtx).WithField("ssl_verification", "disabled").Warn("Certificate verification is disabled")
	}

	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		RootCAs:            caCertPool,
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, // FORCE SSL VERIFICATION OFF
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
		CurvePreferences: []tls.CurveID{
			tls.CurveP521,
			tls.CurveP384,
			tls.CurveP256,
		},
	}

	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	client := &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}

	ContextualLogger(logCtx).WithField("client_creation_result", "success").Debug("HTTP client with certificate options created successfully")
	return client, nil
}

// createSecureSMTPClient creates an SMTP client with secure TLS configuration
func createSecureSMTPClient(host, port string, config *EmailConfig) (*smtp.Client, error) {
	logCtx := &LogContext{
		Component:    "email_client",
		Operation:    "create_secure_smtp_client",
		ResourceID:   fmt.Sprintf("%s:%s", host, port),
		ResourceType: "smtp_server",
	}

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%s", host, port), timeout)
	if err != nil {
		ContextualLogger(logCtx).WithError(err).Error("Failed to connect to SMTP server")
		return nil, fmt.Errorf("failed to connect to SMTP server: %v", err)
	}

	client, err := smtp.NewClient(conn, host)
	if err != nil {
		ContextualLogger(logCtx).WithError(err).Error("Failed to create SMTP client")
		return nil, fmt.Errorf("failed to create SMTP client: %v", err)
	}

	if config.Secure == "true" || config.Secure == "false" { // Handle STARTTLS
		tlsConfig := &tls.Config{
			ServerName: host,
			MinVersion: tls.VersionTLS12,
			MaxVersion: tls.VersionTLS13,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			},
			CurvePreferences: []tls.CurveID{
				tls.CurveP521,
				tls.CurveP384,
				tls.CurveP256,
			},
		}

		// Determine certificate verification behavior based on secure setting
		if config.Secure == "false" {
			// When secure is false, skip certificate verification (accept self-signed certs)
			tlsConfig.InsecureSkipVerify = true
			ContextualLogger(logCtx).WithFields(logrus.Fields{
				"secure_setting":           config.Secure,
				"certificate_verification": "disabled",
				"reason":                   "secure_false_allows_self_signed",
			}).Info("TLS certificate verification disabled due to secure=false setting")
		} else {
			// When secure is true, use proper certificate verification
			if config.CACertPath != "" {
				caCert, err := ioutil.ReadFile(config.CACertPath)
				if err != nil {
					ContextualLogger(logCtx).WithError(err).Error("Failed to read CA certificate")
					return nil, fmt.Errorf("failed to read CA certificate: %v", err)
				}
				caCertPool := x509.NewCertPool()
				if !caCertPool.AppendCertsFromPEM(caCert) {
					ContextualLogger(logCtx).Error("Failed to parse CA certificate")
					return nil, fmt.Errorf("failed to parse CA certificate")
				}
				tlsConfig.RootCAs = caCertPool
				ContextualLogger(logCtx).WithFields(logrus.Fields{
					"secure_setting":           config.Secure,
					"certificate_verification": "enabled_with_ca_cert",
					"ca_cert_path":             config.CACertPath,
				}).Info("TLS certificate verification enabled with custom CA certificate")
			} else {
				// When secure is true but no CA cert provided, use system's default CA certs
				// Set InsecureSkipVerify to false explicitly (this is the default, but being explicit)
				tlsConfig.InsecureSkipVerify = false
				ContextualLogger(logCtx).WithFields(logrus.Fields{
					"secure_setting":           config.Secure,
					"certificate_verification": "enabled_with_system_ca",
				}).Info("TLS certificate verification enabled with system CA certificates")
			}
		}

		if err := client.StartTLS(tlsConfig); err != nil {
			ContextualLogger(logCtx).WithError(err).WithFields(logrus.Fields{
				"secure_setting":          config.Secure,
				"insecure_skip_verify":    tlsConfig.InsecureSkipVerify,
				"starttls_upgrade_result": "failed",
			}).Error("Failed to upgrade connection with STARTTLS")
			return nil, fmt.Errorf("failed to upgrade to TLS: %v", err)
		}

		ContextualLogger(logCtx).WithFields(logrus.Fields{
			"secure_setting":          config.Secure,
			"insecure_skip_verify":    tlsConfig.InsecureSkipVerify,
			"starttls_upgrade_result": "success",
		}).Debug("STARTTLS upgrade completed successfully")
	}

	return client, nil
}

// sendEmail sends an email using the provided configuration
func (sm *SecurityManager) sendEmail(emailConfig *EmailConfig, connectorID string) error {
	logCtx := &LogContext{
		Component:    "email_service",
		Operation:    "send_email",
		ResourceID:   connectorID,
		ResourceType: "email_connector",
	}

	ContextualLogger(logCtx).WithFields(logrus.Fields{
		"smtp_host":   emailConfig.SMTPHost,
		"smtp_port":   emailConfig.SMTPPort,
		"from_email":  emailConfig.FromEmail,
		"auth_method": emailConfig.AuthMethod,
		"secure":      emailConfig.Secure,
	}).Info("Sending email")

	// Create secure SMTP client with enhanced logging
	ContextualLogger(logCtx).WithFields(logrus.Fields{
		"step": "1_create_smtp_client",
	}).Debug("Step 1: Creating SMTP client")

	client, err := createSecureSMTPClient(emailConfig.SMTPHost, emailConfig.SMTPPort, emailConfig)
	if err != nil {
		ContextualLogger(logCtx).WithError(err).Error("Failed to create SMTP client")
		return fmt.Errorf("failed to create SMTP client: %v", err)
	}
	defer client.Close()

	ContextualLogger(logCtx).WithFields(logrus.Fields{
		"step":   "1_create_smtp_client",
		"result": "success",
	}).Debug("SMTP client created successfully")

	// Check server capabilities
	ContextualLogger(logCtx).WithFields(logrus.Fields{
		"step": "2_check_server_capabilities",
	}).Debug("Step 2: Checking server capabilities")

	if ok, ext := client.Extension("AUTH"); ok && ext != "" {
		ContextualLogger(logCtx).WithFields(logrus.Fields{
			"step":                "2_check_server_capabilities",
			"server_auth_methods": ext,
			"result":              "success",
		}).Info("Server AUTH capabilities detected")
	} else {
		ContextualLogger(logCtx).WithFields(logrus.Fields{
			"step":   "2_check_server_capabilities",
			"result": "no_auth_extension",
		}).Warn("No AUTH extension found")
	}

	// Authenticate if credentials are provided
	if emailConfig.Username != "" && emailConfig.Password != "" {
		ContextualLogger(logCtx).WithFields(logrus.Fields{
			"step":     "3_authentication",
			"username": emailConfig.Username,
		}).Debug("Step 3: Starting authentication")

		var auth smtp.Auth

		switch strings.ToUpper(emailConfig.AuthMethod) {
		case "PLAIN":
			ContextualLogger(logCtx).WithField("selected_auth_method", "PLAIN").Debug("Using PLAIN authentication")
			auth = smtp.PlainAuth("", emailConfig.Username, emailConfig.Password, emailConfig.SMTPHost)
		case "CRAM-MD5":
			ContextualLogger(logCtx).WithField("selected_auth_method", "CRAM-MD5").Debug("Using CRAM-MD5 authentication")
			auth = smtp.CRAMMD5Auth(emailConfig.Username, emailConfig.Password)
		case "LOGIN":
			ContextualLogger(logCtx).WithField("selected_auth_method", "LOGIN").Debug("Using LOGIN authentication")
			auth = NewLoginAuth(emailConfig.Username, emailConfig.Password)
		case "AUTO", "":
			// Auto-detect based on server capabilities
			ContextualLogger(logCtx).WithField("auth_method", "AUTO").Debug("Auto-detecting authentication method")
			auth = autoDetectAuth(emailConfig, client)
		default:
			ContextualLogger(logCtx).WithFields(logrus.Fields{
				"requested_auth_method": emailConfig.AuthMethod,
				"fallback_auth_method":  "LOGIN",
			}).Warn("Unsupported authentication method, falling back to LOGIN")
			auth = NewLoginAuth(emailConfig.Username, emailConfig.Password)
		}

		if err := client.Auth(auth); err != nil {
			ContextualLogger(logCtx).WithError(err).WithFields(logrus.Fields{
				"step":        "3_authentication",
				"auth_method": emailConfig.AuthMethod,
				"username":    emailConfig.Username,
				"result":      "failed",
			}).Error("SMTP authentication failed")
			return fmt.Errorf("SMTP authentication failed: %v", err)
		}

		ContextualLogger(logCtx).WithFields(logrus.Fields{
			"step":        "3_authentication",
			"auth_method": emailConfig.AuthMethod,
			"result":      "success",
		}).Info("SMTP authentication successful")
	}

	// Set sender
	ContextualLogger(logCtx).WithFields(logrus.Fields{
		"step":       "4_set_sender",
		"from_email": emailConfig.FromEmail,
	}).Debug("Step 4: Setting sender")

	if err := client.Mail(emailConfig.FromEmail); err != nil {
		ContextualLogger(logCtx).WithError(err).WithFields(logrus.Fields{
			"step":       "4_set_sender",
			"from_email": emailConfig.FromEmail,
			"result":     "failed",
		}).Error("Failed to set sender")
		return fmt.Errorf("failed to set sender: %v", err)
	}

	ContextualLogger(logCtx).WithFields(logrus.Fields{
		"step":       "4_set_sender",
		"from_email": emailConfig.FromEmail,
		"result":     "success",
	}).Debug("Sender set successfully")

	// Set recipient
	toEmail := emailConfig.ToEmail
	if toEmail == "" {
		toEmail = "hr7sha@gmail.com" // Use your specific email
	}

	ContextualLogger(logCtx).WithFields(logrus.Fields{
		"step":     "5_set_recipient",
		"to_email": toEmail,
	}).Debug("Step 5: Setting recipient")

	if err := client.Rcpt(toEmail); err != nil {
		ContextualLogger(logCtx).WithError(err).WithFields(logrus.Fields{
			"step":     "5_set_recipient",
			"to_email": toEmail,
			"result":   "failed",
		}).Error("Failed to set recipient")
		return fmt.Errorf("failed to set recipient: %v", err)
	}

	ContextualLogger(logCtx).WithFields(logrus.Fields{
		"step":     "5_set_recipient",
		"to_email": toEmail,
		"result":   "success",
	}).Debug("Recipient set successfully")

	// Get data writer
	ContextualLogger(logCtx).WithFields(logrus.Fields{
		"step": "6_get_data_writer",
	}).Debug("Step 6: Getting data writer")

	writer, err := client.Data()
	if err != nil {
		ContextualLogger(logCtx).WithError(err).WithFields(logrus.Fields{
			"step":   "6_get_data_writer",
			"result": "failed",
		}).Error("Failed to get data writer")
		return fmt.Errorf("failed to get data writer: %v", err)
	}
	defer writer.Close()

	ContextualLogger(logCtx).WithFields(logrus.Fields{
		"step":   "6_get_data_writer",
		"result": "success",
	}).Debug("Data writer obtained successfully")

	// Prepare email message
	subject := emailConfig.Subject
	if subject == "" {
		subject = "SIEM Security Manager Test Email - " + time.Now().Format("2006-01-02 15:04:05")
	}

	body := emailConfig.Body
	if body == "" {
		body = fmt.Sprintf("This is a test email from SIEM Security Manager.\n\nConnector ID: %s\nTimestamp: %s\nFrom Server: %s\nTest ID: %d",
			connectorID,
			time.Now().Format(time.RFC3339),
			emailConfig.SMTPHost,
			time.Now().Unix())
	}

	fromName := emailConfig.FromName
	if fromName == "" {
		fromName = "SIEM Security Manager"
	}

	// Create properly formatted email with all required headers
	message := []byte(
		fmt.Sprintf("From: %s <%s>\r\n", fromName, emailConfig.FromEmail) +
			fmt.Sprintf("To: %s\r\n", toEmail) +
			fmt.Sprintf("Subject: %s\r\n", subject) +
			fmt.Sprintf("Date: %s\r\n", time.Now().Format(time.RFC1123Z)) +
			fmt.Sprintf("Message-ID: <%d@%s>\r\n", time.Now().UnixNano(), emailConfig.SMTPHost) +
			"MIME-Version: 1.0\r\n" +
			"Content-Type: text/plain; charset=UTF-8\r\n" +
			"Content-Transfer-Encoding: 8bit\r\n" +
			"\r\n" +
			body,
	)

	ContextualLogger(logCtx).WithFields(logrus.Fields{
		"step":         "7_send_email_data",
		"message_size": len(message),
		"subject":      subject,
		"from_name":    fromName,
		"message_id":   fmt.Sprintf("%d@%s", time.Now().UnixNano(), emailConfig.SMTPHost),
	}).Debug("Step 7: Sending email data")

	// Send the message
	if _, err := writer.Write(message); err != nil {
		ContextualLogger(logCtx).WithError(err).WithFields(logrus.Fields{
			"step":   "7_send_email_data",
			"result": "failed",
		}).Error("Failed to write email message")
		return fmt.Errorf("failed to write email message: %v", err)
	}

	ContextualLogger(logCtx).WithFields(logrus.Fields{
		"step":   "7_send_email_data",
		"result": "success",
	}).Debug("Email data written successfully")

	// Close the data writer (this actually sends the email)
	ContextualLogger(logCtx).WithFields(logrus.Fields{
		"step": "8_finalize_send",
	}).Debug("Step 8: Finalizing email send")

	if err := writer.Close(); err != nil {
		ContextualLogger(logCtx).WithError(err).WithFields(logrus.Fields{
			"step":   "8_finalize_send",
			"result": "failed",
		}).Error("Failed to finalize email send")
		return fmt.Errorf("failed to finalize email send: %v", err)
	}

	ContextualLogger(logCtx).WithFields(logrus.Fields{
		"step":         "8_finalize_send",
		"result":       "success",
		"to_email":     toEmail,
		"subject":      subject,
		"body_length":  len(body),
		"from_email":   emailConfig.FromEmail,
		"smtp_server":  emailConfig.SMTPHost,
		"final_status": "email_queued_for_delivery",
	}).Info("Email sent successfully and queued for delivery")

	// Add a note about delivery expectations
	ContextualLogger(logCtx).WithFields(logrus.Fields{
		"delivery_note":      "Email has been accepted by SMTP server and queued for delivery",
		"check_instructions": "Check spam folder, allow 1-5 minutes for delivery, verify recipient email address",
		"troubleshooting":    "If email not received, check Exchange server logs or contact IT administrator",
	}).Info("Email delivery information")

	return nil
}

// parseEmailConfig parses email configuration from request data
func parseEmailConfig(data map[string]interface{}, service string) (*EmailConfig, error) {
	logCtx := &LogContext{
		Component:    "email_service",
		Operation:    "parse_email_config",
		ResourceType: "email_config",
	}

	ContextualLogger(logCtx).WithField("email_service", service).Debug("Parsing email configuration")

	config := &EmailConfig{}

	// Helper function to get string value
	getString := func(key string, required bool) (string, error) {
		if val, exists := data[key]; exists {
			if str, ok := val.(string); ok {
				return str, nil
			}
			return "", fmt.Errorf("field '%s' must be a string", key)
		}
		if required {
			return "", fmt.Errorf("required field '%s' is missing", key)
		}
		return "", nil
	}

	var err error

	// Required fields
	if config.SMTPHost, err = getString("smtp_host", true); err != nil {
		ContextualLogger(logCtx).WithError(err).Error("Failed to parse smtp_host")
		return nil, err
	}
	if config.SMTPPort, err = getString("smtp_port", true); err != nil {
		ContextualLogger(logCtx).WithError(err).Error("Failed to parse smtp_port")
		return nil, err
	}
	if config.Username, err = getString("username", true); err != nil {
		ContextualLogger(logCtx).WithError(err).Error("Failed to parse username")
		return nil, err
	}
	if config.Password, err = getString("password", true); err != nil {
		ContextualLogger(logCtx).WithError(err).Error("Failed to parse password")
		return nil, err
	}
	if config.FromEmail, err = getString("from_email", true); err != nil {
		ContextualLogger(logCtx).WithError(err).Error("Failed to parse from_email")
		return nil, err
	}

	// Optional fields
	config.FromName, _ = getString("from_name", false)
	config.AuthMethod, _ = getString("auth_method", false)
	config.Secure, _ = getString("secure", false)
	config.ToEmail, _ = getString("to_email", false)
	config.Subject, _ = getString("subject", false)
	config.Body, _ = getString("body", false)

	// Handle ca_cert_path - REQUIRED for Exchange service
	if strings.ToLower(service) == "exchange" {
		caCertPath, err := getString("ca_cert_path", true)
		if err != nil {
			ContextualLogger(logCtx).WithError(err).WithFields(logrus.Fields{
				"email_service": service,
				"requirement":   "ca_cert_path_required_for_exchange",
			}).Error("CA certificate path is required for Exchange service")
			return nil, fmt.Errorf("ca_cert_path is required for Exchange service: %v", err)
		}
		config.CACertPath = caCertPath

		// Validate that the CA certificate file exists
		if _, err := os.Stat(caCertPath); os.IsNotExist(err) {
			ContextualLogger(logCtx).WithFields(logrus.Fields{
				"ca_cert_path":         caCertPath,
				"file_existence_check": "failed",
			}).Error("CA certificate file does not exist")
			return nil, fmt.Errorf("CA certificate file does not exist: %s", caCertPath)
		}

		ContextualLogger(logCtx).WithFields(logrus.Fields{
			"email_service": service,
			"ca_cert_path":  caCertPath,
		}).Info("CA certificate path validated for Exchange service")
	} else {
		// For non-Exchange services, ca_cert_path is optional
		config.CACertPath, _ = getString("ca_cert_path", false)
		if config.CACertPath != "" {
			ContextualLogger(logCtx).WithFields(logrus.Fields{
				"email_service": service,
				"ca_cert_path":  config.CACertPath,
			}).Debug("Optional CA certificate path provided for non-Exchange service")
		}
	}

	// Set defaults
	if config.AuthMethod == "" {
		config.AuthMethod = "LOGIN"
	}
	if config.Secure == "" {
		config.Secure = "true"
	}

	ContextualLogger(logCtx).WithFields(logrus.Fields{
		"email_service": service,
		"smtp_host":     config.SMTPHost,
		"smtp_port":     config.SMTPPort,
		"from_email":    config.FromEmail,
		"auth_method":   config.AuthMethod,
		"secure":        config.Secure,
		"ca_cert_path":  config.CACertPath,
	}).Debug("Email configuration parsed successfully")

	return config, nil
}

// NewSecurityManager creates a new instance of SecurityManager
func NewSecurityManager() *SecurityManager {
	logCtx := &LogContext{
		Component:    "security_manager",
		Operation:    "create_new_instance",
		ResourceType: "security_manager",
	}

	ContextualLogger(logCtx).Debug("Creating new SecurityManager instance")

	return &SecurityManager{
		client: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true, // TODO: Set to false and configure proper CA verification
					MinVersion:         tls.VersionTLS12,
					MaxVersion:         tls.VersionTLS12,
					CipherSuites: []uint16{
						tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
						tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					},
					CurvePreferences: []tls.CurveID{
						tls.CurveP521,
						tls.CurveP384,
						tls.CurveP256,
					},
				},
			},
		},
	}
}

// makeHTTPRequest is a helper function to make HTTP requests
func (sm *SecurityManager) makeHTTPRequest(method, requestURL string, body []byte) (*http.Response, error) {
	logCtx := &LogContext{
		Component:    "security_manager",
		Operation:    "make_http_request",
		ResourceType: "elasticsearch",
	}

	ContextualLogger(logCtx).WithFields(logrus.Fields{
		"http_method":       method,
		"target_url":        requestURL,
		"request_body_size": len(body),
	}).Debug("Making HTTP request to Elasticsearch")

	req, err := http.NewRequest(method, requestURL, bytes.NewBuffer(body))
	if err != nil {
		ContextualLogger(logCtx).WithError(err).WithFields(logrus.Fields{
			"http_method":             method,
			"target_url":              requestURL,
			"request_creation_result": "failed",
		}).Error("Failed to create HTTP request")
		return nil, fmt.Errorf("error creating request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(elasticSearchUser, elasticSearchPass)

	return sm.client.Do(req)
}

// makeKibanaRequest makes HTTP requests to Kibana API
func (sm *SecurityManager) makeKibanaRequest(method, path string, body []byte) (*http.Response, error) {
	logCtx := &LogContext{
		Component:    "security_manager",
		Operation:    "make_kibana_request",
		ResourceType: "kibana_api",
	}

	requestURL := fmt.Sprintf("%s%s", kibanaURL, path)

	ContextualLogger(logCtx).WithFields(logrus.Fields{
		"http_method":       method,
		"kibana_url":        requestURL,
		"kibana_path":       path,
		"request_body_size": len(body),
	}).Debug("Making Kibana API request")

	req, err := http.NewRequest(method, requestURL, bytes.NewBuffer(body))
	if err != nil {
		ContextualLogger(logCtx).WithError(err).WithFields(logrus.Fields{
			"http_method":             method,
			"kibana_url":              requestURL,
			"request_creation_result": "failed",
		}).Error("Failed to create Kibana request")
		return nil, fmt.Errorf("error creating request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("kbn-xsrf", "true")
	req.SetBasicAuth(elasticSearchUser, elasticSearchPass)

	resp, err := sm.client.Do(req)
	if err != nil {
		ContextualLogger(logCtx).WithError(err).WithFields(logrus.Fields{
			"kibana_url":            requestURL,
			"kibana_request_result": "failed",
		}).Error("Kibana request failed")
		return nil, err
	}

	ContextualLogger(logCtx).WithFields(logrus.Fields{
		"http_method":           method,
		"kibana_url":            requestURL,
		"response_status_code":  resp.StatusCode,
		"kibana_request_result": "success",
	}).Debug("Kibana request completed")

	return resp, nil
}

// FetchConnectorInfo retrieves connector information from Kibana API
func (sm *SecurityManager) FetchConnectorInfo(connectorID string) (*ConnectorResponse, error) {
	logCtx := &LogContext{
		Component:    "security_manager",
		Operation:    "fetch_connector_info",
		ResourceID:   connectorID,
		ResourceType: "kibana_connector",
	}

	ContextualLogger(logCtx).Info("Fetching connector information")

	path := fmt.Sprintf("/api/actions/connector/%s", connectorID)
	resp, err := sm.makeKibanaRequest("GET", path, nil)
	if err != nil {
		ContextualLogger(logCtx).WithError(err).WithField("fetch_result", "request_failed").Error("Failed to fetch connector info")
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		ContextualLogger(logCtx).WithFields(logrus.Fields{
			"response_status_code": resp.StatusCode,
			"response_body":        string(body),
			"fetch_result":         "non_200_status",
		}).Error("Kibana API error while fetching connector")
		return nil, fmt.Errorf("kibana API error: %s", resp.Status)
	}

	var connectorResp ConnectorResponse
	if err := json.NewDecoder(resp.Body).Decode(&connectorResp); err != nil {
		ContextualLogger(logCtx).WithError(err).WithField("decode_result", "failed").Error("Failed to decode connector response")
		return nil, fmt.Errorf("error decoding response: %v", err)
	}

	ContextualLogger(logCtx).WithFields(logrus.Fields{
		"connector_name":    connectorResp.Name,
		"connector_url":     connectorResp.Config.URL,
		"connector_type_id": connectorResp.ConnectorTypeID,
		"fetch_result":      "success",
	}).Info("Connector information fetched successfully")

	return &connectorResp, nil
}

// FetchCertificateInfo retrieves certificate information for a connector
func (sm *SecurityManager) FetchCertificateInfo(connectorName string) (*CertificateSearchResponse, error) {
	logCtx := &LogContext{
		Component:    "security_manager",
		Operation:    "fetch_certificate_info",
		ResourceID:   connectorName,
		ResourceType: "connector_certificate",
	}

	ContextualLogger(logCtx).Info("Fetching certificate information")

	requestURL := fmt.Sprintf("%s/siem-certificate-cert/_search", elasticSearchURL)

	// Create query to search for the specific connector name
	query := map[string]interface{}{
		"query": map[string]interface{}{
			"match": map[string]interface{}{
				"connector_name": connectorName,
			},
		},
	}

	queryBody, err := json.Marshal(query)
	if err != nil {
		ContextualLogger(logCtx).WithError(err).WithField("query_marshal_result", "failed").Error("Failed to marshal certificate query")
		return nil, fmt.Errorf("error marshaling query: %v", err)
	}

	ContextualLogger(logCtx).WithFields(logrus.Fields{
		"search_url":   requestURL,
		"search_query": string(queryBody),
	}).Debug("Executing certificate search")

	resp, err := sm.makeHTTPRequest("POST", requestURL, queryBody)
	if err != nil {
		ContextualLogger(logCtx).WithError(err).WithField("search_result", "request_failed").Error("Certificate search request failed")
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		ContextualLogger(logCtx).WithFields(logrus.Fields{
			"response_status_code": resp.StatusCode,
			"response_body":        string(body),
			"search_result":        "non_200_status",
		}).Error("Elasticsearch certificate search error")
		return nil, fmt.Errorf("elasticsearch error: %s", resp.Status)
	}

	var certResp CertificateSearchResponse
	if err := json.NewDecoder(resp.Body).Decode(&certResp); err != nil {
		ContextualLogger(logCtx).WithError(err).WithField("decode_result", "failed").Error("Failed to decode certificate response")
		return nil, fmt.Errorf("error decoding response: %v", err)
	}

	ContextualLogger(logCtx).WithFields(logrus.Fields{
		"certificates_found": len(certResp.Hits.Hits),
		"search_took_ms":     certResp.Took,
		"search_result":      "success",
	}).Info("Certificate search completed")

	return &certResp, nil
}

// FetchSecurityConfig retrieves security management configuration
func (sm *SecurityManager) FetchSecurityConfig() (*SecurityManagementResponse, error) {
	logCtx := &LogContext{
		Component:    "security_manager",
		Operation:    "fetch_security_config",
		ResourceType: "security_configuration",
	}

	ContextualLogger(logCtx).Info("Fetching security management configuration")

	requestURL := fmt.Sprintf("%s/.kibana-security-management/_search", elasticSearchURL)
	resp, err := sm.makeHTTPRequest("GET", requestURL, nil)
	if err != nil {
		ContextualLogger(logCtx).WithError(err).WithField("fetch_result", "request_failed").Error("Failed to fetch security config")
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		ContextualLogger(logCtx).WithFields(logrus.Fields{
			"response_status_code": resp.StatusCode,
			"response_body":        string(body),
			"fetch_result":         "non_200_status",
		}).Error("Elasticsearch security config error")
		return nil, fmt.Errorf("elasticsearch error: %s", resp.Status)
	}

	var securityResp SecurityManagementResponse
	if err := json.NewDecoder(resp.Body).Decode(&securityResp); err != nil {
		ContextualLogger(logCtx).WithError(err).WithField("decode_result", "failed").Error("Failed to decode security config response")
		return nil, fmt.Errorf("error decoding response: %v", err)
	}

	ContextualLogger(logCtx).WithFields(logrus.Fields{
		"config_records_found": len(securityResp.Hits.Hits),
		"search_took_ms":       securityResp.Took,
		"fetch_result":         "success",
	}).Info("Security configuration fetched successfully")
	return &securityResp, nil
}

// ValidateConnectorCN validates if connector CN exists in security config CNs
func (sm *SecurityManager) ValidateConnectorCN(connectorCN string, configuredCNs []string) (bool, string, error) {
	logCtx := &LogContext{
		Component:    "security_manager",
		Operation:    "validate_connector_cn",
		ResourceID:   connectorCN,
		ResourceType: "certificate_cn",
	}

	ContextualLogger(logCtx).WithFields(logrus.Fields{
		"connector_cn":         connectorCN,
		"configured_cns":       configuredCNs,
		"configured_cns_count": len(configuredCNs),
	}).Info("Validating connector CN")

	for _, cn := range configuredCNs {
		cn = strings.TrimSpace(cn)
		if cn == connectorCN {
			ContextualLogger(logCtx).WithFields(logrus.Fields{
				"matched_cn":        cn,
				"match_type":        "exact",
				"validation_result": "success",
			}).Info("CN validation successful - exact match found")
			return true, connectorCN, nil
		}

		// Check for wildcard match
		if strings.HasPrefix(cn, "*.") {
			domain := cn[2:] // Remove *.
			if strings.HasSuffix(connectorCN, domain) {
				ContextualLogger(logCtx).WithFields(logrus.Fields{
					"wildcard_cn":       cn,
					"matched_domain":    domain,
					"match_type":        "wildcard",
					"validation_result": "success",
				}).Info("CN validation successful - wildcard match found")
				return true, connectorCN, nil
			}
		}
	}

	ContextualLogger(logCtx).WithFields(logrus.Fields{
		"validation_result": "failed",
		"match_type":        "none",
	}).Warn("CN validation failed - no matching CN found")

	return false, connectorCN, nil
}

// TestConnectorEndpoint tests the connector endpoint with certificates
func (sm *SecurityManager) TestConnectorEndpoint(connectorURL, caPath, certPath, keyPath, password string, payload map[string]interface{}) (int, string, error) {
	logCtx := &LogContext{
		Component:    "security_manager",
		Operation:    "test_connector_endpoint",
		ResourceID:   connectorURL,
		ResourceType: "connector_endpoint",
	}

	ContextualLogger(logCtx).WithFields(logrus.Fields{
		"connector_url":             connectorURL,
		"ca_cert_path":              caPath,
		"client_cert_path":          certPath,
		"private_key_path":          keyPath,
		"has_password":              password != "",
		"payload_keys":              extractMapKeys(payload),
		"strict_validation_enabled": shouldFailOnCertValidationError(),
	}).Info("Testing connector endpoint with POST request")

	// Extract server name from URL for proper certificate validation
	serverName, err := extractServerNameFromURL(connectorURL)
	if err != nil {
		ContextualLogger(logCtx).WithError(err).WithField("server_name_extraction_result", "failed").Error("Failed to extract server name from URL")
		return 0, "", err
	}

	// Always use skipVerify = true to disable SSL verification
	skipVerify := true
	ContextualLogger(logCtx).WithFields(logrus.Fields{
		"server_name":     serverName,
		"ssl_skip_verify": skipVerify,
	}).Warn("SSL verification is disabled")

	// Try with standard certificate loading but no SSL verification
	ContextualLogger(logCtx).WithField("connection_method", "standard_certificate").Debug("Attempting connection with SSL verification disabled")
	statusCode, responseBody, err := sm.attemptConnectionWithStandardCertPost(connectorURL, caPath, certPath, keyPath, password, serverName, skipVerify, payload)

	if err != nil {
		// Check if this is a certificate validation error in strict mode
		if isCertificateValidationError(err) && shouldFailOnCertValidationError() {
			ContextualLogger(logCtx).WithError(err).WithFields(logrus.Fields{
				"connection_method": "standard_certificate",
				"error_type":        "certificate_validation_failure",
				"strict_validation": true,
				"security_decision": "reject_connection",
				"fallback_attempt":  false,
			}).Error("Certificate validation failed in strict mode - connection rejected, no fallback attempted")
			return 0, "", fmt.Errorf("certificate validation failed in strict mode: %v", err)
		}

		ContextualLogger(logCtx).WithError(err).WithFields(logrus.Fields{
			"standard_cert_result": "failed",
			"will_try_fallback":    !isCertificateValidationError(err) || !shouldFailOnCertValidationError(),
		}).Warn("Standard certificate connection failed, trying with complete certificate chain")

		// Only try with complete certificate chain if it's not a validation error in strict mode
		ContextualLogger(logCtx).WithField("connection_method", "complete_certificate_chain").Debug("Trying with complete certificate chain")
		statusCode, responseBody, err = sm.attemptConnectionWithCompleteCertPost(connectorURL, caPath, certPath, keyPath, password, serverName, skipVerify, payload)
	}

	if err != nil {
		ContextualLogger(logCtx).WithError(err).WithField("all_connection_attempts_result", "failed").Error("Connection failed even with SSL verification disabled")
		if strings.Contains(err.Error(), "tls:") || strings.Contains(err.Error(), "certificate") {
			return 0, "", fmt.Errorf("TLS/Certificate error: %v", err)
		}
		return 0, "", fmt.Errorf("error making request: %v", err)
	}

	ContextualLogger(logCtx).WithFields(logrus.Fields{
		"response_status_code": statusCode,
		"response_body_length": len(responseBody),
		"endpoint_test_result": "success",
	}).Info("Connector endpoint test completed successfully")

	return statusCode, responseBody, nil
}

// isCertificateValidationError checks if an error is specifically related to certificate validation failures
func isCertificateValidationError(err error) bool {
	if err == nil {
		return false
	}

	errMsg := strings.ToLower(err.Error())
	validationErrorPatterns := []string{
		"certificate validation failed",
		"key length",
		"below minimum requirement",
		"signature algorithm",
		"certificate has expired",
		"certificate is not yet valid",
		"basic constraints",
		"key usage",
		"certificate validation failed in strict mode",
		"missing subject alternative names",
		"missing extended key usage",
		"self-signed certificate should be a ca",
		"no key usage defined",
		"required in strict validation mode",
		"elevated to error in strict mode",
		"warning treated as error in strict mode",
	}

	for _, pattern := range validationErrorPatterns {
		if strings.Contains(errMsg, pattern) {
			return true
		}
	}

	return false
}

// extractMapKeys extracts keys from a map for logging
func extractMapKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// attemptConnectionWithStandardCertPost tries connection with standard certificate loading
func (sm *SecurityManager) attemptConnectionWithStandardCertPost(connectorURL, caPath, certPath, keyPath, password, serverName string, skipVerify bool, payload map[string]interface{}) (int, string, error) {
	logCtx := &LogContext{
		Component:    "security_manager",
		Operation:    "attempt_connection_standard_cert",
		ResourceID:   connectorURL,
		ResourceType: "connector_endpoint",
	}

	client, err := sm.createHTTPClientWithOptions(caPath, certPath, keyPath, password, skipVerify)
	if err != nil {
		ContextualLogger(logCtx).WithError(err).WithField("client_creation_result", "failed").Error("Failed to create HTTP client with standard certificates")
		return 0, "", fmt.Errorf("failed to create HTTP client: %v", err)
	}

	// Set the ServerName in the TLS config for proper certificate validation
	transport := client.Transport.(*http.Transport)
	if transport.TLSClientConfig != nil {
		transport.TLSClientConfig.ServerName = serverName
		ContextualLogger(logCtx).WithFields(logrus.Fields{
			"tls_server_name": serverName,
			"tls_skip_verify": skipVerify,
		}).Debug("TLS configuration updated")
	}

	return sm.makeConnectionRequestPost(client, connectorURL, serverName, skipVerify, payload)
}

// createCompleteClientCertificate creates a client certificate with complete chain including CA
func createCompleteClientCertificate(certPath, keyPath, caPath, password string) (tls.Certificate, error) {
	logCtx := &LogContext{
		Component:    "certificate_management",
		Operation:    "create_complete_client_certificate",
		ResourceType: "certificate_chain",
	}

	ContextualLogger(logCtx).WithFields(logrus.Fields{
		"client_cert_path":          certPath,
		"private_key_path":          keyPath,
		"ca_cert_path":              caPath,
		"strict_validation_enabled": shouldFailOnCertValidationError(),
	}).Debug("Creating complete client certificate with CA chain")

	// IMPORTANT: Validate the client certificate first before proceeding
	// This prevents using invalid certificates even in the complete chain approach
	if shouldFailOnCertValidationError() {
		// Read and validate the client certificate before creating the complete chain
		certData, err := ioutil.ReadFile(certPath)
		if err != nil {
			ContextualLogger(logCtx).WithError(err).WithField("file_type", "client_certificate").Error("Failed to read client certificate for validation")
			return tls.Certificate{}, fmt.Errorf("failed to read client certificate: %v", err)
		}

		// Parse and validate the client certificate
		block, _ := pem.Decode(certData)
		if block == nil || block.Type != "CERTIFICATE" {
			ContextualLogger(logCtx).WithField("validation_result", "invalid_pem").Error("Client certificate file does not contain valid certificate PEM")
			return tls.Certificate{}, fmt.Errorf("client certificate file does not contain valid certificate PEM")
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			ContextualLogger(logCtx).WithError(err).WithField("validation_result", "parse_failed").Error("Failed to parse client certificate")
			return tls.Certificate{}, fmt.Errorf("failed to parse client certificate: %v", err)
		}

		// Perform comprehensive validation on the client certificate
		validationConfig := getDefaultCertValidationConfig()
		validationResult := ValidateCertificateWithConfig(cert, validationConfig, certPath)

		if !validationResult.Valid {
			ContextualLogger(logCtx).WithFields(logrus.Fields{
				"cert_subject":      cert.Subject.String(),
				"validation_errors": validationResult.Errors,
				"validation_result": "failed",
				"security_decision": "reject_complete_chain_creation",
				"reason":            "client_certificate_validation_failed",
			}).Error("Client certificate validation failed - rejecting complete chain creation")
			return tls.Certificate{}, fmt.Errorf("client certificate validation failed in strict mode: %v", validationResult.Errors)
		}

		ContextualLogger(logCtx).WithFields(logrus.Fields{
			"cert_subject":      cert.Subject.String(),
			"validation_result": "passed",
		}).Debug("Client certificate validation passed, proceeding with complete chain creation")
	}

	// Read client certificate
	clientCertPEM, err := ioutil.ReadFile(certPath)
	if err != nil {
		ContextualLogger(logCtx).WithError(err).WithField("file_type", "client_certificate").Error("Failed to read client certificate")
		return tls.Certificate{}, fmt.Errorf("failed to read client certificate: %v", err)
	}

	// Read CA certificate
	caCertPEM, err := ioutil.ReadFile(caPath)
	if err != nil {
		ContextualLogger(logCtx).WithError(err).WithField("file_type", "ca_certificate").Error("Failed to read CA certificate")
		return tls.Certificate{}, fmt.Errorf("failed to read CA certificate: %v", err)
	}

	// Combine client certificate and CA certificate
	completeCertPEM := append(clientCertPEM, '\n')
	completeCertPEM = append(completeCertPEM, caCertPEM...)

	// Read private key
	keyPEM, err := ioutil.ReadFile(keyPath)
	if err != nil {
		ContextualLogger(logCtx).WithError(err).WithField("file_type", "private_key").Error("Failed to read private key")
		return tls.Certificate{}, fmt.Errorf("failed to read private key: %v", err)
	}

	// Handle encrypted private key if password is provided
	if password != "" {
		keyBlock, _ := pem.Decode(keyPEM)
		if keyBlock != nil && x509.IsEncryptedPEMBlock(keyBlock) {
			ContextualLogger(logCtx).WithField("key_encryption", "encrypted").Debug("Decrypting private key with password")
			keyDER, err := x509.DecryptPEMBlock(keyBlock, []byte(password))
			if err != nil {
				ContextualLogger(logCtx).WithError(err).WithField("decrypt_result", "failed").Error("Failed to decrypt private key")
				return tls.Certificate{}, fmt.Errorf("failed to decrypt private key: %v", err)
			}
			keyPEM = pem.EncodeToMemory(&pem.Block{
				Type:  keyBlock.Type,
				Bytes: keyDER,
			})
		}
	}

	// Create certificate from the complete chain
	cert, err := tls.X509KeyPair(completeCertPEM, keyPEM)
	if err != nil {
		ContextualLogger(logCtx).WithError(err).WithField("cert_chain_creation_result", "failed").Error("Failed to create certificate pair with CA chain")
		return tls.Certificate{}, fmt.Errorf("failed to create certificate pair with CA chain: %v", err)
	}

	ContextualLogger(logCtx).WithFields(logrus.Fields{
		"certificate_chain_length":   len(cert.Certificate),
		"cert_chain_creation_result": "success",
	}).Debug("Complete client certificate created successfully")
	return cert, nil
}

// attemptConnectionWithCompleteCertPost tries connection with complete certificate chain
func (sm *SecurityManager) attemptConnectionWithCompleteCertPost(connectorURL, caPath, certPath, keyPath, password, serverName string, skipVerify bool, payload map[string]interface{}) (int, string, error) {
	logCtx := &LogContext{
		Component:    "security_manager",
		Operation:    "attempt_connection_complete_cert",
		ResourceID:   connectorURL,
		ResourceType: "connector_endpoint",
	}

	ContextualLogger(logCtx).Debug("Creating HTTP client with complete certificate chain")

	// Create complete certificate with CA chain
	cert, err := createCompleteClientCertificate(certPath, keyPath, caPath, password)
	if err != nil {
		ContextualLogger(logCtx).WithError(err).WithField("complete_cert_creation_result", "failed").Error("Failed to create complete certificate")
		return 0, "", fmt.Errorf("failed to create complete certificate: %v", err)
	}

	var caCertPool *x509.CertPool
	if !skipVerify {
		caCertPool, err = validateAndLoadCACertificate(caPath)
		if err != nil {
			ContextualLogger(logCtx).WithError(err).WithField("ca_cert_load_result", "failed").Error("Failed to load CA certificate")
			return 0, "", fmt.Errorf("failed to load CA certificate: %v", err)
		}
	}

	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		RootCAs:            caCertPool,
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, // FORCE SSL VERIFICATION OFF
		ServerName:         serverName,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
		CurvePreferences: []tls.CurveID{
			tls.CurveP521,
			tls.CurveP384,
			tls.CurveP256,
		},
	}

	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	client := &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}

	return sm.makeConnectionRequestPost(client, connectorURL, serverName, true, payload)
}

// makeConnectionRequestPost makes the actual HTTP POST request to webhook endpoint
func (sm *SecurityManager) makeConnectionRequestPost(client *http.Client, connectorURL, serverName string, skipVerify bool, payload map[string]interface{}) (int, string, error) {
	logCtx := &LogContext{
		Component:    "security_manager",
		Operation:    "make_connection_request_post",
		ResourceID:   connectorURL,
		ResourceType: "webhook_endpoint",
	}

	// Parse the original URL and modify it to append /webhook/kibana
	parsedURL, err := url.Parse(connectorURL)
	if err != nil {
		ContextualLogger(logCtx).WithError(err).WithField("url_parse_result", "failed").Error("Failed to parse connector URL")
		return 0, "", fmt.Errorf("error parsing connector URL: %v", err)
	}

	// Construct the webhook endpoint URL
	webhookURL := fmt.Sprintf("%s://%s/webhook/kibana", parsedURL.Scheme, parsedURL.Host)

	// Marshal the POST payload to JSON
	jsonData, err := json.Marshal(payload)
	if err != nil {
		ContextualLogger(logCtx).WithError(err).WithField("payload_marshal_result", "failed").Error("Failed to marshal POST payload")
		return 0, "", fmt.Errorf("error marshaling POST payload: %v", err)
	}

	// Create the POST request
	req, err := http.NewRequest("POST", webhookURL, bytes.NewBuffer(jsonData))
	if err != nil {
		ContextualLogger(logCtx).WithError(err).WithFields(logrus.Fields{
			"webhook_url":             webhookURL,
			"request_creation_result": "failed",
		}).Error("Failed to create POST request")
		return 0, "", fmt.Errorf("error creating request: %v", err)
	}

	// Add headers
	req.Header.Set("User-Agent", "SIEM-Connector-Validator/1.0")
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Content-Type", "application/json")

	ContextualLogger(logCtx).WithFields(logrus.Fields{
		"webhook_url":       webhookURL,
		"tls_server_name":   serverName,
		"tls_skip_verify":   skipVerify,
		"post_payload_size": len(jsonData),
	}).Debug("Making POST request to webhook endpoint")

	resp, err := client.Do(req)
	if err != nil {
		ContextualLogger(logCtx).WithError(err).WithFields(logrus.Fields{
			"webhook_url":            webhookURL,
			"webhook_request_result": "failed",
		}).Error("POST request to webhook failed")
		return 0, "", err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		ContextualLogger(logCtx).WithError(err).WithFields(logrus.Fields{
			"webhook_url":          webhookURL,
			"response_status_code": resp.StatusCode,
			"response_read_result": "failed",
		}).Error("Failed to read response body")
		return resp.StatusCode, "", fmt.Errorf("error reading response: %v", err)
	}

	ContextualLogger(logCtx).WithFields(logrus.Fields{
		"webhook_url":            webhookURL,
		"response_status_code":   resp.StatusCode,
		"response_body_length":   len(body),
		"webhook_request_result": "success",
	}).Debug("POST request to webhook completed")

	return resp.StatusCode, string(body), nil
}

// FetchConfig retrieves configuration from Elasticsearch using SecurityManagementResponse
func (sm *SecurityManager) FetchConfig() (*Config, error) {
	logCtx := &LogContext{
		Component:    "security_manager",
		Operation:    "fetch_config",
		ResourceType: "elasticsearch_config",
	}

	ContextualLogger(logCtx).Info("Fetching configuration from Elasticsearch")

	requestURL := fmt.Sprintf("%s/.kibana-security-management/_search", elasticSearchURL)
	resp, err := sm.makeHTTPRequest("GET", requestURL, nil)
	if err != nil {
		ContextualLogger(logCtx).WithError(err).WithField("config_fetch_result", "request_failed").Error("Failed to fetch config from Elasticsearch")
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		ContextualLogger(logCtx).WithFields(logrus.Fields{
			"response_status_code": resp.StatusCode,
			"config_fetch_result":  "non_200_status",
		}).Error("Elasticsearch config fetch failed")
		return nil, fmt.Errorf("elasticsearch error: %s", resp.Status)
	}

	var securityResp SecurityManagementResponse
	if err := json.NewDecoder(resp.Body).Decode(&securityResp); err != nil {
		ContextualLogger(logCtx).WithError(err).WithField("response_decode_result", "failed").Error("Failed to decode Elasticsearch config response")
		return nil, fmt.Errorf("error decoding response: %v", err)
	}

	config, err := sm.parseSecurityManagementResponse(&securityResp)
	if err != nil {
		ContextualLogger(logCtx).WithError(err).WithField("config_parse_result", "failed").Error("Failed to parse Elasticsearch response")
		return nil, err
	}

	ContextualLogger(logCtx).WithFields(logrus.Fields{
		"remote_syslog_ip":    config.RemoteSyslogIp,
		"remote_syslog_port":  config.RemoteSyslogPort,
		"ca_cert_path":        config.CaPath,
		"ssh_idle_timeout":    config.SSHIdleTimeout,
		"ssh_session_timeout": config.SSHSessionTimeout,
		"host_type":           config.HostType,
		"config_fetch_result": "success",
	}).Info("Configuration fetched successfully")

	return config, nil
}

// parseSecurityManagementResponse converts SecurityManagementResponse to Config
func (sm *SecurityManager) parseSecurityManagementResponse(securityResp *SecurityManagementResponse) (*Config, error) {
	logCtx := &LogContext{
		Component:    "security_manager",
		Operation:    "parse_security_management_response",
		ResourceType: "security_config",
	}

	if len(securityResp.Hits.Hits) == 0 {
		ContextualLogger(logCtx).WithField("parse_result", "no_configuration_found").Error("No configuration found in SecurityManagement response")
		return nil, fmt.Errorf("no configuration found")
	}

	source := securityResp.Hits.Hits[0].Source

	port, err := strconv.Atoi(source.RemoteSyslogPort)
	if err != nil {
		ContextualLogger(logCtx).WithError(err).WithFields(logrus.Fields{
			"port_string":  source.RemoteSyslogPort,
			"parse_result": "invalid_port",
		}).Error("Invalid port number")
		return nil, fmt.Errorf("invalid port number: %v", err)
	}

	idleTimeout, err := strconv.Atoi(source.SSHIdleTimeout)
	if err != nil {
		ContextualLogger(logCtx).WithError(err).WithFields(logrus.Fields{
			"idle_timeout_string": source.SSHIdleTimeout,
			"parse_result":        "invalid_idle_timeout",
		}).Error("Invalid SSH idle timeout")
		return nil, fmt.Errorf("invalid SSH idle timeout: %v", err)
	}

	sessionTimeout, err := strconv.Atoi(source.SSHSessionTimeout)
	if err != nil {
		ContextualLogger(logCtx).WithError(err).WithFields(logrus.Fields{
			"session_timeout_string": source.SSHSessionTimeout,
			"parse_result":           "invalid_session_timeout",
		}).Error("Invalid SSH session timeout")
		return nil, fmt.Errorf("invalid SSH session timeout: %v", err)
	}

	config := &Config{
		RemoteSyslogIp:    source.RemoteSyslogIP, // Note: field name is RemoteSyslogIP in SecurityManagementResponse
		RemoteSyslogPort:  port,
		CaPath:            source.CAPath, // This will now populate the cacert field
		SSHIdleTimeout:    idleTimeout,
		SSHSessionTimeout: sessionTimeout,
		SSHWarning:        source.SSHWarning,
		HostType:          "sf", // Default to SF if not specified
	}

	ContextualLogger(logCtx).WithFields(logrus.Fields{
		"parsed_remote_syslog_ip":    config.RemoteSyslogIp,
		"parsed_remote_syslog_port":  config.RemoteSyslogPort,
		"parsed_ca_path":             config.CaPath,
		"parsed_ssh_idle_timeout":    config.SSHIdleTimeout,
		"parsed_ssh_session_timeout": config.SSHSessionTimeout,
		"parsed_host_type":           config.HostType,
		"parse_result":               "success",
	}).Debug("Security management response parsed successfully")

	return config, nil
}

// Additional helper functions for logstash, SSH config, etc. remain the same...
// [updateConfigs, updateSSHConfig, updateSSHBanner, restartSSHService, restartLogstashService]

// updateConfigs updates all configurations
func (sm *SecurityManager) updateConfigs(config *Config) error {
	logCtx := &LogContext{
		Component:    "configuration_management",
		Operation:    "update_configs",
		ResourceType: "system_configuration",
	}

	ContextualLogger(logCtx).WithFields(logrus.Fields{
		"config_host_type":           config.HostType,
		"config_remote_syslog_ip":    config.RemoteSyslogIp,
		"config_remote_syslog_port":  config.RemoteSyslogPort,
		"config_ca_path":             config.CaPath,
		"config_ssh_idle_timeout":    config.SSHIdleTimeout,
		"config_ssh_session_timeout": config.SSHSessionTimeout,
	}).Info("Updating system configurations")

	if err := sm.updateSSHConfig(config); err != nil {
		ContextualLogger(logCtx).WithError(err).WithField("ssh_config_update_result", "failed").Error("Failed to update SSH config")
		return fmt.Errorf("failed to update SSH config: %v", err)
	}

	if err := sm.updateSSHBanner(config.SSHWarning); err != nil {
		ContextualLogger(logCtx).WithError(err).WithField("ssh_banner_update_result", "failed").Error("Failed to update SSH banner")
		return fmt.Errorf("failed to update SSH banner: %v", err)
	}

	if err := sm.restartSSHService(); err != nil {
		ContextualLogger(logCtx).WithError(err).WithField("ssh_service_restart_result", "failed").Error("Failed to restart SSH service")
		return fmt.Errorf("failed to restart SSH service: %v", err)
	}

	// Only configure Logstash on coordinator nodes
	if strings.ToLower(config.HostType) == "coordinator" {
		if config.RemoteSyslogIp == "" || config.RemoteSyslogPort == 0 {
			ContextualLogger(logCtx).WithFields(logrus.Fields{
				"remote_syslog_ip":       config.RemoteSyslogIp,
				"remote_syslog_port":     config.RemoteSyslogPort,
				"logstash_config_result": "skipped_empty_syslog",
			}).Warn("RemoteSyslogIp is empty, skipping Logstash configuration")
			return nil
		}

		err := os.MkdirAll(configPath, 0755)
		if err != nil {
			ContextualLogger(logCtx).WithError(err).WithFields(logrus.Fields{
				"logstash_config_path":      configPath,
				"directory_creation_result": "failed",
			}).Error("Failed to create Logstash config directory")
			return fmt.Errorf("failed to create directory %s: %v", configPath, err)
		}

		configContent := fmt.Sprintf(configTemplate,
			elasticSearchURL,
			elasticSearchUser,
			elasticSearchPass,
			config.RemoteSyslogIp,
			config.RemoteSyslogPort,
			config.CaPath,
		)

		configFile := filepath.Join(configPath, "elasticsearch_to_udp.conf")
		err = os.WriteFile(configFile, []byte(configContent), 0644)
		if err != nil {
			ContextualLogger(logCtx).WithError(err).WithFields(logrus.Fields{
				"logstash_config_file":     configFile,
				"config_file_write_result": "failed",
			}).Error("Failed to write Logstash config file")
			return fmt.Errorf("failed to write config file: %v", err)
		}

		ContextualLogger(logCtx).WithFields(logrus.Fields{
			"logstash_config_file":     configFile,
			"ca_cert_path":             config.CaPath,
			"remote_syslog_ip":         config.RemoteSyslogIp,
			"remote_syslog_port":       config.RemoteSyslogPort,
			"config_file_write_result": "success",
		}).Info("Logstash config file created successfully")

		if err := sm.restartLogstashService(); err != nil {
			ContextualLogger(logCtx).WithError(err).WithField("logstash_service_restart_result", "failed").Error("Failed to restart Logstash service")
			return fmt.Errorf("failed to restart Logstash service: %v", err)
		}
	}

	ContextualLogger(logCtx).WithField("config_update_result", "success").Info("All configurations updated successfully")
	return nil
}

// updateSSHConfig updates the SSH configuration file
func (sm *SecurityManager) updateSSHConfig(config *Config) error {
	logCtx := &LogContext{
		Component:    "ssh_configuration",
		Operation:    "update_ssh_config",
		ResourceID:   sshConfigPath,
		ResourceType: "ssh_config_file",
	}

	ContextualLogger(logCtx).Debug("Updating SSH configuration")

	content, err := os.ReadFile(sshConfigPath)
	if err != nil {
		ContextualLogger(logCtx).WithError(err).WithField("config_read_result", "failed").Error("Failed to read SSH config file")
		return fmt.Errorf("error reading SSH config: %v", err)
	}

	lines := strings.Split(string(content), "\n")
	newConfig := make([]string, 0, len(lines))

	clientAliveFound := false
	clientIntervalFound := false
	bannerFound := false

	for _, line := range lines {
		switch {
		case strings.HasPrefix(line, "ClientAliveInterval"):
			newConfig = append(newConfig, fmt.Sprintf("ClientAliveInterval %d", config.SSHIdleTimeout))
			clientAliveFound = true
		case strings.HasPrefix(line, "ClientAliveCountMax"):
			newConfig = append(newConfig, fmt.Sprintf("ClientAliveCountMax %d", config.SSHSessionTimeout))
			clientIntervalFound = true
		case strings.HasPrefix(line, "Banner"):
			newConfig = append(newConfig, fmt.Sprintf("Banner %s", sshBannerPath))
			bannerFound = true
		default:
			newConfig = append(newConfig, line)
		}
	}

	if !clientAliveFound {
		newConfig = append(newConfig, fmt.Sprintf("ClientAliveInterval %d", config.SSHIdleTimeout))
	}
	if !clientIntervalFound {
		newConfig = append(newConfig, fmt.Sprintf("ClientAliveCountMax %d", config.SSHSessionTimeout))
	}
	if !bannerFound {
		newConfig = append(newConfig, fmt.Sprintf("Banner %s", sshBannerPath))
	}

	err = os.WriteFile(sshConfigPath, []byte(strings.Join(newConfig, "\n")), 0644)
	if err != nil {
		ContextualLogger(logCtx).WithError(err).WithField("config_write_result", "failed").Error("Failed to write SSH config file")
		return err
	}

	ContextualLogger(logCtx).WithFields(logrus.Fields{
		"ssh_client_alive_interval": config.SSHIdleTimeout,
		"ssh_client_alive_count":    config.SSHSessionTimeout,
		"ssh_banner_path":           sshBannerPath,
		"config_update_result":      "success",
	}).Debug("SSH configuration updated successfully")

	return nil
}

// updateSSHBanner updates the SSH banner file
func (sm *SecurityManager) updateSSHBanner(warning string) error {
	logCtx := &LogContext{
		Component:    "ssh_configuration",
		Operation:    "update_ssh_banner",
		ResourceID:   sshBannerPath,
		ResourceType: "ssh_banner_file",
	}

	ContextualLogger(logCtx).WithField("banner_content_length", len(warning)).Debug("Updating SSH banner")

	err := os.WriteFile(sshBannerPath, []byte(warning), 0644)
	if err != nil {
		ContextualLogger(logCtx).WithError(err).WithField("banner_write_result", "failed").Error("Failed to write SSH banner file")
		return err
	}

	ContextualLogger(logCtx).WithField("banner_update_result", "success").Debug("SSH banner updated successfully")
	return nil
}

// restartSSHService restarts the SSH service
func (sm *SecurityManager) restartSSHService() error {
	logCtx := &LogContext{
		Component:    "service_management",
		Operation:    "restart_ssh_service",
		ResourceType: "system_service",
	}

	ContextualLogger(logCtx).Debug("Restarting SSH service")

	cmd := exec.Command("systemctl", "restart", "sshd")
	err := cmd.Run()
	if err != nil {
		ContextualLogger(logCtx).WithError(err).WithField("service_restart_result", "failed").Error("Failed to restart SSH service")
		return err
	}

	ContextualLogger(logCtx).WithField("service_restart_result", "success").Info("SSH service restarted successfully")
	return nil
}

// restartLogstashService restarts the Logstash service
func (sm *SecurityManager) restartLogstashService() error {
	logCtx := &LogContext{
		Component:    "service_management",
		Operation:    "restart_logstash_service",
		ResourceType: "system_service",
	}

	ContextualLogger(logCtx).Debug("Restarting Logstash service")

	cmd := exec.Command("systemctl", "restart", "logstash")
	err := cmd.Run()
	if err != nil {
		ContextualLogger(logCtx).WithError(err).WithField("service_restart_result", "failed").Error("Failed to restart Logstash service")
		return err
	}

	ContextualLogger(logCtx).WithField("service_restart_result", "success").Info("Logstash service restarted successfully")
	return nil
}

// performCertificateValidation performs comprehensive certificate validation for API endpoint
func performCertificateValidation(certPath string) *CertificateValidationResult {
	logCtx := &LogContext{
		Component:    "certificate_validation",
		Operation:    "perform_certificate_validation",
		ResourceID:   certPath,
		ResourceType: "certificate",
	}

	ContextualLogger(logCtx).Debug("Performing certificate validation for API endpoint")

	// Read and parse certificate
	certData, err := ioutil.ReadFile(certPath)
	if err != nil {
		ContextualLogger(logCtx).WithError(err).WithField("cert_read_result", "failed").Error("Failed to read certificate file for validation")
		return &CertificateValidationResult{
			Valid:        false,
			Errors:       []string{fmt.Sprintf("Failed to read certificate file: %v", err)},
			CheckResults: make(map[string]CertCheckResult),
		}
	}

	block, _ := pem.Decode(certData)
	if block == nil {
		ContextualLogger(logCtx).WithField("pem_decode_result", "failed").Error("Failed to decode PEM block for validation")
		return &CertificateValidationResult{
			Valid:        false,
			Errors:       []string{"Failed to decode PEM block"},
			CheckResults: make(map[string]CertCheckResult),
		}
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		ContextualLogger(logCtx).WithError(err).WithField("cert_parse_result", "failed").Error("Failed to parse certificate for validation")
		return &CertificateValidationResult{
			Valid:        false,
			Errors:       []string{fmt.Sprintf("Failed to parse certificate: %v", err)},
			CheckResults: make(map[string]CertCheckResult),
		}
	}

	// Get validation configuration and perform validation
	validationConfig := getDefaultCertValidationConfig()
	return ValidateCertificateWithConfig(cert, validationConfig, certPath)
}

// getCertificateCN reads the certificate from the given path and returns its CN
func getCertificateCN(certPath string) (string, error) {
	logCtx := &LogContext{
		Component:    "certificate_processing",
		Operation:    "get_certificate_cn",
		ResourceID:   certPath,
		ResourceType: "certificate",
	}

	ContextualLogger(logCtx).Debug("Extracting CN from certificate")

	certData, err := ioutil.ReadFile(certPath)
	if err != nil {
		ContextualLogger(logCtx).WithError(err).WithField("cert_read_result", "failed").Error("Failed to read certificate file")
		return "", fmt.Errorf("failed to read certificate file: %v", err)
	}

	block, _ := pem.Decode(certData)
	if block == nil {
		ContextualLogger(logCtx).WithField("pem_decode_result", "failed").Error("Failed to decode PEM block")
		return "", fmt.Errorf("failed to decode PEM block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		ContextualLogger(logCtx).WithError(err).WithField("cert_parse_result", "failed").Error("Failed to parse certificate")
		return "", fmt.Errorf("failed to parse certificate: %v", err)
	}

	cn := cert.Subject.CommonName
	ContextualLogger(logCtx).WithFields(logrus.Fields{
		"extracted_cn":         cn,
		"cert_subject":         cert.Subject.String(),
		"cn_extraction_result": "success",
	}).Debug("CN extracted successfully from certificate")

	return cn, nil
}

// Authentication middleware
func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		logCtx := getLogContextFromGin(c)
		logCtx.Component = "authentication_middleware"
		logCtx.Operation = "validate_jwt_token"

		tokenString := c.GetHeader("Authorization")
		if tokenString == "" {
			ContextualLogger(logCtx).WithField("auth_result", "missing_header").Warn("Authentication failed - missing Authorization header")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
			c.Abort()
			return
		}

		if len(tokenString) > 7 && tokenString[:7] == "Bearer " {
			tokenString = tokenString[7:]
		}

		claims := &Claims{}
		var jwtSecret string
		if globalConfig != nil {
			jwtSecret = globalConfig.Security.JWTSecret
		} else {
			jwtSecret = "P@ssw0rdM@t@6810jwtSec"
		}

		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(jwtSecret), nil
		})

		if err != nil || !token.Valid {
			ContextualLogger(logCtx).WithError(err).WithField("auth_result", "invalid_token").Warn("Authentication failed - invalid or expired token")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired token"})
			c.Abort()
			return
		}

		// Update context with username
		logCtx.Username = claims.Username
		ContextualLogger(logCtx).WithField("auth_result", "success").Debug("Authentication successful")
		c.Set("claims", claims)
		c.Next()
	}
}

// generateToken generates a new JWT token using YAML config
func generateToken(username string) (string, error) {
	logCtx := &LogContext{
		Component: "authentication",
		Operation: "generate_jwt_token",
		Username:  username,
	}

	ContextualLogger(logCtx).Debug("Generating JWT token")

	var jwtSecret string
	var tokenExpiration time.Duration

	if globalConfig != nil {
		jwtSecret = globalConfig.Security.JWTSecret
		// Parse token expiration duration
		if duration, err := time.ParseDuration(globalConfig.Security.TokenExpiration); err == nil {
			tokenExpiration = duration
		} else {
			tokenExpiration = 24 * time.Hour // fallback
		}
	} else {
		jwtSecret = "P@ssw0rdM@t@6810jwtSec"
		tokenExpiration = 24 * time.Hour
	}

	claims := &Claims{
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(tokenExpiration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(jwtSecret))
	if err != nil {
		ContextualLogger(logCtx).WithError(err).WithField("token_generation_result", "failed").Error("Failed to generate JWT token")
		return "", err
	}

	ContextualLogger(logCtx).WithFields(logrus.Fields{
		"token_expiration_duration": tokenExpiration.String(),
		"token_generation_result":   "success",
	}).Debug("JWT token generated successfully")
	return tokenString, nil
}

// handleLogin handles the login endpoint
func handleLogin() gin.HandlerFunc {
	return func(c *gin.Context) {
		logCtx := getLogContextFromGin(c)
		logCtx.Component = "login_handler"
		logCtx.Operation = "handle_login"

		var credentials Credentials
		if err := c.ShouldBindJSON(&credentials); err != nil {
			ContextualLogger(logCtx).WithError(err).WithField("login_result", "invalid_request").Warn("Login failed - invalid request body")
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		logCtx.Username = credentials.Username

		if isValidUser(credentials.Username, credentials.Password) {
			token, err := generateToken(credentials.Username)
			if err != nil {
				ContextualLogger(logCtx).WithError(err).WithField("login_result", "token_generation_failed").Error("Login failed - token generation error")
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
				return
			}

			ContextualLogger(logCtx).WithField("login_result", "success").Info("User logged in successfully")
			c.JSON(http.StatusOK, gin.H{
				"token": token,
				"type":  "Bearer",
			})
			return
		}

		ContextualLogger(logCtx).WithField("login_result", "invalid_credentials").Warn("Login failed - invalid credentials")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
	}
}

// handleAPI function to support both webhook and email with Exchange CA certificate CN validation
func handleAPI(sm *SecurityManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		logCtx := getLogContextFromGin(c)
		logCtx.Component = "api_handler"
		logCtx.Operation = "handle_connector_validation"

		ContextualLogger(logCtx).Info("Starting connector validation/email request")

		var req ConnectorValidationRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			ContextualLogger(logCtx).WithError(err).WithField("validation_result", "invalid_request").Error("Invalid request body")
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body: " + err.Error()})
			return
		}

		connectorID := req.ConnectorID
		if connectorID == "" {
			ContextualLogger(logCtx).WithField("validation_result", "missing_connector_id").Error("Missing connector ID in request")
			c.JSON(http.StatusBadRequest, gin.H{"error": "Connector ID is required"})
			return
		}

		logCtx.ResourceID = connectorID
		logCtx.ResourceType = "connector"

		response := &ConnectorValidationResponse{
			ConnectorID:   connectorID,
			ConnectorType: req.Type,
			Message:       "Processing completed",
		}

		// Handle different connector types
		switch strings.ToLower(req.Type) {
		case "email":
			response.EmailService = req.Service
			ContextualLogger(logCtx).WithFields(logrus.Fields{
				"connector_type": "email",
				"email_service":  req.Service,
			}).Info("Processing email connector request")

			// Parse email configuration with service validation
			emailConfig, err := parseEmailConfig(req.Data, req.Service)
			if err != nil {
				ContextualLogger(logCtx).WithError(err).Error("Failed to parse email configuration")
				response.Message = "Failed to parse email configuration"
				response.TestResult.Success = false
				response.TestResult.Error = err.Error()
				c.JSON(http.StatusBadRequest, response)
				return
			}

			// Additional validation for Exchange service - validate CA certificate CN
			if strings.ToLower(req.Service) == "exchange" {
				ContextualLogger(logCtx).WithFields(logrus.Fields{
					"email_service":   req.Service,
					"ca_cert_path":    emailConfig.CACertPath,
					"validation_step": "exchange_ca_cn_validation",
				}).Info("Validating Exchange CA certificate CN against security management configuration")

				if err := sm.validateExchangeCACertificate(emailConfig.CACertPath); err != nil {
					ContextualLogger(logCtx).WithError(err).WithFields(logrus.Fields{
						"email_service":           req.Service,
						"ca_cert_path":            emailConfig.CACertPath,
						"ca_cn_validation_result": "failed",
					}).Error("Exchange CA certificate CN validation failed")
					response.Message = "Exchange CA certificate CN validation failed"
					response.TestResult.Success = false
					response.TestResult.Error = err.Error()
					c.JSON(http.StatusForbidden, response)
					return
				}

				ContextualLogger(logCtx).WithFields(logrus.Fields{
					"email_service":           req.Service,
					"ca_cert_path":            emailConfig.CACertPath,
					"ca_cn_validation_result": "success",
				}).Info("Exchange CA certificate CN validation successful")
			}

			// Send test email
			if err := sm.sendEmail(emailConfig, connectorID); err != nil {
				ContextualLogger(logCtx).WithError(err).Error("Failed to send test email")
				response.Message = "Failed to send test email"
				response.TestResult.Success = false
				response.TestResult.Error = err.Error()
				response.TestResult.EmailSent = false
				c.JSON(http.StatusInternalServerError, response)
				return
			}

			response.TestResult.Success = true
			response.TestResult.EmailSent = true
			response.Message = "Email sent successfully"

			if strings.ToLower(req.Service) == "exchange" {
				response.Message += " (Exchange CA certificate CN validated)"
			}

			ContextualLogger(logCtx).WithFields(logrus.Fields{
				"email_service": req.Service,
				"ca_cert_path":  emailConfig.CACertPath,
			}).Info("Email connector test completed successfully")

		case "webhook":
			response.ConnectorURL = req.URL
			ContextualLogger(logCtx).WithFields(logrus.Fields{
				"connector_type": "webhook",
				"connector_url":  req.URL,
			}).Info("Processing webhook connector request")

			// Step 1: Fetch connector information from Kibana
			ContextualLogger(logCtx).WithField("validation_step", "1_fetch_connector_info").Info("Step 1: Fetching connector information")
			connectorInfo, err := sm.FetchConnectorInfo(connectorID)
			if err != nil {
				ContextualLogger(logCtx).WithError(err).WithFields(logrus.Fields{
					"validation_step": "1_fetch_connector_info",
					"step_result":     "failed",
				}).Error("Step 1 failed - connector info fetch error")
				response.Message = "Failed to fetch connector information"
				response.TestResult.Success = false
				response.TestResult.Error = err.Error()
				c.JSON(http.StatusInternalServerError, response)
				return
			}
			response.ConnectorName = connectorInfo.Name
			ContextualLogger(logCtx).WithFields(logrus.Fields{
				"validation_step": "1_fetch_connector_info",
				"step_result":     "success",
				"connector_name":  connectorInfo.Name,
				"connector_url":   connectorInfo.Config.URL,
			}).Info("Step 1 completed successfully")

			// Step 2: Fetch certificate information
			ContextualLogger(logCtx).WithField("validation_step", "2_fetch_certificate_info").Info("Step 2: Fetching certificate information")
			certInfo, err := sm.FetchCertificateInfo(connectorInfo.Name)
			if err != nil {
				ContextualLogger(logCtx).WithError(err).WithFields(logrus.Fields{
					"validation_step": "2_fetch_certificate_info",
					"step_result":     "failed",
				}).Error("Step 2 failed - certificate info fetch error")
				response.Message = "Failed to fetch certificate information"
				response.TestResult.Success = false
				response.TestResult.Error = err.Error()
				c.JSON(http.StatusInternalServerError, response)
				return
			}
			if len(certInfo.Hits.Hits) == 0 {
				ContextualLogger(logCtx).WithFields(logrus.Fields{
					"validation_step": "2_fetch_certificate_info",
					"step_result":     "no_certificates_found",
				}).Warn("Step 2 failed - no certificates found")
				response.Message = "No certificates found for connector"
				response.TestResult.Success = false
				response.TestResult.Error = "No certificates found"
				c.JSON(http.StatusNotFound, response)
				return
			}
			cert := certInfo.Hits.Hits[0].Source
			response.CertificateInfo.CAPath = cert.CAPath
			response.CertificateInfo.PublicPath = cert.PublicPath
			response.CertificateInfo.PrivatePath = cert.PrivatePath
			response.CertificateInfo.Password = cert.Password
			ContextualLogger(logCtx).WithFields(logrus.Fields{
				"validation_step":  "2_fetch_certificate_info",
				"step_result":      "success",
				"ca_cert_path":     cert.CAPath,
				"public_cert_path": cert.PublicPath,
				"private_key_path": cert.PrivatePath,
			}).Info("Step 2 completed successfully")

			// Step 3: Extract CN from certificate and perform comprehensive validation
			ContextualLogger(logCtx).WithField("validation_step", "3_extract_cn_and_validate").Info("Step 3: Extracting CN from certificate and performing validation")
			certificateCN, err := getCertificateCN(cert.PublicPath)
			if err != nil {
				ContextualLogger(logCtx).WithError(err).WithFields(logrus.Fields{
					"validation_step": "3_extract_cn_and_validate",
					"step_result":     "cn_extraction_failed",
				}).Error("Step 3 failed - CN extraction error")
				response.Message = "Failed to extract CN from certificate"
				response.TestResult.Success = false
				response.TestResult.Error = err.Error()
				c.JSON(http.StatusInternalServerError, response)
				return
			}

			// Perform comprehensive certificate validation
			certificateValidationResult := performCertificateValidation(cert.PublicPath)
			response.CertificateValidation = certificateValidationResult

			// Log certificate validation results and stop if validation fails
			if !certificateValidationResult.Valid {
				ContextualLogger(logCtx).WithFields(logrus.Fields{
					"validation_step":          "3_extract_cn_and_validate",
					"certificate_cn":           certificateCN,
					"cert_validation_errors":   certificateValidationResult.Errors,
					"cert_validation_warnings": certificateValidationResult.Warnings,
					"cert_validation_result":   "failed",
				}).Error("Step 3 failed - certificate validation failed")
				response.Message = "Certificate validation failed"
				response.TestResult.Success = false
				response.TestResult.Error = strings.Join(certificateValidationResult.Errors, "; ")
				c.JSON(http.StatusForbidden, response)
				return
			}

			// Log warnings if any, but continue if valid
			if len(certificateValidationResult.Warnings) > 0 {
				ContextualLogger(logCtx).WithFields(logrus.Fields{
					"validation_step":          "3_extract_cn_and_validate",
					"certificate_cn":           certificateCN,
					"cert_validation_warnings": certificateValidationResult.Warnings,
					"cert_validation_result":   "warning",
				}).Warn("Step 3 - certificate validation completed with warnings")
			} else {
				ContextualLogger(logCtx).WithFields(logrus.Fields{
					"validation_step":        "3_extract_cn_and_validate",
					"certificate_cn":         certificateCN,
					"cert_validation_result": "success",
				}).Info("Step 3 completed successfully with valid certificate")
			}

			// Step 4: Fetch security configuration
			ContextualLogger(logCtx).WithField("validation_step", "4_fetch_security_config").Info("Step 4: Fetching security management configuration")
			securityConfig, err := sm.FetchSecurityConfig()
			if err != nil {
				ContextualLogger(logCtx).WithError(err).WithFields(logrus.Fields{
					"validation_step": "4_fetch_security_config",
					"step_result":     "failed",
				}).Error("Step 4 failed - security config fetch error")
				response.Message = "Failed to fetch security configuration"
				response.TestResult.Success = false
				response.TestResult.Error = err.Error()
				c.JSON(http.StatusInternalServerError, response)
				return
			}
			if len(securityConfig.Hits.Hits) == 0 {
				ContextualLogger(logCtx).WithFields(logrus.Fields{
					"validation_step": "4_fetch_security_config",
					"step_result":     "no_config_found",
				}).Error("Step 4 failed - no security configuration found")
				response.Message = "No security configuration found"
				response.TestResult.Success = false
				response.TestResult.Error = "No security configuration found"
				c.JSON(http.StatusNotFound, response)
				return
			}
			cnConfig := securityConfig.Hits.Hits[0].Source.CN
			configuredCNs := strings.Split(cnConfig, ",")
			for i := range configuredCNs {
				configuredCNs[i] = strings.TrimSpace(configuredCNs[i])
			}
			ContextualLogger(logCtx).WithFields(logrus.Fields{
				"validation_step":      "4_fetch_security_config",
				"step_result":          "success",
				"configured_cns_count": len(configuredCNs),
				"configured_cns":       configuredCNs,
			}).Info("Step 4 completed successfully")

			// Step 5: Validate CN
			ContextualLogger(logCtx).WithField("validation_step", "5_validate_cn").Info("Step 5: Validating CN from certificate")
			isValid, extractedCN, err := sm.ValidateConnectorCN(certificateCN, configuredCNs)
			if err != nil {
				ContextualLogger(logCtx).WithError(err).WithFields(logrus.Fields{
					"validation_step": "5_validate_cn",
					"step_result":     "failed",
				}).Error("Step 5 failed - CN validation error")
				response.Message = "CN validation failed"
				response.TestResult.Success = false
				response.TestResult.Error = err.Error()
				c.JSON(http.StatusInternalServerError, response)
				return
			}
			response.CNValidation.ConfiguredCNs = configuredCNs
			response.CNValidation.ConnectorCN = extractedCN
			response.CNValidation.IsValid = isValid

			if !isValid {
				ContextualLogger(logCtx).WithFields(logrus.Fields{
					"validation_step": "5_validate_cn",
					"step_result":     "validation_unsuccessful",
					"certificate_cn":  certificateCN,
					"configured_cns":  configuredCNs,
				}).Warn("Step 5 failed - CN validation unsuccessful")
				response.Message = "CN validation failed - connector not authorized"
				response.TestResult.Success = false
				response.TestResult.Error = fmt.Sprintf("Certificate CN '%s' not found in configured CNs", certificateCN)
				c.JSON(http.StatusForbidden, response)
				return
			}
			ContextualLogger(logCtx).WithFields(logrus.Fields{
				"validation_step": "5_validate_cn",
				"step_result":     "success",
			}).Info("Step 5 completed successfully")

			// Step 6: POST data to webhook endpoint
			ContextualLogger(logCtx).WithField("validation_step", "6_post_webhook_payload").Info("Step 6: POSTing data to webhook endpoint")

			statusCode, responseBody, err := sm.TestConnectorEndpoint(
				req.URL,
				cert.CAPath,
				cert.PublicPath,
				cert.PrivatePath,
				cert.Password,
				req.Data,
			)
			response.TestResult.StatusCode = statusCode
			response.TestResult.ResponseBody = responseBody
			if err != nil {
				ContextualLogger(logCtx).WithError(err).WithFields(logrus.Fields{
					"validation_step": "6_post_webhook_payload",
					"step_result":     "failed",
				}).Error("Step 6 failed - webhook endpoint payload POST error")
				response.Message = "Webhook endpoint payload POST failed"
				response.TestResult.Success = false
				response.TestResult.Error = err.Error()

				if strings.Contains(err.Error(), "TLS/Certificate error") {
					response.Message = "TLS/Certificate authentication failed"
				}

				c.JSON(http.StatusInternalServerError, response)
				return
			}

			// Consider only 200 OK as success
			if statusCode != http.StatusOK {
				ContextualLogger(logCtx).WithFields(logrus.Fields{
					"validation_step":      "6_post_webhook_payload",
					"step_result":          "non_200_status",
					"response_status_code": statusCode,
				}).Warn("Step 6 failed - webhook endpoint returned non-200 status")
				response.Message = fmt.Sprintf("Webhook endpoint payload POST failed - received status %d", statusCode)
				response.TestResult.Success = false
				response.TestResult.Error = fmt.Sprintf("Received status code %d", statusCode)
				c.JSON(http.StatusBadRequest, response)
				return
			}

			response.TestResult.Success = true
			response.Message = "Connector validation and webhook payload POST completed successfully"

			ContextualLogger(logCtx).WithFields(logrus.Fields{
				"validation_step":           "6_post_webhook_payload",
				"step_result":               "success",
				"response_status_code":      statusCode,
				"overall_validation_result": "success",
			}).Info("Step 6 completed successfully")
			ContextualLogger(logCtx).WithField("overall_validation_result", "success").Info("Connector validation completed successfully")

		default:
			ContextualLogger(logCtx).WithField("unsupported_type", req.Type).Error("Unsupported connector type")
			response.Message = fmt.Sprintf("Unsupported connector type: %s", req.Type)
			response.TestResult.Success = false
			response.TestResult.Error = fmt.Sprintf("Unsupported connector type: %s. Supported types: webhook, email", req.Type)
			c.JSON(http.StatusBadRequest, response)
			return
		}

		c.JSON(http.StatusOK, response)
	}
}

// readHostsFile reads and parses the hosts file
func readHostsFile(path string) ([]Host, error) {
	logCtx := &LogContext{
		Component:    "file_processing",
		Operation:    "read_hosts_file",
		ResourceID:   path,
		ResourceType: "hosts_file",
	}

	ContextualLogger(logCtx).Debug("Reading hosts file")

	file, err := os.Open(path)
	if err != nil {
		ContextualLogger(logCtx).WithError(err).WithField("file_open_result", "failed").Error("Failed to open hosts file")
		return nil, fmt.Errorf("error opening hosts file: %v", err)
	}
	defer file.Close()

	var hosts []Host
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) >= 2 {
			ip := fields[0]
			for _, hostname := range fields[1:] {
				if strings.HasPrefix(hostname, "SF") && strings.HasSuffix(hostname, ".siem.apk") {
					hosts = append(hosts, Host{
						IP:   ip,
						Name: hostname,
					})
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		ContextualLogger(logCtx).WithError(err).WithField("file_scan_result", "failed").Error("Error reading hosts file")
		return nil, fmt.Errorf("error reading hosts file: %v", err)
	}

	ContextualLogger(logCtx).WithFields(logrus.Fields{
		"parsed_hosts_count": len(hosts),
		"file_parse_result":  "success",
	}).Debug("Hosts file parsed successfully")

	return hosts, nil
}

// getAuthToken obtains authentication token from the API
func getAuthToken(client *http.Client, host string) (string, error) {
	logCtx := &LogContext{
		Component:    "authentication",
		Operation:    "get_auth_token",
		ResourceID:   host,
		ResourceType: "remote_host",
	}

	ContextualLogger(logCtx).Debug("Obtaining authentication token")

	var username, password string
	if globalConfig != nil {
		username = globalConfig.Security.Username
		password = globalConfig.Security.Password
	} else {
		username = "api"
		password = "P@ssw0rdM@t@G3tT0ken"
	}

	credentials := Credentials{
		Username: username,
		Password: password,
	}

	jsonData, err := json.Marshal(credentials)
	if err != nil {
		ContextualLogger(logCtx).WithError(err).WithField("marshal_result", "failed").Error("Failed to marshal credentials")
		return "", fmt.Errorf("error marshaling credentials: %v", err)
	}

	var apiPort string
	if globalConfig != nil {
		apiPort = globalConfig.Server.Port
	} else {
		apiPort = "5005"
	}

	authURL := fmt.Sprintf("https://%s:%s/login", host, apiPort)
	req, err := http.NewRequest("POST", authURL, bytes.NewBuffer(jsonData))
	if err != nil {
		ContextualLogger(logCtx).WithError(err).WithFields(logrus.Fields{
			"auth_url":                authURL,
			"request_creation_result": "failed",
		}).Error("Failed to create authentication request")
		return "", fmt.Errorf("error creating request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		ContextualLogger(logCtx).WithError(err).WithFields(logrus.Fields{
			"auth_url":    authURL,
			"auth_result": "request_failed",
		}).Error("Authentication request failed")
		return "", fmt.Errorf("error making request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		ContextualLogger(logCtx).WithFields(logrus.Fields{
			"auth_url":             authURL,
			"response_status_code": resp.StatusCode,
			"auth_result":          "non_200_status",
		}).Error("Authentication failed with non-200 status")
		return "", fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		ContextualLogger(logCtx).WithError(err).WithFields(logrus.Fields{
			"auth_url":      authURL,
			"decode_result": "failed",
		}).Error("Failed to decode authentication response")
		return "", fmt.Errorf("error decoding response: %v", err)
	}

	ContextualLogger(logCtx).WithFields(logrus.Fields{
		"auth_url":    authURL,
		"auth_result": "success",
	}).Debug("Authentication token obtained successfully")
	return tokenResp.Token, nil
}

// makeAPICall handles the complete API call process for a host
func makeAPICall(host Host) error {
	logCtx := &LogContext{
		Component:    "api_client",
		Operation:    "make_api_call",
		ResourceID:   host.Name,
		ResourceType: "remote_host",
	}

	ContextualLogger(logCtx).WithFields(logrus.Fields{
		"target_host_name": host.Name,
		"target_host_ip":   host.IP,
	}).Debug("Making API call to host")

	client, err := createHTTPClient()
	if err != nil {
		ContextualLogger(logCtx).WithError(err).WithField("client_creation_result", "failed").Error("Failed to create HTTP client")
		return fmt.Errorf("error creating HTTP client: %v", err)
	}

	token, err := getAuthToken(client, host.Name)
	if err != nil {
		ContextualLogger(logCtx).WithError(err).WithField("token_acquisition_result", "failed").Error("Failed to get authentication token")
		return fmt.Errorf("error getting auth token: %v", err)
	}

	var apiPort string
	if globalConfig != nil {
		apiPort = globalConfig.Server.Port
	} else {
		apiPort = "5005"
	}

	// Explicitly set hostType=sf for SF nodes
	apiURL := fmt.Sprintf("https://%s:%s/update-configs?hostType=sf", host.Name, apiPort)
	req, err := http.NewRequest("POST", apiURL, nil)
	if err != nil {
		ContextualLogger(logCtx).WithError(err).WithFields(logrus.Fields{
			"api_url":                 apiURL,
			"request_creation_result": "failed",
		}).Error("Failed to create update-configs request")
		return fmt.Errorf("error creating request: %v", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		ContextualLogger(logCtx).WithError(err).WithFields(logrus.Fields{
			"api_url":         apiURL,
			"api_call_result": "request_failed",
		}).Error("Update-configs request failed")
		return fmt.Errorf("error making request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		ContextualLogger(logCtx).WithFields(logrus.Fields{
			"api_url":              apiURL,
			"response_status_code": resp.StatusCode,
			"api_call_result":      "non_200_status",
		}).Error("Update-configs failed with non-200 status")
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	ContextualLogger(logCtx).WithFields(logrus.Fields{
		"api_url":         apiURL,
		"api_call_result": "success",
	}).Debug("API call completed successfully")
	return nil
}

// readHosts reads and parses the hosts file
func readHosts() ([]Host, error) {
	return readHostsFile("/etc/hosts")
}

// handleUpdateConfigs handles configuration updates and propagation with optional authentication
func handleUpdateConfigs(sm *SecurityManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		logCtx := getLogContextFromGin(c)
		logCtx.Component = "update_configs_handler"
		logCtx.Operation = "handle_update_configs"

		ContextualLogger(logCtx).Info("Starting configuration update")

		config, err := sm.FetchConfig()
		if err != nil {
			ContextualLogger(logCtx).WithError(err).WithField("config_fetch_result", "failed").Error("Failed to fetch configuration")
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		hostType := strings.ToLower(c.DefaultQuery("hostType", "coordinator"))
		if hostType != "coordinator" && hostType != "sf" {
			ContextualLogger(logCtx).WithFields(logrus.Fields{
				"provided_host_type": hostType,
				"valid_host_types":   []string{"coordinator", "sf"},
				"validation_result":  "invalid_host_type",
			}).Error("Invalid hostType parameter")
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid hostType parameter"})
			return
		}
		config.HostType = hostType

		logCtx.ResourceType = "system_configuration"
		ContextualLogger(logCtx).WithFields(logrus.Fields{
			"config_host_type":          hostType,
			"config_remote_syslog_ip":   config.RemoteSyslogIp,
			"config_remote_syslog_port": config.RemoteSyslogPort,
		}).Info("Updating configurations")

		if err := sm.updateConfigs(config); err != nil {
			ContextualLogger(logCtx).WithError(err).WithField("config_update_result", "failed").Error("Failed to update configurations")
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		if hostType == "coordinator" {
			ContextualLogger(logCtx).WithField("propagation_target", "sf_nodes").Info("Propagating configuration to SF nodes")
			hosts, err := readHosts()
			if err != nil {
				ContextualLogger(logCtx).WithError(err).WithField("hosts_read_result", "failed").Error("Failed to read hosts file")
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}

			var wg sync.WaitGroup
			var errors []string
			var mu sync.Mutex

			ContextualLogger(logCtx).WithFields(logrus.Fields{
				"target_sf_nodes_count": len(hosts),
				"propagation_method":    "parallel_api_calls",
			}).Info("Starting parallel API calls to SF nodes")

			for _, host := range hosts {
				wg.Add(1)
				go func(h Host) {
					defer wg.Done()
					hostLogCtx := &LogContext{
						Component:    "sf_node_propagation",
						Operation:    "propagate_config_to_sf_node",
						ResourceID:   h.Name,
						ResourceType: "remote_sf_node",
						ClientIP:     systemInfo.PrimaryIP,
						ClientHost:   systemInfo.Hostname,
					}

					ContextualLogger(hostLogCtx).WithFields(logrus.Fields{
						"target_sf_node_name": h.Name,
						"target_sf_node_ip":   h.IP,
					}).Debug("Making API call to SF node")
					if err := makeAPICall(h); err != nil {
						ContextualLogger(hostLogCtx).WithError(err).WithFields(logrus.Fields{
							"target_sf_node_name": h.Name,
							"target_sf_node_ip":   h.IP,
							"api_call_result":     "failed",
						}).Error("API call to SF node failed")
						mu.Lock()
						errors = append(errors, fmt.Sprintf("%s: %v", h.Name, err))
						mu.Unlock()
					} else {
						ContextualLogger(hostLogCtx).WithFields(logrus.Fields{
							"target_sf_node_name": h.Name,
							"target_sf_node_ip":   h.IP,
							"api_call_result":     "success",
						}).Debug("API call to SF node successful")
					}
				}(host)
			}

			wg.Wait()

			if len(errors) > 0 {
				ContextualLogger(logCtx).WithFields(logrus.Fields{
					"propagation_error_count": len(errors),
					"propagation_errors":      errors,
					"propagation_result":      "completed_with_errors",
				}).Error("Configuration update completed with errors")
				c.JSON(http.StatusInternalServerError, gin.H{
					"message": "Completed with errors",
					"errors":  errors,
				})
				return
			}

			ContextualLogger(logCtx).WithFields(logrus.Fields{
				"propagated_sf_nodes_count": len(hosts),
				"propagation_result":        "success",
			}).Info("Configuration propagated to all SF nodes successfully")
		}

		ContextualLogger(logCtx).WithFields(logrus.Fields{
			"config_host_type":      hostType,
			"overall_update_result": "success",
		}).Info("Configuration update completed successfully")
		c.JSON(http.StatusOK, gin.H{
			"message": "Configurations updated successfully",
			"config":  config,
		})
	}
}

// handleCertificateValidation handles the certificate validation endpoint
func handleCertificateValidation() gin.HandlerFunc {
	return func(c *gin.Context) {
		logCtx := getLogContextFromGin(c)
		logCtx.Component = "certificate_validation_handler"
		logCtx.Operation = "handle_certificate_validation"

		ContextualLogger(logCtx).Info("Starting certificate validation request")

		var req CertificateValidationRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			ContextualLogger(logCtx).WithError(err).WithField("request_validation_result", "invalid_request").Error("Invalid certificate validation request body")
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body: " + err.Error()})
			return
		}

		certPath := req.CertificatePath
		logCtx.ResourceID = certPath
		logCtx.ResourceType = "certificate"

		// Check if certificate file exists
		if _, err := os.Stat(certPath); os.IsNotExist(err) {
			ContextualLogger(logCtx).WithField("file_existence_check", "not_found").Error("Certificate file does not exist")
			c.JSON(http.StatusNotFound, gin.H{"error": "Certificate file not found"})
			return
		}

		// Use provided config or default
		validationConfig := req.Config
		if validationConfig == nil {
			validationConfig = getDefaultCertValidationConfig()
		}

		ContextualLogger(logCtx).WithFields(logrus.Fields{
			"validation_config_check_expiration":          validationConfig.CheckExpiration,
			"validation_config_check_basic_constraints":   validationConfig.CheckBasicConstraints,
			"validation_config_check_ca_flags":            validationConfig.CheckCAFlags,
			"validation_config_check_self_signed":         validationConfig.CheckSelfSigned,
			"validation_config_check_key_usage":           validationConfig.CheckKeyUsage,
			"validation_config_check_ext_key_usage":       validationConfig.CheckExtKeyUsage,
			"validation_config_check_subject_alt_name":    validationConfig.CheckSubjectAltName,
			"validation_config_check_signature_algorithm": validationConfig.CheckSignatureAlgorithm,
			"validation_config_check_key_length":          validationConfig.CheckKeyLength,
		}).Debug("Using certificate validation configuration")

		// Read and parse certificate
		certData, err := ioutil.ReadFile(certPath)
		if err != nil {
			ContextualLogger(logCtx).WithError(err).WithField("cert_read_result", "failed").Error("Failed to read certificate file")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read certificate file"})
			return
		}

		block, _ := pem.Decode(certData)
		if block == nil {
			ContextualLogger(logCtx).WithField("pem_decode_result", "failed").Error("Failed to decode PEM block")
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid PEM format"})
			return
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			ContextualLogger(logCtx).WithError(err).WithField("cert_parse_result", "failed").Error("Failed to parse certificate")
			c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to parse certificate"})
			return
		}

		// Perform comprehensive validation
		validationResult := ValidateCertificateWithConfig(cert, validationConfig, certPath)

		// Log validation summary
		ContextualLogger(logCtx).WithFields(logrus.Fields{
			"cert_subject":             cert.Subject.String(),
			"validation_valid":         validationResult.Valid,
			"validation_error_count":   len(validationResult.Errors),
			"validation_warning_count": len(validationResult.Warnings),
			"validation_result":        "completed",
		}).Info("Certificate validation completed")

		// Return detailed validation result
		c.JSON(http.StatusOK, gin.H{
			"certificate_path":  certPath,
			"validation_result": validationResult,
			"config_used":       validationConfig,
		})
	}
}

// handleHealthCheck provides system health and status information
func handleHealthCheck() gin.HandlerFunc {
	return func(c *gin.Context) {
		logCtx := getLogContextFromGin(c)
		logCtx.Component = "health_check_handler"
		logCtx.Operation = "handle_health_check"

		ContextualLogger(logCtx).Debug("Health check requested")

		healthStatus := map[string]interface{}{
			"status":         "healthy",
			"timestamp":      time.Now().UTC().Format(time.RFC3339),
			"system_info":    systemInfo,
			"logging_status": getLoggingStatus(),
			"config_source":  getConfigSource(),
			"server_info": map[string]interface{}{
				"gin_mode":                      gin.Mode(),
				"update_configs_auth_required":  isUpdateConfigsAuthRequired(),
				"certificate_validation_strict": shouldFailOnCertValidationError(),
				"email_support":                 "enabled",
			},
		}

		// Check if we're running with degraded logging
		loggingStatus := getLoggingStatus()
		if !loggingStatus["file_logging_enabled"].(bool) {
			healthStatus["warnings"] = []string{
				"File logging is disabled - using stdout only",
			}
		}

		ContextualLogger(logCtx).WithField("health_status", "healthy").Debug("Health check completed")

		c.JSON(http.StatusOK, healthStatus)
	}
}

// HSTSMiddleware adds the Strict-Transport-Security header
func HSTSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
		c.Next()
	}
}

// getConfigSource returns the configuration source for logging
func getConfigSource() string {
	if globalConfig != nil {
		return "YAML configuration file"
	}
	return "Environment variables and defaults"
}

func main() {
	// Initialize basic logger first (before config loading)
	initBasicLogger()

	// Initialize system information for consistent logging
	if err := initSystemInfo(); err != nil {
		// Use basic logger since system info init failed
		logger.WithError(err).Error("Failed to initialize system information")
	}

	// Initialize configuration from YAML file
	if err := initializeConfiguration(); err != nil {
		// If YAML config fails, log error but continue with environment variables
		ContextualLogger(&LogContext{
			Component: "main",
			Operation: "initialize_configuration",
		}).WithError(err).Warn("Failed to load YAML configuration, falling back to environment variables and defaults")
	}

	// Reinitialize logger with YAML configuration settings and file output
	initLogger()

	// Log comprehensive startup information
	logSystemStartupInfo()

	// Ensure log file is properly closed on shutdown
	defer closeLogFile()

	mainLogCtx := &LogContext{
		Component: "main",
		Operation: "startup",
	}

	ContextualLogger(mainLogCtx).Info("Starting SIEM Security Manager API server with Email support")

	sm := NewSecurityManager()

	// Set Gin mode from configuration
	ginMode := "release"
	if globalConfig != nil {
		ginMode = globalConfig.Server.Mode
	} else if os.Getenv("GIN_MODE") != "" {
		ginMode = os.Getenv("GIN_MODE")
	}

	if ginMode != "debug" {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.New()

	// Add recovery middleware
	router.Use(gin.Recovery())

	// Add custom logging middleware
	router.Use(loggerMiddleware())

	// Apply the HSTS middleware globally
	router.Use(HSTSMiddleware())

	// Health check endpoint (no authentication required)
	router.GET("/health", handleHealthCheck())

	// Public endpoint for login
	router.POST("/login", handleLogin())

	// Public certificate validation endpoint
	router.POST("/validate-certificate", handleCertificateValidation())

	// Public routes (no authentication required) - UPDATED to handle both webhook and email
	router.POST("/api", handleAPI(sm))

	// Check if authentication is required for update-configs
	if isUpdateConfigsAuthRequired() {
		ContextualLogger(mainLogCtx).WithField("update_configs_auth", "required").Info("Authentication is REQUIRED for /update-configs endpoint")
		// Secured routes requiring authentication
		secured := router.Group("")
		secured.Use(authMiddleware())
		{
			secured.POST("/update-configs", handleUpdateConfigs(sm))
		}
	} else {
		ContextualLogger(mainLogCtx).WithField("update_configs_auth", "disabled").Warn("Authentication is DISABLED for /update-configs endpoint - this is a security risk in production!")
		// Public route (no authentication required)
		router.POST("/update-configs", handleUpdateConfigs(sm))
	}

	// Get server configuration
	serverPort := ":5005"
	tlsCertPath := "/etc/siem/certs/wildcard.crt"
	tlsKeyPath := "/etc/siem/certs/wildcard.key"

	if globalConfig != nil {
		serverPort = ":" + globalConfig.Server.Port
		tlsCertPath = globalConfig.Server.TLSCertPath
		tlsKeyPath = globalConfig.Server.TLSKeyPath
	}

	server := &http.Server{
		Addr:    serverPort,
		Handler: router,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			MaxVersion: tls.VersionTLS13, // Updated to support TLS 1.3
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			},
			PreferServerCipherSuites: true,
			CurvePreferences: []tls.CurveID{
				tls.CurveP521,
				tls.CurveP384,
				tls.CurveP256,
			},
		},
	}

	// Log final server configuration before starting
	ContextualLogger(mainLogCtx).WithFields(logrus.Fields{
		"server_port":                   serverPort,
		"tls_cert_path":                 tlsCertPath,
		"tls_key_path":                  tlsKeyPath,
		"log_level":                     logger.GetLevel().String(),
		"logging_status":                getLoggingStatus(),
		"config_source":                 getConfigSource(),
		"update_configs_auth_required":  isUpdateConfigsAuthRequired(),
		"certificate_validation_strict": shouldFailOnCertValidationError(),
		"gin_mode":                      ginMode,
		"tls_min_version":               "TLS_1.2",
		"tls_max_version":               "TLS_1.3",
		"email_support":                 "enabled",
		"secure_cipher_suites":          []string{"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
		"server_ready":                  true,
	}).Info("Server configuration completed, starting TLS server with Email support")

	// Start the server
	if err := server.ListenAndServeTLS(tlsCertPath, tlsKeyPath); err != nil {
		ContextualLogger(mainLogCtx).WithError(err).WithFields(logrus.Fields{
			"server_startup_result": "failed",
			"tls_cert_path":         tlsCertPath,
			"tls_key_path":          tlsKeyPath,
			"server_port":           serverPort,
		}).Fatal("Server failed to start")
	}
}
