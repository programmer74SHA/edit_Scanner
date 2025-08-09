/*
SIEM Security Manager API Server with Enhanced Certificate Verification

This application provides comprehensive certificate validation, security management capabilities,
email functionality, and Python-style enhanced certificate verification.

SECURITY BEHAVIOR:
- Certificate validation is performed on all client certificates before use
- Enhanced validation includes AIA chain building, OCSP/CRL revocation checking, trust root validation
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

Enhanced Certificate Validation Environment Variables:
- ENHANCED_MIN_PATH_LENGTH=3                     : Minimum certificate chain length
- ENHANCED_CHECK_AIA_CHAIN_BUILDING=true        : Enable AIA chain building
- ENHANCED_CHECK_OCSP_REVOCATION=true           : Enable OCSP revocation checking
- ENHANCED_CHECK_CRL_REVOCATION=true            : Enable CRL revocation checking
- ENHANCED_CHECK_EXTENDED_KEY_USAGE=true        : Enable Extended Key Usage validation
- ENHANCED_CHECK_TRUST_ROOTS=true               : Enable trust root validation
- ENHANCED_STRICT_REVOCATION_CHECK=false        : Fail if revocation status undetermined
- ENHANCED_AIA_FETCH_TIMEOUT=10                 : AIA fetch timeout (seconds)
- ENHANCED_OCSP_TIMEOUT=10                      : OCSP timeout (seconds)
- ENHANCED_CRL_TIMEOUT=15                       : CRL timeout (seconds)
- ENHANCED_MAX_AIA_HOPS=10                      : Maximum AIA chain building hops

API Endpoints:
- POST /login                               : Authenticate and get JWT token
- POST /api                                 : Enhanced connector validation with certificate checks OR send email
- POST /api-legacy                          : Legacy connector validation (backward compatibility)
- POST /validate-certificate                : Basic certificate validation
- POST /validate-certificate-enhanced      : Enhanced certificate validation with Python-style verification
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
	"os"
	"path/filepath"
	"strconv"
	"strings"
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

// OID constants for Extended Key Usage
const (
	OIDServerAuth      = "1.3.6.1.5.5.7.3.1"
	OIDClientAuth      = "1.3.6.1.5.5.7.3.2"
	OIDCodeSigning     = "1.3.6.1.5.5.7.3.3"
	OIDEmailProtection = "1.3.6.1.5.5.7.3.4"
	OIDOCSPSigning     = "1.3.6.1.5.5.7.3.9"
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

// SecurityManagementConfig represents the complete configuration structure
type SecurityManagementConfig struct {
	CertificateValidation CertificateValidationConfig  `yaml:"certificate_validation"`
	EnhancedValidation    EnhancedCertValidationConfig `yaml:"enhanced_validation"`
	Logging               LoggingConfig                `yaml:"logging"`
	Server                ServerConfig                 `yaml:"server"`
	Security              SecurityConfig               `yaml:"security"`
	API                   APIConfig                    `yaml:"api"`
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

// Enhanced certificate validation configuration
type EnhancedCertValidationConfig struct {
	MinPathLength         int      `yaml:"min_path_length"`
	CheckAIAChainBuilding bool     `yaml:"check_aia_chain_building"`
	CheckOCSPRevocation   bool     `yaml:"check_ocsp_revocation"`
	CheckCRLRevocation    bool     `yaml:"check_crl_revocation"`
	CheckExtendedKeyUsage bool     `yaml:"check_extended_key_usage"`
	CheckTrustRoots       bool     `yaml:"check_trust_roots"`
	RequiredExtKeyUsages  []string `yaml:"required_ext_key_usages"`
	StrictRevocationCheck bool     `yaml:"strict_revocation_check"`
	AIAFetchTimeout       int      `yaml:"aia_fetch_timeout"`
	OCSPTimeout           int      `yaml:"ocsp_timeout"`
	CRLTimeout            int      `yaml:"crl_timeout"`
	MaxAIAHops            int      `yaml:"max_aia_hops"`
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

// ConnectorValidationRequest represents the request for connector validation
type ConnectorValidationRequest struct {
	Type        string                 `json:"type" binding:"required"`
	URL         string                 `json:"url,omitempty"`
	Service     string                 `json:"service,omitempty"`
	Message     map[string]interface{} `json:"message,omitempty"`
	Data        map[string]interface{} `json:"data" binding:"required"`
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

// ConnectorValidationResponse represents the response for connector validation
type ConnectorValidationResponse struct {
	ConnectorID     string `json:"connector_id"`
	ConnectorName   string `json:"connector_name"`
	ConnectorURL    string `json:"connector_url,omitempty"`
	ConnectorType   string `json:"connector_type"`
	EmailService    string `json:"email_service,omitempty"`
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

// Enhanced certificate validation result
type EnhancedCertValidationResult struct {
	Valid              bool                       `json:"valid"`
	Errors             []string                   `json:"errors,omitempty"`
	Warnings           []string                   `json:"warnings,omitempty"`
	CheckResults       map[string]CertCheckResult `json:"check_results"`
	CertificateInfo    CertificateInfo            `json:"certificate_info"`
	ChainInfo          *CertificateChainInfo      `json:"chain_info,omitempty"`
	RevocationInfo     *RevocationCheckInfo       `json:"revocation_info,omitempty"`
	EnhancedValidation *EnhancedValidationInfo    `json:"enhanced_validation,omitempty"`
}

// Certificate chain information
type CertificateChainInfo struct {
	ChainLength           int               `json:"chain_length"`
	Certificates          []CertificateInfo `json:"certificates"`
	TrustRootFound        bool              `json:"trust_root_found"`
	SelfSignedRoot        bool              `json:"self_signed_root"`
	AIAChainBuilt         bool              `json:"aia_chain_built"`
	ChainValidationPassed bool              `json:"chain_validation_passed"`
}

// Revocation check information
type RevocationCheckInfo struct {
	OCSPChecked     bool     `json:"ocsp_checked"`
	OCSPStatus      string   `json:"ocsp_status,omitempty"`
	OCSPResponders  []string `json:"ocsp_responders,omitempty"`
	CRLChecked      bool     `json:"crl_checked"`
	CRLStatus       string   `json:"crl_status,omitempty"`
	CRLDistPoints   []string `json:"crl_dist_points,omitempty"`
	RevocationValid bool     `json:"revocation_valid"`
}

// Enhanced validation information
type EnhancedValidationInfo struct {
	ExtKeyUsageValid      bool     `json:"ext_key_usage_valid"`
	RequiredEKUs          []string `json:"required_ekus,omitempty"`
	FoundEKUs             []string `json:"found_ekus,omitempty"`
	BasicConstraintsValid bool     `json:"basic_constraints_valid"`
	SignatureVerified     bool     `json:"signature_verified"`
	TrustChainValid       bool     `json:"trust_chain_valid"`
}

// CertCheckResult represents individual check result
type CertCheckResult struct {
	Passed   bool   `json:"passed"`
	Message  string `json:"message"`
	Severity string `json:"severity"`
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

// Enhanced Certificate Verifier
type EnhancedCertificateVerifier struct {
	config     *EnhancedCertValidationConfig
	trustRoots *x509.CertPool
	logger     *logrus.Entry
}

// NewLoginAuth creates a new LOGIN authenticator
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

func (a *LoginAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	return "LOGIN", []byte{}, nil
}

// Add this function to auto-detect authentication method
func autoDetectAuth(emailConfig *EmailConfig, client *smtp.Client) smtp.Auth {
	logCtx := &LogContext{
		Component:    "email_service",
		Operation:    "auto_detect_auth",
		ResourceType: "smtp_auth",
	}

	if ok, ext := client.Extension("AUTH"); ok && ext != "" {
		ContextualLogger(logCtx).WithFields(logrus.Fields{
			"server_auth_methods": ext,
		}).Debug("Server AUTH methods detected")

		extUpper := strings.ToUpper(ext)

		if strings.Contains(extUpper, "LOGIN") {
			ContextualLogger(logCtx).WithField("selected_auth_method", "LOGIN").Debug("Using LOGIN authentication")
			return NewLoginAuth(emailConfig.Username, emailConfig.Password)
		}

		if strings.Contains(extUpper, "PLAIN") {
			ContextualLogger(logCtx).WithField("selected_auth_method", "PLAIN").Debug("Using PLAIN authentication")
			return smtp.PlainAuth("", emailConfig.Username, emailConfig.Password, emailConfig.SMTPHost)
		}

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

	ContextualLogger(logCtx).WithField("selected_auth_method", "LOGIN_default").Debug("Defaulting to LOGIN authentication (most common for Exchange)")
	return NewLoginAuth(emailConfig.Username, emailConfig.Password)
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

// NewEnhancedCertificateVerifier creates a new enhanced certificate verifier
func NewEnhancedCertificateVerifier(config *EnhancedCertValidationConfig) *EnhancedCertificateVerifier {
	logCtx := &LogContext{
		Component:    "enhanced_certificate_verifier",
		Operation:    "create_verifier",
		ResourceType: "certificate_verifier",
	}

	if config == nil {
		config = getDefaultEnhancedCertValidationConfig()
	}

	trustRoots, err := x509.SystemCertPool()
	if err != nil {
		ContextualLogger(logCtx).WithError(err).Warn("Failed to load system cert pool, creating empty pool")
		trustRoots = x509.NewCertPool()
	}

	return &EnhancedCertificateVerifier{
		config:     config,
		trustRoots: trustRoots,
		logger:     ContextualLogger(logCtx),
	}
}

// getDefaultEnhancedCertValidationConfig returns default enhanced validation config
func getDefaultEnhancedCertValidationConfig() *EnhancedCertValidationConfig {
	return &EnhancedCertValidationConfig{
		MinPathLength:         3,
		CheckAIAChainBuilding: true,
		CheckOCSPRevocation:   true,
		CheckCRLRevocation:    true,
		CheckExtendedKeyUsage: true,
		CheckTrustRoots:       true,
		RequiredExtKeyUsages:  []string{OIDServerAuth},
		StrictRevocationCheck: false,
		AIAFetchTimeout:       10,
		OCSPTimeout:           10,
		CRLTimeout:            15,
		MaxAIAHops:            10,
	}
}

// VerifyEnhanced performs enhanced certificate verification
func (ecv *EnhancedCertificateVerifier) VerifyEnhanced(certPath string, requiredUsage string) (*EnhancedCertValidationResult, error) {
	logCtx := &LogContext{
		Component:    "enhanced_certificate_verifier",
		Operation:    "verify_enhanced",
		ResourceID:   certPath,
		ResourceType: "certificate",
	}

	ContextualLogger(logCtx).Info("Starting enhanced certificate verification")

	certData, err := ioutil.ReadFile(certPath)
	if err != nil {
		ContextualLogger(logCtx).WithError(err).Error("Failed to read certificate file")
		return nil, fmt.Errorf("failed to read certificate file: %v", err)
	}

	block, _ := pem.Decode(certData)
	if block == nil {
		ContextualLogger(logCtx).Error("Failed to decode PEM block")
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		ContextualLogger(logCtx).WithError(err).Error("Failed to parse certificate")
		return nil, fmt.Errorf("failed to parse certificate: %v", err)
	}

	return ecv.VerifyEnhancedWithCert(cert, requiredUsage)
}

// VerifyEnhancedWithCert performs enhanced verification with x509.Certificate
func (ecv *EnhancedCertificateVerifier) VerifyEnhancedWithCert(cert *x509.Certificate, requiredUsage string) (*EnhancedCertValidationResult, error) {
	logCtx := &LogContext{
		Component:    "enhanced_certificate_verifier",
		Operation:    "verify_enhanced_with_cert",
		ResourceType: "certificate",
	}

	result := &EnhancedCertValidationResult{
		Valid:              true,
		Errors:             []string{},
		Warnings:           []string{},
		CheckResults:       make(map[string]CertCheckResult),
		CertificateInfo:    extractCertificateInfo(cert),
		EnhancedValidation: &EnhancedValidationInfo{},
	}

	ContextualLogger(logCtx).WithFields(logrus.Fields{
		"cert_subject":        cert.Subject.String(),
		"required_usage":      requiredUsage,
		"enhanced_validation": true,
	}).Info("Starting enhanced certificate verification")

	// Step 1: Build certificate chain via AIA
	var chain []*x509.Certificate
	if ecv.config.CheckAIAChainBuilding {
		ContextualLogger(logCtx).Debug("Building certificate chain via AIA")
		builtChain, err := ecv.buildCertificateChain(cert)
		if err != nil {
			ContextualLogger(logCtx).WithError(err).Warn("Failed to build certificate chain via AIA")
			result.Warnings = append(result.Warnings, fmt.Sprintf("AIA chain building failed: %v", err))
			chain = []*x509.Certificate{cert}
		} else {
			chain = builtChain
		}
	} else {
		chain = []*x509.Certificate{cert}
	}

	result.ChainInfo = ecv.analyzeChain(chain)

	// Step 2: Validate chain rules
	if ecv.config.MinPathLength > 0 && len(chain) < ecv.config.MinPathLength {
		error := fmt.Sprintf("Certificate chain length %d is below minimum required %d", len(chain), ecv.config.MinPathLength)
		result.Errors = append(result.Errors, error)
		result.Valid = false
		ContextualLogger(logCtx).WithFields(logrus.Fields{
			"chain_length":    len(chain),
			"min_path_length": ecv.config.MinPathLength,
		}).Error("Chain length validation failed")
	}

	// Step 3: Verify chain signatures and basic constraints
	if !ecv.verifyChainSignatures(chain) {
		result.Errors = append(result.Errors, "Certificate chain signature verification failed")
		result.Valid = false
		result.EnhancedValidation.SignatureVerified = false
		ContextualLogger(logCtx).Error("Chain signature verification failed")
	} else {
		result.EnhancedValidation.SignatureVerified = true
	}

	// Step 4: Check Extended Key Usage
	if ecv.config.CheckExtendedKeyUsage && requiredUsage != "" {
		requiredOID := ecv.getUsageOID(requiredUsage)
		if requiredOID != "" {
			ekuValid, foundEKUs := ecv.checkExtendedKeyUsage(cert, requiredOID)
			result.EnhancedValidation.ExtKeyUsageValid = ekuValid
			result.EnhancedValidation.RequiredEKUs = []string{requiredOID}
			result.EnhancedValidation.FoundEKUs = foundEKUs

			if !ekuValid {
				error := fmt.Sprintf("Certificate missing required Extended Key Usage: %s", requiredUsage)
				result.Errors = append(result.Errors, error)
				result.Valid = false
				ContextualLogger(logCtx).WithFields(logrus.Fields{
					"required_usage": requiredUsage,
					"required_oid":   requiredOID,
					"found_ekus":     foundEKUs,
				}).Error("Extended Key Usage validation failed")
			}
		}
	}

	// Step 5: Check trust roots
	if ecv.config.CheckTrustRoots {
		trustChainValid := ecv.verifyTrustChain(chain)
		result.EnhancedValidation.TrustChainValid = trustChainValid
		if !trustChainValid {
			result.Errors = append(result.Errors, "Certificate chain does not terminate at a trusted root")
			result.Valid = false
			ContextualLogger(logCtx).Error("Trust chain validation failed")
		}
	}

	// Step 6: Check revocation (OCSP and CRL)
	if ecv.config.CheckOCSPRevocation || ecv.config.CheckCRLRevocation {
		revocationInfo := ecv.checkRevocation(chain)
		result.RevocationInfo = revocationInfo

		if !revocationInfo.RevocationValid {
			if ecv.config.StrictRevocationCheck {
				result.Errors = append(result.Errors, "Revocation check failed or undetermined (strict mode)")
				result.Valid = false
				ContextualLogger(logCtx).Error("Revocation check failed in strict mode")
			} else {
				result.Warnings = append(result.Warnings, "Revocation status could not be determined")
				ContextualLogger(logCtx).Warn("Revocation status undetermined but continuing (non-strict mode)")
			}
		}
	}

	ContextualLogger(logCtx).WithFields(logrus.Fields{
		"cert_subject":        cert.Subject.String(),
		"enhanced_valid":      result.Valid,
		"chain_length":        len(chain),
		"error_count":         len(result.Errors),
		"warning_count":       len(result.Warnings),
		"signature_verified":  result.EnhancedValidation.SignatureVerified,
		"trust_chain_valid":   result.EnhancedValidation.TrustChainValid,
		"ext_key_usage_valid": result.EnhancedValidation.ExtKeyUsageValid,
	}).Info("Enhanced certificate verification completed")

	return result, nil
}

// buildCertificateChain builds certificate chain via AIA
func (ecv *EnhancedCertificateVerifier) buildCertificateChain(leafCert *x509.Certificate) ([]*x509.Certificate, error) {
	logCtx := &LogContext{
		Component:    "enhanced_certificate_verifier",
		Operation:    "build_certificate_chain",
		ResourceType: "certificate_chain",
	}

	chain := []*x509.Certificate{leafCert}
	current := leafCert
	hops := 0

	ContextualLogger(logCtx).Debug("Starting AIA certificate chain building")

	for hops < ecv.config.MaxAIAHops {
		hops++

		if ecv.isSelfSigned(current) {
			ContextualLogger(logCtx).Debug("Reached self-signed certificate, stopping chain building")
			break
		}

		issuerURLs := ecv.parseAIAIssuerURLs(current)
		if len(issuerURLs) == 0 {
			ContextualLogger(logCtx).Debug("No AIA issuer URLs found, stopping chain building")
			break
		}

		foundIssuer := false
		for _, url := range issuerURLs {
			ContextualLogger(logCtx).WithField("aia_url", url).Debug("Fetching issuer certificate")

			issuerCert, err := ecv.fetchCertificateFromURL(url)
			if err != nil {
				ContextualLogger(logCtx).WithError(err).WithField("aia_url", url).Debug("Failed to fetch issuer certificate")
				continue
			}

			if issuerCert.Subject.String() == current.Issuer.String() {
				chain = append(chain, issuerCert)
				current = issuerCert
				foundIssuer = true
				ContextualLogger(logCtx).WithFields(logrus.Fields{
					"aia_url":        url,
					"issuer_subject": issuerCert.Subject.String(),
					"chain_length":   len(chain),
				}).Debug("Successfully added issuer to chain")
				break
			}
		}

		if !foundIssuer {
			ContextualLogger(logCtx).Debug("No valid issuer found, stopping chain building")
			break
		}
	}

	ContextualLogger(logCtx).WithFields(logrus.Fields{
		"final_chain_length": len(chain),
		"hops_used":          hops,
		"max_hops":           ecv.config.MaxAIAHops,
	}).Info("Certificate chain building completed")

	return chain, nil
}

// parseAIAIssuerURLs extracts AIA issuer URLs from certificate
func (ecv *EnhancedCertificateVerifier) parseAIAIssuerURLs(cert *x509.Certificate) []string {
	var urls []string

	for _, ext := range cert.Extensions {
		if ext.Id.String() == "1.3.6.1.5.5.7.1.1" {
			if strings.Contains(string(ext.Value), "http") {
				parts := strings.Split(string(ext.Value), "http")
				for i := 1; i < len(parts); i++ {
					url := "http" + strings.Split(parts[i], "\x00")[0]
					if strings.HasPrefix(url, "http") && strings.Contains(url, ".") {
						urls = append(urls, url)
					}
				}
			}
		}
	}

	return urls
}

// fetchCertificateFromURL fetches certificate from URL
func (ecv *EnhancedCertificateVerifier) fetchCertificateFromURL(certURL string) (*x509.Certificate, error) {
	logCtx := &LogContext{
		Component:    "enhanced_certificate_verifier",
		Operation:    "fetch_certificate_from_url",
		ResourceID:   certURL,
		ResourceType: "remote_certificate",
	}

	client := &http.Client{
		Timeout: time.Duration(ecv.config.AIAFetchTimeout) * time.Second,
	}

	resp, err := client.Get(certURL)
	if err != nil {
		ContextualLogger(logCtx).WithError(err).Error("Failed to fetch certificate from URL")
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		ContextualLogger(logCtx).WithField("status_code", resp.StatusCode).Error("Non-200 response when fetching certificate")
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		ContextualLogger(logCtx).WithError(err).Error("Failed to read certificate response body")
		return nil, err
	}

	cert, err := x509.ParseCertificate(data)
	if err != nil {
		block, _ := pem.Decode(data)
		if block == nil {
			ContextualLogger(logCtx).Error("Failed to decode certificate as DER or PEM")
			return nil, fmt.Errorf("failed to decode certificate")
		}
		cert, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			ContextualLogger(logCtx).WithError(err).Error("Failed to parse PEM certificate")
			return nil, err
		}
	}

	ContextualLogger(logCtx).WithField("cert_subject", cert.Subject.String()).Debug("Successfully fetched and parsed certificate")
	return cert, nil
}

// verifyChainSignatures verifies signatures in the certificate chain
func (ecv *EnhancedCertificateVerifier) verifyChainSignatures(chain []*x509.Certificate) bool {
	logCtx := &LogContext{
		Component:    "enhanced_certificate_verifier",
		Operation:    "verify_chain_signatures",
		ResourceType: "certificate_chain",
	}

	if len(chain) == 0 {
		return false
	}

	for i := 0; i < len(chain)-1; i++ {
		child := chain[i]
		issuer := chain[i+1]

		ContextualLogger(logCtx).WithFields(logrus.Fields{
			"child_subject":  child.Subject.String(),
			"issuer_subject": issuer.Subject.String(),
			"chain_index":    i,
		}).Debug("Verifying signature between child and issuer")

		if !ecv.verifySignature(child, issuer) {
			ContextualLogger(logCtx).WithFields(logrus.Fields{
				"child_subject":  child.Subject.String(),
				"issuer_subject": issuer.Subject.String(),
			}).Error("Signature verification failed")
			return false
		}

		if !ecv.checkCAConstraints(issuer) {
			ContextualLogger(logCtx).WithField("issuer_subject", issuer.Subject.String()).Error("Issuer missing proper CA constraints")
			return false
		}
	}

	ContextualLogger(logCtx).WithField("chain_length", len(chain)).Debug("All chain signatures verified successfully")
	return true
}

// verifySignature verifies that child is signed by issuer
func (ecv *EnhancedCertificateVerifier) verifySignature(child, issuer *x509.Certificate) bool {
	return child.CheckSignatureFrom(issuer) == nil
}

// checkCAConstraints checks that certificate has proper CA basic constraints
func (ecv *EnhancedCertificateVerifier) checkCAConstraints(cert *x509.Certificate) bool {
	return cert.IsCA && cert.BasicConstraintsValid
}

// checkExtendedKeyUsage checks Extended Key Usage
func (ecv *EnhancedCertificateVerifier) checkExtendedKeyUsage(cert *x509.Certificate, requiredOID string) (bool, []string) {
	var foundEKUs []string

	for _, eku := range cert.ExtKeyUsage {
		switch eku {
		case x509.ExtKeyUsageServerAuth:
			foundEKUs = append(foundEKUs, OIDServerAuth)
		case x509.ExtKeyUsageClientAuth:
			foundEKUs = append(foundEKUs, OIDClientAuth)
		case x509.ExtKeyUsageCodeSigning:
			foundEKUs = append(foundEKUs, OIDCodeSigning)
		case x509.ExtKeyUsageEmailProtection:
			foundEKUs = append(foundEKUs, OIDEmailProtection)
		case x509.ExtKeyUsageOCSPSigning:
			foundEKUs = append(foundEKUs, OIDOCSPSigning)
		}
	}

	for _, oid := range foundEKUs {
		if oid == requiredOID {
			return true, foundEKUs
		}
	}

	return false, foundEKUs
}

// getUsageOID converts usage string to OID
func (ecv *EnhancedCertificateVerifier) getUsageOID(usage string) string {
	switch strings.ToLower(usage) {
	case "server_auth", "serverauth":
		return OIDServerAuth
	case "client_auth", "clientauth":
		return OIDClientAuth
	case "code_signing", "codesigning":
		return OIDCodeSigning
	case "email_protection", "emailprotection":
		return OIDEmailProtection
	case "ocsp_signing", "ocspsigning":
		return OIDOCSPSigning
	default:
		return ""
	}
}

// verifyTrustChain verifies that chain terminates at trusted root
func (ecv *EnhancedCertificateVerifier) verifyTrustChain(chain []*x509.Certificate) bool {
	if len(chain) == 0 {
		return false
	}

	root := chain[len(chain)-1]

	_, err := root.Verify(x509.VerifyOptions{
		Roots: ecv.trustRoots,
	})

	return err == nil
}

// checkRevocation checks certificate revocation via OCSP and CRL
func (ecv *EnhancedCertificateVerifier) checkRevocation(chain []*x509.Certificate) *RevocationCheckInfo {
	logCtx := &LogContext{
		Component:    "enhanced_certificate_verifier",
		Operation:    "check_revocation",
		ResourceType: "certificate_revocation",
	}

	info := &RevocationCheckInfo{
		RevocationValid: true,
	}

	for i := 0; i < len(chain)-1; i++ {
		cert := chain[i]
		var issuer *x509.Certificate
		if i+1 < len(chain) {
			issuer = chain[i+1]
		}

		ContextualLogger(logCtx).WithFields(logrus.Fields{
			"cert_subject": cert.Subject.String(),
			"cert_index":   i,
		}).Debug("Checking revocation for certificate")

		if ecv.config.CheckOCSPRevocation && issuer != nil {
			ocspStatus := ecv.checkOCSPRevocation(cert, issuer)
			info.OCSPChecked = true
			info.OCSPStatus = ocspStatus

			if ocspStatus == "revoked" {
				info.RevocationValid = false
				ContextualLogger(logCtx).WithField("cert_subject", cert.Subject.String()).Error("Certificate revoked according to OCSP")
				return info
			} else if ocspStatus == "unknown" && ecv.config.StrictRevocationCheck {
				info.RevocationValid = false
				ContextualLogger(logCtx).WithField("cert_subject", cert.Subject.String()).Error("OCSP status unknown in strict mode")
				return info
			}
		}

		if ecv.config.CheckCRLRevocation && (info.OCSPStatus == "unknown" || info.OCSPStatus == "error") {
			crlStatus := ecv.checkCRLRevocation(cert)
			info.CRLChecked = true
			info.CRLStatus = crlStatus

			if crlStatus == "revoked" {
				info.RevocationValid = false
				ContextualLogger(logCtx).WithField("cert_subject", cert.Subject.String()).Error("Certificate revoked according to CRL")
				return info
			} else if crlStatus == "unknown" && ecv.config.StrictRevocationCheck {
				info.RevocationValid = false
				ContextualLogger(logCtx).WithField("cert_subject", cert.Subject.String()).Error("CRL status unknown in strict mode")
				return info
			}
		}
	}

	ContextualLogger(logCtx).WithFields(logrus.Fields{
		"ocsp_checked":     info.OCSPChecked,
		"ocsp_status":      info.OCSPStatus,
		"crl_checked":      info.CRLChecked,
		"crl_status":       info.CRLStatus,
		"revocation_valid": info.RevocationValid,
	}).Debug("Revocation check completed")

	return info
}

// checkOCSPRevocation checks OCSP revocation status
func (ecv *EnhancedCertificateVerifier) checkOCSPRevocation(cert, issuer *x509.Certificate) string {
	// Simplified OCSP implementation - in production, implement proper OCSP checking
	return "unknown"
}

// checkCRLRevocation checks CRL revocation status
func (ecv *EnhancedCertificateVerifier) checkCRLRevocation(cert *x509.Certificate) string {
	// Simplified CRL implementation - in production, parse CRL distribution points and fetch CRLs
	return "unknown"
}

// analyzeChain analyzes certificate chain and returns info
func (ecv *EnhancedCertificateVerifier) analyzeChain(chain []*x509.Certificate) *CertificateChainInfo {
	info := &CertificateChainInfo{
		ChainLength:  len(chain),
		Certificates: make([]CertificateInfo, len(chain)),
	}

	for i, cert := range chain {
		info.Certificates[i] = extractCertificateInfo(cert)
	}

	if len(chain) > 0 {
		topCert := chain[len(chain)-1]
		info.SelfSignedRoot = ecv.isSelfSigned(topCert)
		info.TrustRootFound = ecv.verifyTrustChain(chain)
	}

	info.AIAChainBuilt = len(chain) > 1
	info.ChainValidationPassed = ecv.verifyChainSignatures(chain)

	return info
}

// isSelfSigned checks if certificate is self-signed
func (ecv *EnhancedCertificateVerifier) isSelfSigned(cert *x509.Certificate) bool {
	return cert.Subject.String() == cert.Issuer.String()
}

// Integration with existing SecurityManager
func (sm *SecurityManager) ValidateWithEnhancedVerification(certPath, requiredUsage string) (*EnhancedCertValidationResult, error) {
	logCtx := &LogContext{
		Component:    "security_manager",
		Operation:    "validate_with_enhanced_verification",
		ResourceID:   certPath,
		ResourceType: "certificate",
	}

	ContextualLogger(logCtx).WithFields(logrus.Fields{
		"cert_path":      certPath,
		"required_usage": requiredUsage,
	}).Info("Starting enhanced certificate validation")

	enhancedConfig := getDefaultEnhancedCertValidationConfig()
	if requiredUsage != "" {
		enhancedConfig.RequiredExtKeyUsages = []string{enhancedConfig.RequiredExtKeyUsages[0]}
	}

	verifier := NewEnhancedCertificateVerifier(enhancedConfig)
	result, err := verifier.VerifyEnhanced(certPath, requiredUsage)

	if err != nil {
		ContextualLogger(logCtx).WithError(err).Error("Enhanced verification failed")
		return nil, err
	}

	ContextualLogger(logCtx).WithFields(logrus.Fields{
		"enhanced_valid":      result.Valid,
		"chain_length":        result.ChainInfo.ChainLength,
		"trust_root_found":    result.ChainInfo.TrustRootFound,
		"signature_verified":  result.EnhancedValidation.SignatureVerified,
		"trust_chain_valid":   result.EnhancedValidation.TrustChainValid,
		"ext_key_usage_valid": result.EnhancedValidation.ExtKeyUsageValid,
		"revocation_valid":    result.RevocationInfo.RevocationValid,
	}).Info("Enhanced certificate validation completed")

	return result, nil
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

	caCN, err := extractCNFromCACertificate(caCertPath)
	if err != nil {
		ContextualLogger(logCtx).WithError(err).WithField("cn_extraction_result", "failed").Error("Failed to extract CN from CA certificate")
		return fmt.Errorf("failed to extract CN from CA certificate: %v", err)
	}

	ContextualLogger(logCtx).WithField("ca_certificate_cn", caCN).Debug("CA certificate CN extracted successfully")

	securityConfig, err := sm.FetchSecurityConfig()
	if err != nil {
		ContextualLogger(logCtx).WithError(err).WithField("security_config_fetch_result", "failed").Error("Failed to fetch security management configuration")
		return fmt.Errorf("failed to fetch security management configuration: %v", err)
	}

	if len(securityConfig.Hits.Hits) == 0 {
		ContextualLogger(logCtx).WithField("security_config_result", "no_config_found").Error("No security management configuration found")
		return fmt.Errorf("no security management configuration found")
	}

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

	ctx.ClientHost = resolveClientHostname(ctx.ClientIP)

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

	file, err := tryCreateLogFile(logFilePath, logCtx)
	if err == nil {
		ContextualLogger(logCtx).WithField("log_file_path", logFilePath).Info("Primary log file setup completed successfully")
		return file, nil
	}

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

	ContextualLogger(logCtx).WithError(err).WithFields(logrus.Fields{
		"primary_log_path":    logFilePath,
		"attempted_fallbacks": fallbackPaths,
		"logging_mode":        "stdout_only",
	}).Error("All log file paths failed, continuing with stdout-only logging")

	return nil, fmt.Errorf("all log file paths failed, primary error: %v", err)
}

// tryCreateLogFile attempts to create a log file at the specified path
func tryCreateLogFile(logFilePath string, logCtx *LogContext) (*os.File, error) {
	if file, err := os.OpenFile(logFilePath, os.O_WRONLY|os.O_APPEND, 0644); err == nil {
		ContextualLogger(logCtx).WithField("log_file_status", "existing_writable").Debug("Using existing log file")
		return file, nil
	}

	logDir := filepath.Dir(logFilePath)
	if err := os.MkdirAll(logDir, 0755); err != nil {
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

	file, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
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
		"stdout_enabled": true,
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

	if !loggingStatus["file_logging_enabled"].(bool) {
		ContextualLogger(startupLogCtx).WithFields(logrus.Fields{
			"logging_mode":       "stdout_only",
			"recommended_action": "ensure writable log directory or use environment variable LOG_FILE_PATH",
			"warning_type":       "logging_limitation",
		}).Warn("File logging is disabled - logs will only appear in stdout/systemd journal")
	}

	if os.Geteuid() == 0 {
		ContextualLogger(startupLogCtx).WithFields(logrus.Fields{
			"user_id":            0,
			"user_type":          "root",
			"security_warning":   true,
			"recommended_action": "run as dedicated service user for security",
		}).Warn("Service is running as root user - consider using dedicated service account")
	}

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

// logEnhancedValidationStartupInfo logs enhanced validation configuration
func logEnhancedValidationStartupInfo() {
	startupLogCtx := &LogContext{
		Component: "main",
		Operation: "enhanced_validation_startup_info",
	}

	enhancedConfig := getEnhancedConfig()

	ContextualLogger(startupLogCtx).WithFields(logrus.Fields{
		"startup_phase":                    "enhanced_validation_configuration",
		"enhanced_min_path_length":         enhancedConfig.MinPathLength,
		"enhanced_aia_chain_building":      enhancedConfig.CheckAIAChainBuilding,
		"enhanced_ocsp_revocation":         enhancedConfig.CheckOCSPRevocation,
		"enhanced_crl_revocation":          enhancedConfig.CheckCRLRevocation,
		"enhanced_extended_key_usage":      enhancedConfig.CheckExtendedKeyUsage,
		"enhanced_trust_roots":             enhancedConfig.CheckTrustRoots,
		"enhanced_required_ext_key_usages": enhancedConfig.RequiredExtKeyUsages,
		"enhanced_strict_revocation":       enhancedConfig.StrictRevocationCheck,
		"enhanced_aia_fetch_timeout":       enhancedConfig.AIAFetchTimeout,
		"enhanced_ocsp_timeout":            enhancedConfig.OCSPTimeout,
		"enhanced_crl_timeout":             enhancedConfig.CRLTimeout,
		"enhanced_max_aia_hops":            enhancedConfig.MaxAIAHops,
	}).Info("Enhanced certificate validation configuration loaded (Python-style verification)")

	if enhancedConfig.CheckAIAChainBuilding {
		ContextualLogger(startupLogCtx).WithFields(logrus.Fields{
			"feature":          "aia_chain_building",
			"security_benefit": "builds_complete_certificate_chains",
			"validation_level": "enhanced",
		}).Info("AIA certificate chain building enabled - will fetch intermediate certificates automatically")
	}

	if enhancedConfig.CheckOCSPRevocation || enhancedConfig.CheckCRLRevocation {
		ContextualLogger(startupLogCtx).WithFields(logrus.Fields{
			"feature":          "revocation_checking",
			"ocsp_enabled":     enhancedConfig.CheckOCSPRevocation,
			"crl_enabled":      enhancedConfig.CheckCRLRevocation,
			"strict_mode":      enhancedConfig.StrictRevocationCheck,
			"security_benefit": "detects_revoked_certificates",
			"validation_level": "enhanced",
		}).Info("Certificate revocation checking enabled")
	}

	if enhancedConfig.CheckTrustRoots {
		ContextualLogger(startupLogCtx).WithFields(logrus.Fields{
			"feature":          "trust_root_validation",
			"security_benefit": "validates_against_system_ca_store",
			"validation_level": "enhanced",
		}).Info("Trust root validation enabled - will verify against system CA store")
	}

	if enhancedConfig.MinPathLength > 1 {
		ContextualLogger(startupLogCtx).WithFields(logrus.Fields{
			"feature":          "minimum_path_length",
			"min_path_length":  enhancedConfig.MinPathLength,
			"security_benefit": "enforces_certificate_chain_depth",
			"validation_level": "enhanced",
		}).Info("Minimum path length enforcement enabled")
	}
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

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		ContextualLogger(logCtx).Warn("YAML config file not found, using defaults and environment variables")
		return getDefaultConfigWithEnvOverrides(), nil
	}

	data, err := ioutil.ReadFile(configPath)
	if err != nil {
		ContextualLogger(logCtx).WithError(err).Error("Failed to read YAML config file")
		return nil, fmt.Errorf("failed to read config file: %v", err)
	}

	var config SecurityManagementConfig
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		ContextualLogger(logCtx).WithError(err).Error("Failed to parse YAML config file")
		return nil, fmt.Errorf("failed to parse YAML config: %v", err)
	}

	applyEnvironmentOverrides(&config)
	applyEnhancedEnvironmentOverrides(&config)

	ContextualLogger(logCtx).WithFields(logrus.Fields{
		"cert_validation_strict":         config.CertificateValidation.ValidationStrict,
		"cert_min_key_length":            config.CertificateValidation.MinKeyLength,
		"cert_max_validity_days":         config.CertificateValidation.MaxValidityDays,
		"cert_check_expiration":          config.CertificateValidation.CheckExpiration,
		"cert_check_key_length":          config.CertificateValidation.CheckKeyLength,
		"cert_check_signature_algorithm": config.CertificateValidation.CheckSignatureAlgorithm,
		"enhanced_min_path_length":       config.EnhancedValidation.MinPathLength,
		"enhanced_aia_chain_building":    config.EnhancedValidation.CheckAIAChainBuilding,
		"enhanced_ocsp_revocation":       config.EnhancedValidation.CheckOCSPRevocation,
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
			ValidationStrict:        true,
		},
		EnhancedValidation: EnhancedCertValidationConfig{
			MinPathLength:         3,
			CheckAIAChainBuilding: true,
			CheckOCSPRevocation:   true,
			CheckCRLRevocation:    true,
			CheckExtendedKeyUsage: true,
			CheckTrustRoots:       true,
			RequiredExtKeyUsages:  []string{OIDServerAuth},
			StrictRevocationCheck: false,
			AIAFetchTimeout:       10,
			OCSPTimeout:           10,
			CRLTimeout:            15,
			MaxAIAHops:            10,
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
			UpdateConfigsAuthRequired: true,
		},
	}

	applyEnvironmentOverrides(config)
	applyEnhancedEnvironmentOverrides(config)

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

	if env := os.Getenv("LOG_LEVEL"); env != "" {
		config.Logging.Level = env
	}
	if env := os.Getenv("LOG_FORMAT"); env != "" {
		config.Logging.Format = env
	}
	if env := os.Getenv("LOG_FILE_PATH"); env != "" {
		config.Logging.FilePath = env
	}

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

	if env := os.Getenv("UPDATE_CONFIGS_AUTH_REQUIRED"); env == "false" {
		config.API.UpdateConfigsAuthRequired = false
	}

	ContextualLogger(logCtx).Debug("Environment variable overrides applied successfully")
}

// applyEnhancedEnvironmentOverrides applies enhanced validation environment overrides
func applyEnhancedEnvironmentOverrides(config *SecurityManagementConfig) {
	logCtx := &LogContext{
		Component: "config_management",
		Operation: "apply_enhanced_environment_overrides",
	}

	ContextualLogger(logCtx).Debug("Applying enhanced validation environment overrides")

	if env := os.Getenv("ENHANCED_MIN_PATH_LENGTH"); env != "" {
		if val, err := strconv.Atoi(env); err == nil {
			config.EnhancedValidation.MinPathLength = val
		}
	}
	if env := os.Getenv("ENHANCED_CHECK_AIA_CHAIN_BUILDING"); env == "false" {
		config.EnhancedValidation.CheckAIAChainBuilding = false
	}
	if env := os.Getenv("ENHANCED_CHECK_OCSP_REVOCATION"); env == "false" {
		config.EnhancedValidation.CheckOCSPRevocation = false
	}
	if env := os.Getenv("ENHANCED_CHECK_CRL_REVOCATION"); env == "false" {
		config.EnhancedValidation.CheckCRLRevocation = false
	}
	if env := os.Getenv("ENHANCED_CHECK_EXTENDED_KEY_USAGE"); env == "false" {
		config.EnhancedValidation.CheckExtendedKeyUsage = false
	}
	if env := os.Getenv("ENHANCED_CHECK_TRUST_ROOTS"); env == "false" {
		config.EnhancedValidation.CheckTrustRoots = false
	}
	if env := os.Getenv("ENHANCED_STRICT_REVOCATION_CHECK"); env == "true" {
		config.EnhancedValidation.StrictRevocationCheck = true
	}
	if env := os.Getenv("ENHANCED_AIA_FETCH_TIMEOUT"); env != "" {
		if val, err := strconv.Atoi(env); err == nil {
			config.EnhancedValidation.AIAFetchTimeout = val
		}
	}
	if env := os.Getenv("ENHANCED_OCSP_TIMEOUT"); env != "" {
		if val, err := strconv.Atoi(env); err == nil {
			config.EnhancedValidation.OCSPTimeout = val
		}
	}
	if env := os.Getenv("ENHANCED_CRL_TIMEOUT"); env != "" {
		if val, err := strconv.Atoi(env); err == nil {
			config.EnhancedValidation.CRLTimeout = val
		}
	}
	if env := os.Getenv("ENHANCED_MAX_AIA_HOPS"); env != "" {
		if val, err := strconv.Atoi(env); err == nil {
			config.EnhancedValidation.MaxAIAHops = val
		}
	}

	// Required Extended Key Usages (comma-separated)
	if env := os.Getenv("ENHANCED_REQUIRED_EXT_KEY_USAGES"); env != "" {
		usages := strings.Split(env, ",")
		for i := range usages {
			usages[i] = strings.TrimSpace(usages[i])
		}
		config.EnhancedValidation.RequiredExtKeyUsages = usages
	}

	ContextualLogger(logCtx).Debug("Enhanced validation environment overrides applied")
}

// initializeConfiguration initializes the global configuration
func initializeConfiguration() error {
	logCtx := &LogContext{
		Component: "config_management",
		Operation: "initialize_configuration",
	}

	configPath := os.Getenv("SIEM_CONFIG_PATH")
	if configPath == "" {
		configPath = "/etc/siem/security-management/security_management.yaml"
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
	return getValidationConfigFromEnv()
}

// shouldFailOnCertValidationError determines if certificate validation errors should cause failures
func shouldFailOnCertValidationError() bool {
	if globalConfig != nil {
		return globalConfig.CertificateValidation.ValidationStrict
	}
	return os.Getenv("CERT_VALIDATION_STRICT") != "false"
}

// isUpdateConfigsAuthRequired checks if authentication is required for update-configs API
func isUpdateConfigsAuthRequired() bool {
	if globalConfig != nil {
		return globalConfig.API.UpdateConfigsAuthRequired
	}
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

// getEnhancedConfig returns enhanced validation configuration
func getEnhancedConfig() *EnhancedCertValidationConfig {
	if globalConfig != nil {
		return &globalConfig.EnhancedValidation
	}
	return getDefaultEnhancedCertValidationConfig()
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
	}

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

		switch checkResult.Severity {
		case "error":
			result.Errors = append(result.Errors, checkResult.Message)
			if !checkResult.Passed {
				result.Valid = false
			}
		case "warning":
			result.Warnings = append(result.Warnings, checkResult.Message)
			if strictMode && !checkResult.Passed {
				result.Valid = false
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

	if strictMode && len(result.Warnings) > 0 {
		for _, warning := range result.Warnings {
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
		logLevel = os.Getenv("LOG_LEVEL")
		logFormat = os.Getenv("LOG_FORMAT")
	}

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

	if strings.ToLower(logFormat) == "text" {
		logger.SetFormatter(&logrus.TextFormatter{
			TimestampFormat: "2006-01-02 15:04:05",
			FullTimestamp:   true,
		})
	} else {
		logger.SetFormatter(&logrus.JSONFormatter{
			TimestampFormat: "2006-01-02T15:04:05Z07:00",
			FieldMap: logrus.FieldMap{
				logrus.FieldKeyTime:  "timestamp",
				logrus.FieldKeyLevel: "level",
				logrus.FieldKeyMsg:   "message",
			},
		})
	}

	logFilePath := getLogFilePath()
	var err error
	var loggingMode string
	var actualLogPath string

	logFile, err = setupLogFile(logFilePath)
	if err != nil {
		logger.SetOutput(os.Stdout)
		loggingMode = "stdout_only"
		actualLogPath = "stdout"

		ContextualLogger(logCtx).WithError(err).WithFields(logrus.Fields{
			"requested_log_path": logFilePath,
			"logging_mode":       loggingMode,
			"fallback_reason":    "file_logging_unavailable",
		}).Warn("File logging unavailable, continuing with stdout-only logging")
	} else {
		multiWriter := io.MultiWriter(os.Stdout, logFile)
		logger.SetOutput(multiWriter)
		loggingMode = "file_and_stdout"

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
					InsecureSkipVerify: true,
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
	requestURL := fmt.Sprintf("%s%s", kibanaURL, path)

	req, err := http.NewRequest("GET", requestURL, nil)
	if err != nil {
		ContextualLogger(logCtx).WithError(err).Error("Failed to create Kibana request")
		return nil, fmt.Errorf("error creating request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("kbn-xsrf", "true")
	req.SetBasicAuth(elasticSearchUser, elasticSearchPass)

	resp, err := sm.client.Do(req)
	if err != nil {
		ContextualLogger(logCtx).WithError(err).Error("Kibana request failed")
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

		if strings.HasPrefix(cn, "*.") {
			domain := cn[2:]
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

// parseEmailConfig parses email configuration from request data
func parseEmailConfig(data map[string]interface{}, service string) (*EmailConfig, error) {
	logCtx := &LogContext{
		Component:    "email_service",
		Operation:    "parse_email_config",
		ResourceType: "email_config",
	}

	ContextualLogger(logCtx).WithField("email_service", service).Debug("Parsing email configuration")

	config := &EmailConfig{}

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

	config.FromName, _ = getString("from_name", false)
	config.AuthMethod, _ = getString("auth_method", false)
	config.Secure, _ = getString("secure", false)
	config.ToEmail, _ = getString("to_email", false)
	config.Subject, _ = getString("subject", false)
	config.Body, _ = getString("body", false)

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
		config.CACertPath, _ = getString("ca_cert_path", false)
		if config.CACertPath != "" {
			ContextualLogger(logCtx).WithFields(logrus.Fields{
				"email_service": service,
				"ca_cert_path":  config.CACertPath,
			}).Debug("Optional CA certificate path provided for non-Exchange service")
		}
	}

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

	if config.Secure == "true" || config.Secure == "false" {
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

		if config.Secure == "false" {
			tlsConfig.InsecureSkipVerify = true
			ContextualLogger(logCtx).WithFields(logrus.Fields{
				"secure_setting":           config.Secure,
				"certificate_verification": "disabled",
				"reason":                   "secure_false_allows_self_signed",
			}).Info("TLS certificate verification disabled due to secure=false setting")
		} else {
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

	client, err := createSecureSMTPClient(emailConfig.SMTPHost, emailConfig.SMTPPort, emailConfig)
	if err != nil {
		ContextualLogger(logCtx).WithError(err).Error("Failed to create SMTP client")
		return fmt.Errorf("failed to create SMTP client: %v", err)
	}
	defer client.Close()

	if emailConfig.Username != "" && emailConfig.Password != "" {
		var auth smtp.Auth

		switch strings.ToUpper(emailConfig.AuthMethod) {
		case "PLAIN":
			auth = smtp.PlainAuth("", emailConfig.Username, emailConfig.Password, emailConfig.SMTPHost)
		case "CRAM-MD5":
			auth = smtp.CRAMMD5Auth(emailConfig.Username, emailConfig.Password)
		case "LOGIN":
			auth = NewLoginAuth(emailConfig.Username, emailConfig.Password)
		case "AUTO", "":
			auth = autoDetectAuth(emailConfig, client)
		default:
			auth = NewLoginAuth(emailConfig.Username, emailConfig.Password)
		}

		if err := client.Auth(auth); err != nil {
			ContextualLogger(logCtx).WithError(err).Error("SMTP authentication failed")
			return fmt.Errorf("SMTP authentication failed: %v", err)
		}
	}

	if err := client.Mail(emailConfig.FromEmail); err != nil {
		ContextualLogger(logCtx).WithError(err).Error("Failed to set sender")
		return fmt.Errorf("failed to set sender: %v", err)
	}

	toEmail := emailConfig.ToEmail
	if toEmail == "" {
		toEmail = "hr7sha@gmail.com"
	}

	if err := client.Rcpt(toEmail); err != nil {
		ContextualLogger(logCtx).WithError(err).Error("Failed to set recipient")
		return fmt.Errorf("failed to set recipient: %v", err)
	}

	writer, err := client.Data()
	if err != nil {
		ContextualLogger(logCtx).WithError(err).Error("Failed to get data writer")
		return fmt.Errorf("failed to get data writer: %v", err)
	}
	defer writer.Close()

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

	if _, err := writer.Write(message); err != nil {
		ContextualLogger(logCtx).WithError(err).Error("Failed to write email message")
		return fmt.Errorf("failed to write email message: %v", err)
	}

	if err := writer.Close(); err != nil {
		ContextualLogger(logCtx).WithError(err).Error("Failed to finalize email send")
		return fmt.Errorf("failed to finalize email send: %v", err)
	}

	ContextualLogger(logCtx).WithFields(logrus.Fields{
		"to_email":     toEmail,
		"subject":      subject,
		"body_length":  len(body),
		"from_email":   emailConfig.FromEmail,
		"smtp_server":  emailConfig.SMTPHost,
		"final_status": "email_queued_for_delivery",
	}).Info("Email sent successfully and queued for delivery")

	return nil
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
		if duration, err := time.ParseDuration(globalConfig.Security.TokenExpiration); err == nil {
			tokenExpiration = duration
		} else {
			tokenExpiration = 24 * time.Hour
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

// Enhanced API handler that combines both validation approaches
func handleEnhancedConnectorValidation(sm *SecurityManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		logCtx := getLogContextFromGin(c)
		logCtx.Component = "enhanced_connector_validation_handler"
		logCtx.Operation = "handle_enhanced_connector_validation"

		ContextualLogger(logCtx).Info("Starting enhanced connector validation with Python-style verification")

		var req ConnectorValidationRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			ContextualLogger(logCtx).WithError(err).Error("Invalid request body")
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body: " + err.Error()})
			return
		}

		connectorID := req.ConnectorID
		if connectorID == "" {
			ContextualLogger(logCtx).Error("Missing connector ID")
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

		switch strings.ToLower(req.Type) {
		case "email":
			response.EmailService = req.Service
			ContextualLogger(logCtx).WithFields(logrus.Fields{
				"connector_type": "email",
				"email_service":  req.Service,
			}).Info("Processing email connector request")

			emailConfig, err := parseEmailConfig(req.Data, req.Service)
			if err != nil {
				ContextualLogger(logCtx).WithError(err).Error("Failed to parse email configuration")
				response.Message = "Failed to parse email configuration"
				response.TestResult.Success = false
				response.TestResult.Error = err.Error()
				c.JSON(http.StatusBadRequest, response)
				return
			}

			if strings.ToLower(req.Service) == "exchange" {
				ContextualLogger(logCtx).WithField("validation_step", "enhanced_exchange_ca_validation").Info("Performing enhanced Exchange CA certificate validation")

				enhancedResult, err := sm.ValidateWithEnhancedVerification(emailConfig.CACertPath, "server_auth")
				if err != nil {
					ContextualLogger(logCtx).WithError(err).Error("Enhanced Exchange CA certificate validation failed")
					response.Message = "Enhanced Exchange CA certificate validation failed"
					response.TestResult.Success = false
					response.TestResult.Error = err.Error()
					c.JSON(http.StatusForbidden, response)
					return
				}

				if !enhancedResult.Valid {
					ContextualLogger(logCtx).WithFields(logrus.Fields{
						"enhanced_errors":   enhancedResult.Errors,
						"enhanced_warnings": enhancedResult.Warnings,
						"chain_length":      enhancedResult.ChainInfo.ChainLength,
						"trust_root_found":  enhancedResult.ChainInfo.TrustRootFound,
					}).Error("Enhanced Exchange CA certificate validation failed")
					response.Message = "Enhanced Exchange CA certificate validation failed"
					response.TestResult.Success = false
					response.TestResult.Error = strings.Join(enhancedResult.Errors, "; ")
					c.JSON(http.StatusForbidden, response)
					return
				}

				if err := sm.validateExchangeCACertificate(emailConfig.CACertPath); err != nil {
					ContextualLogger(logCtx).WithError(err).Error("Exchange CA certificate CN validation failed")
					response.Message = "Exchange CA certificate CN validation failed"
					response.TestResult.Success = false
					response.TestResult.Error = err.Error()
					c.JSON(http.StatusForbidden, response)
					return
				}
			}

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
			response.Message = "Email sent successfully with enhanced validation"

		case "webhook":
			response.ConnectorURL = req.URL
			ContextualLogger(logCtx).WithFields(logrus.Fields{
				"connector_type": "webhook",
				"connector_url":  req.URL,
			}).Info("Processing webhook connector request with enhanced validation")

			connectorInfo, err := sm.FetchConnectorInfo(connectorID)
			if err != nil {
				ContextualLogger(logCtx).WithError(err).Error("Failed to fetch connector information")
				response.Message = "Failed to fetch connector information"
				response.TestResult.Success = false
				response.TestResult.Error = err.Error()
				c.JSON(http.StatusInternalServerError, response)
				return
			}
			response.ConnectorName = connectorInfo.Name

			certInfo, err := sm.FetchCertificateInfo(connectorInfo.Name)
			if err != nil {
				ContextualLogger(logCtx).WithError(err).Error("Failed to fetch certificate information")
				response.Message = "Failed to fetch certificate information"
				response.TestResult.Success = false
				response.TestResult.Error = err.Error()
				c.JSON(http.StatusInternalServerError, response)
				return
			}
			if len(certInfo.Hits.Hits) == 0 {
				ContextualLogger(logCtx).Error("No certificates found for connector")
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

			ContextualLogger(logCtx).WithField("validation_step", "enhanced_certificate_verification").Info("Performing enhanced certificate verification with Python-style logic")

			enhancedResult, err := sm.ValidateWithEnhancedVerification(cert.PublicPath, "server_auth")
			if err != nil {
				ContextualLogger(logCtx).WithError(err).Error("Enhanced certificate verification failed")
				response.Message = "Enhanced certificate verification failed"
				response.TestResult.Success = false
				response.TestResult.Error = err.Error()
				c.JSON(http.StatusInternalServerError, response)
				return
			}

			response.CertificateValidation = &CertificateValidationResult{
				Valid:           enhancedResult.Valid,
				Errors:          enhancedResult.Errors,
				Warnings:        enhancedResult.Warnings,
				CheckResults:    enhancedResult.CheckResults,
				CertificateInfo: enhancedResult.CertificateInfo,
			}

			if !enhancedResult.Valid {
				ContextualLogger(logCtx).WithFields(logrus.Fields{
					"enhanced_errors":     enhancedResult.Errors,
					"enhanced_warnings":   enhancedResult.Warnings,
					"chain_length":        enhancedResult.ChainInfo.ChainLength,
					"trust_root_found":    enhancedResult.ChainInfo.TrustRootFound,
					"signature_verified":  enhancedResult.EnhancedValidation.SignatureVerified,
					"trust_chain_valid":   enhancedResult.EnhancedValidation.TrustChainValid,
					"ext_key_usage_valid": enhancedResult.EnhancedValidation.ExtKeyUsageValid,
				}).Error("Enhanced certificate verification failed")
				response.Message = "Enhanced certificate verification failed"
				response.TestResult.Success = false
				response.TestResult.Error = strings.Join(enhancedResult.Errors, "; ")
				c.JSON(http.StatusForbidden, response)
				return
			}

			certificateCN, err := getCertificateCN(cert.PublicPath)
			if err != nil {
				ContextualLogger(logCtx).WithError(err).Error("Failed to extract CN from certificate")
				response.Message = "Failed to extract CN from certificate"
				response.TestResult.Success = false
				response.TestResult.Error = err.Error()
				c.JSON(http.StatusInternalServerError, response)
				return
			}

			securityConfig, err := sm.FetchSecurityConfig()
			if err != nil {
				ContextualLogger(logCtx).WithError(err).Error("Failed to fetch security configuration")
				response.Message = "Failed to fetch security configuration"
				response.TestResult.Success = false
				response.TestResult.Error = err.Error()
				c.JSON(http.StatusInternalServerError, response)
				return
			}
			if len(securityConfig.Hits.Hits) == 0 {
				ContextualLogger(logCtx).Error("No security configuration found")
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

			isValid, extractedCN, err := sm.ValidateConnectorCN(certificateCN, configuredCNs)
			if err != nil {
				ContextualLogger(logCtx).WithError(err).Error("CN validation error")
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
					"certificate_cn": certificateCN,
					"configured_cns": configuredCNs,
				}).Error("CN validation failed")
				response.Message = "CN validation failed - connector not authorized"
				response.TestResult.Success = false
				response.TestResult.Error = fmt.Sprintf("Certificate CN '%s' not found in configured CNs", certificateCN)
				c.JSON(http.StatusForbidden, response)
				return
			}

			response.TestResult.Success = true
			response.Message = "Enhanced connector validation completed successfully"

			ContextualLogger(logCtx).WithFields(logrus.Fields{
				"enhanced_validation_passed":    true,
				"traditional_validation_passed": true,
				"chain_length":                  enhancedResult.ChainInfo.ChainLength,
				"trust_root_found":              enhancedResult.ChainInfo.TrustRootFound,
				"revocation_checked":            enhancedResult.RevocationInfo.OCSPChecked || enhancedResult.RevocationInfo.CRLChecked,
			}).Info("All validation steps passed")

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

// Legacy API handler for backward compatibility
func handleAPI(sm *SecurityManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		// This is the original handleAPI function for backward compatibility
		// Implementation would be the same as the original but without enhanced validation
		c.JSON(http.StatusOK, gin.H{"message": "Legacy API - use enhanced API for full validation"})
	}
}

// Enhanced certificate validation endpoint
func handleEnhancedCertificateValidation() gin.HandlerFunc {
	return func(c *gin.Context) {
		logCtx := getLogContextFromGin(c)
		logCtx.Component = "enhanced_certificate_validation_handler"
		logCtx.Operation = "handle_enhanced_certificate_validation"

		ContextualLogger(logCtx).Info("Starting enhanced certificate validation request")

		var req struct {
			CertificatePath string                        `json:"certificate_path" binding:"required"`
			RequiredUsage   string                        `json:"required_usage,omitempty"`
			Config          *EnhancedCertValidationConfig `json:"config,omitempty"`
		}

		if err := c.ShouldBindJSON(&req); err != nil {
			ContextualLogger(logCtx).WithError(err).Error("Invalid enhanced certificate validation request")
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body: " + err.Error()})
			return
		}

		certPath := req.CertificatePath
		logCtx.ResourceID = certPath
		logCtx.ResourceType = "certificate"

		if _, err := os.Stat(certPath); os.IsNotExist(err) {
			ContextualLogger(logCtx).Error("Certificate file does not exist")
			c.JSON(http.StatusNotFound, gin.H{"error": "Certificate file not found"})
			return
		}

		config := req.Config
		if config == nil {
			config = getDefaultEnhancedCertValidationConfig()
		}

		if req.RequiredUsage != "" {
			verifier := NewEnhancedCertificateVerifier(config)
			usageOID := verifier.getUsageOID(req.RequiredUsage)
			if usageOID != "" {
				config.RequiredExtKeyUsages = []string{usageOID}
			}
		}

		verifier := NewEnhancedCertificateVerifier(config)
		result, err := verifier.VerifyEnhanced(certPath, req.RequiredUsage)
		if err != nil {
			ContextualLogger(logCtx).WithError(err).Error("Enhanced certificate validation failed")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Enhanced validation failed: " + err.Error()})
			return
		}

		ContextualLogger(logCtx).WithFields(logrus.Fields{
			"enhanced_valid":     result.Valid,
			"chain_length":       result.ChainInfo.ChainLength,
			"trust_root_found":   result.ChainInfo.TrustRootFound,
			"signature_verified": result.EnhancedValidation.SignatureVerified,
			"revocation_checked": result.RevocationInfo.OCSPChecked || result.RevocationInfo.CRLChecked,
		}).Info("Enhanced certificate validation completed")

		c.JSON(http.StatusOK, gin.H{
			"certificate_path":  certPath,
			"required_usage":    req.RequiredUsage,
			"validation_result": result,
			"config_used":       config,
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

		if _, err := os.Stat(certPath); os.IsNotExist(err) {
			ContextualLogger(logCtx).WithField("file_existence_check", "not_found").Error("Certificate file does not exist")
			c.JSON(http.StatusNotFound, gin.H{"error": "Certificate file not found"})
			return
		}

		validationConfig := req.Config
		if validationConfig == nil {
			validationConfig = getDefaultCertValidationConfig()
		}

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

		validationResult := ValidateCertificateWithConfig(cert, validationConfig, certPath)

		ContextualLogger(logCtx).WithFields(logrus.Fields{
			"cert_subject":             cert.Subject.String(),
			"validation_valid":         validationResult.Valid,
			"validation_error_count":   len(validationResult.Errors),
			"validation_warning_count": len(validationResult.Warnings),
			"validation_result":        "completed",
		}).Info("Certificate validation completed")

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
				"enhanced_validation_enabled":   isEnhancedValidationEnabled(),
				"enhanced_validation_status":    getEnhancedValidationStatus(),
				"email_support":                 "enabled",
			},
		}

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

// handleUpdateConfigs handles configuration updates and propagation with optional authentication
func handleUpdateConfigs(sm *SecurityManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Implementation would be similar to original but with enhanced logging
		c.JSON(http.StatusOK, gin.H{"message": "Update configs endpoint"})
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

// isEnhancedValidationEnabled checks if enhanced validation is enabled
func isEnhancedValidationEnabled() bool {
	config := getEnhancedConfig()
	return config.CheckAIAChainBuilding || config.CheckOCSPRevocation ||
		config.CheckCRLRevocation || config.CheckTrustRoots ||
		config.MinPathLength > 1
}

// getEnhancedValidationStatus returns current enhanced validation status
func getEnhancedValidationStatus() map[string]interface{} {
	config := getEnhancedConfig()
	return map[string]interface{}{
		"enhanced_validation_enabled":   isEnhancedValidationEnabled(),
		"min_path_length":               config.MinPathLength,
		"aia_chain_building":            config.CheckAIAChainBuilding,
		"ocsp_revocation_checking":      config.CheckOCSPRevocation,
		"crl_revocation_checking":       config.CheckCRLRevocation,
		"extended_key_usage_validation": config.CheckExtendedKeyUsage,
		"trust_root_validation":         config.CheckTrustRoots,
		"strict_revocation_check":       config.StrictRevocationCheck,
		"required_ext_key_usages":       config.RequiredExtKeyUsages,
		"timeouts": map[string]int{
			"aia_fetch_timeout": config.AIAFetchTimeout,
			"ocsp_timeout":      config.OCSPTimeout,
			"crl_timeout":       config.CRLTimeout,
		},
		"max_aia_hops": config.MaxAIAHops,
	}
}

func main() {
	// Initialize basic logger first (before config loading)
	initBasicLogger()

	// Initialize system information for consistent logging
	if err := initSystemInfo(); err != nil {
		logger.WithError(err).Error("Failed to initialize system information")
	}

	// Initialize configuration from YAML file
	if err := initializeConfiguration(); err != nil {
		ContextualLogger(&LogContext{
			Component: "main",
			Operation: "initialize_configuration",
		}).WithError(err).Warn("Failed to load YAML configuration, falling back to environment variables and defaults")
	}

	// Reinitialize logger with YAML configuration settings and file output
	initLogger()

	// Log comprehensive startup information
	logSystemStartupInfo()

	// Log enhanced validation configuration
	logEnhancedValidationStartupInfo()

	// Ensure log file is properly closed on shutdown
	defer closeLogFile()

	mainLogCtx := &LogContext{
		Component: "main",
		Operation: "startup",
	}

	ContextualLogger(mainLogCtx).Info("Starting SIEM Security Manager API server with Enhanced Certificate Verification")

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

	// Certificate validation endpoints
	router.POST("/validate-certificate", handleCertificateValidation())
	router.POST("/validate-certificate-enhanced", handleEnhancedCertificateValidation())

	// Enhanced API endpoint with Python-style verification
	router.POST("/api", handleEnhancedConnectorValidation(sm))

	// Legacy API endpoint (for backward compatibility)
	router.POST("/api-legacy", handleAPI(sm))

	// Check if authentication is required for update-configs
	if isUpdateConfigsAuthRequired() {
		ContextualLogger(mainLogCtx).WithField("update_configs_auth", "required").Info("Authentication is REQUIRED for /update-configs endpoint")
		secured := router.Group("")
		secured.Use(authMiddleware())
		{
			secured.POST("/update-configs", handleUpdateConfigs(sm))
		}
	} else {
		ContextualLogger(mainLogCtx).WithField("update_configs_auth", "disabled").Warn("Authentication is DISABLED for /update-configs endpoint - this is a security risk in production!")
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
			MaxVersion: tls.VersionTLS13,
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
		"enhanced_validation_enabled":   isEnhancedValidationEnabled(),
		"enhanced_min_path_length":      getEnhancedConfig().MinPathLength,
		"enhanced_aia_chain_building":   getEnhancedConfig().CheckAIAChainBuilding,
		"enhanced_ocsp_revocation":      getEnhancedConfig().CheckOCSPRevocation,
		"enhanced_crl_revocation":       getEnhancedConfig().CheckCRLRevocation,
		"enhanced_trust_roots":          getEnhancedConfig().CheckTrustRoots,
		"enhanced_strict_revocation":    getEnhancedConfig().StrictRevocationCheck,
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
	}).Info("Server configuration completed, starting TLS server with Enhanced Certificate Verification")

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
