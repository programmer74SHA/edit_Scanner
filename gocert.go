package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/go-logr/logr"
	"github.com/go-logr/stdr"
	"golang.org/x/crypto/ocsp"
)

// OID constants
var (
	OIDCodeSigning = "1.3.6.1.5.5.7.3.3"
	OIDServerAuth  = "1.3.6.1.5.5.7.3.1"
	OIDClientAuth  = "1.3.6.1.5.5.7.3.2"
	OIDOCSPSigning = "1.3.6.1.5.5.7.3.9"
	usageOIDs      = map[string]string{
		"code_signing": OIDCodeSigning,
		"server_auth":  OIDServerAuth,
		"client_auth":  OIDClientAuth,
		"ocsp_signing": OIDOCSPSigning,
	}
	oidToExtKeyUsage = map[string]x509.ExtKeyUsage{
		OIDCodeSigning: x509.ExtKeyUsageCodeSigning,
		OIDServerAuth:  x509.ExtKeyUsageServerAuth,
		OIDClientAuth:  x509.ExtKeyUsageClientAuth,
		OIDOCSPSigning: x509.ExtKeyUsageOCSPSigning,
	}
)

// Logger setup
func initLogger() logr.Logger {
	logger := stdr.New(log.New(os.Stdout, "", log.LstdFlags))
	logger = logger.WithName("certverifier")
	return logger
}

// Utility functions
func loadCertFromDEROrPEM(data []byte) (*x509.Certificate, error) {
	cert, err := x509.ParseCertificate(data)
	if err == nil {
		return cert, nil
	}
	// Try PEM
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to parse certificate: not DER or PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}

func fetchURLBytes(url string, timeout time.Duration, logger logr.Logger) ([]byte, error) {
	logger.V(1).Info("Fetching URL", "url", url)
	client := &http.Client{Timeout: timeout}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP status %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

func parseAIAIssuerURLs(cert *x509.Certificate) []string {
	urls := []string{}
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1}) { // AuthorityInformationAccess
			var aia []struct {
				ID  asn1.ObjectIdentifier
				URL string `asn1:"tag:6"`
			}
			_, err := asn1.Unmarshal(ext.Value, &aia)
			if err != nil {
				continue
			}
			for _, entry := range aia {
				if entry.ID.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 2}) && len(entry.URL) > 0 && entry.URL[:4] == "http" {
					urls = append(urls, entry.URL)
				}
			}
		}
	}
	return urls
}

func parseOCSPURLs(cert *x509.Certificate) []string {
	urls := []string{}
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1}) {
			var aia []struct {
				ID  asn1.ObjectIdentifier
				URL string `asn1:"tag:6"`
			}
			_, err := asn1.Unmarshal(ext.Value, &aia)
			if err != nil {
				continue
			}
			for _, entry := range aia {
				if entry.ID.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1}) && len(entry.URL) > 0 && entry.URL[:4] == "http" {
					urls = append(urls, entry.URL)
				}
			}
		}
	}
	return urls
}

func parseCRLDistributionPoints(cert *x509.Certificate) []string {
	urls := []string{}
	for _, url := range cert.CRLDistributionPoints {
		if len(url) > 0 && url[:4] == "http" {
			urls = append(urls, url)
		}
	}
	return urls
}

func isSelfSigned(cert *x509.Certificate) bool {
	return cert.Subject.String() == cert.Issuer.String()
}

func verifySignature(child, issuer *x509.Certificate, logger logr.Logger) bool {
	err := child.CheckSignatureFrom(issuer)
	if err != nil {
		logger.Error(err, "Signature verification failed", "child", child.Subject.String(), "issuer", issuer.Subject.String())
		return false
	}
	return true
}

// Chain building
func buildChainFromLeaf(leafCert *x509.Certificate, maxHops int, logger logr.Logger) ([]*x509.Certificate, error) {
	chain := []*x509.Certificate{leafCert}
	current := leafCert
	hops := 0

	for hops < maxHops {
		hops++
		if isSelfSigned(current) {
			logger.V(1).Info("Reached self-signed cert in chain")
			break
		}
		issuerURLs := parseAIAIssuerURLs(current)
		foundIssuer := false
		for _, url := range issuerURLs {
			data, err := fetchURLBytes(url, 10*time.Second, logger)
			if err != nil {
				logger.V(1).Info("Failed to fetch issuer", "url", url, "error", err)
				continue
			}
			cert, err := loadCertFromDEROrPEM(data)
			if err != nil {
				logger.V(1).Info("Failed to parse issuer cert", "url", url, "error", err)
				continue
			}
			if cert.Subject.String() == current.Issuer.String() {
				chain = append(chain, cert)
				current = cert
				foundIssuer = true
				logger.V(1).Info("Fetched issuer cert", "url", url, "subject", cert.Subject.String())
				break
			}
		}
		if !foundIssuer {
			logger.V(1).Info("No issuer fetched via AIA; stopping chain build")
			break
		}
	}
	return chain, nil
}

// Trust root detection
func loadSystemTrustRoots(logger logr.Logger) (*x509.CertPool, error) {
	pool, err := x509.SystemCertPool()
	if err != nil {
		return nil, err
	}
	logger.V(1).Info("Loaded system trust roots", "count", len(pool.Subjects()))
	return pool, nil
}

func isTrustedTopCert(cert *x509.Certificate, trustRoots *x509.CertPool) bool {
	opts := x509.VerifyOptions{Roots: trustRoots}
	_, err := cert.Verify(opts)
	return err == nil
}

// Extended Key Usage checks
func checkExtendedKeyUsage(cert *x509.Certificate, requiredOID string) bool {
	expectedUsage, ok := oidToExtKeyUsage[requiredOID]
	if !ok {
		return false
	}
	for _, usage := range cert.ExtKeyUsage {
		if usage == expectedUsage {
			return true
		}
	}
	return false
}

// Revocation checks
func checkCRLRevocation(cert *x509.Certificate, logger logr.Logger) *bool {
	dpURLs := parseCRLDistributionPoints(cert)
	if len(dpURLs) == 0 {
		logger.V(1).Info("No CRL distribution points found")
		return nil
	}
	for _, url := range dpURLs {
		data, err := fetchURLBytes(url, 10*time.Second, logger)
		if err != nil {
			logger.V(1).Info("Fetching CRL failed", "url", url, "error", err)
			continue
		}
		crl, err := x509.ParseCRL(data)
		if err != nil {
			logger.V(1).Info("Parsing CRL failed", "url", url, "error", err)
			continue
		}
		for _, revoked := range crl.TBSCertList.RevokedCertificates {
			if revoked.SerialNumber.Cmp(cert.SerialNumber) == 0 {
				logger.Info("Certificate revoked according to CRL", "url", url)
				return boolPtr(true)
			}
		}
		logger.V(1).Info("Certificate not found in CRL", "url", url)
		return boolPtr(false)
	}
	return nil
}

func checkOCSPRevocation(cert, issuer *x509.Certificate, logger logr.Logger) *bool {
	ocspURLs := parseOCSPURLs(cert)
	if len(ocspURLs) == 0 {
		logger.V(1).Info("No OCSP URLs in AIA")
		return nil
	}
	ocspReq, err := ocsp.CreateRequest(cert, issuer, nil)
	if err != nil {
		logger.V(1).Info("Failed to create OCSP request", "error", err)
		return nil
	}
	for _, url := range ocspURLs {
		req, err := http.NewRequest("POST", url, nil)
		if err != nil {
			logger.V(1).Info("Failed to create OCSP HTTP request", "url", url, "error", err)
			continue
		}
		req.Header.Set("Content-Type", "application/ocsp-request")
		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Post(url, "application/ocsp-request", bytes.NewReader(ocspReq))
		if err != nil {
			logger.V(1).Info("OCSP check failed", "url", url, "error", err)
			continue
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			logger.V(1).Info("Failed to read OCSP response", "url", url, "error", err)
			continue
		}
		ocspResp, err := ocsp.ParseResponse(body, issuer)
		if err != nil {
			logger.V(1).Info("Failed to parse OCSP response", "url", url, "error", err)
			continue
		}
		switch ocspResp.Status {
		case ocsp.Good:
			logger.V(1).Info("OCSP responder reports GOOD", "url", url)
			return boolPtr(false)
		case ocsp.Revoked:
			logger.Info("OCSP responder reports REVOKED", "url", url)
			return boolPtr(true)
		default:
			logger.V(1).Info("OCSP responder returned unknown status", "url", url, "status", ocspResp.Status)
			return nil
		}
	}
	return nil
}

func boolPtr(b bool) *bool {
	return &b
}

// CertificateVerifier struct
type CertificateVerifier struct {
	MinPathLength int
	TrustRoots    *x509.CertPool
	Logger        logr.Logger
}

func NewCertificateVerifier(minPathLength int) *CertificateVerifier {
	logger := initLogger()
	pool, err := loadSystemTrustRoots(logger)
	if err != nil {
		logger.Error(err, "Failed to load system trust roots")
		return nil
	}
	return &CertificateVerifier{
		MinPathLength: minPathLength,
		TrustRoots:    pool,
		Logger:        logger,
	}
}

func (v *CertificateVerifier) VerifyChainRules(chain []*x509.Certificate, intendedUsageOID *string) bool {
	v.Logger.Info("Verifying chain rules", "chain_length", len(chain))
	if len(chain) < v.MinPathLength {
		v.Logger.Error(nil, "Chain too short", "length", len(chain), "min_required", v.MinPathLength)
		return false
	}

	// Signature and basicConstraints checks
	for i := 0; i < len(chain)-1; i++ {
		child := chain[i]
		issuer := chain[i+1]
		if !verifySignature(child, issuer, v.Logger) {
			v.Logger.Error(nil, "Signature verification failed", "child", child.Subject.String(), "issuer", issuer.Subject.String())
			return false
		}
		if !issuer.IsCA {
			v.Logger.Error(nil, "Issuer basicConstraints CA flag is not True", "issuer", issuer.Subject.String())
			return false
		}
	}

	// Check top cert
	top := chain[len(chain)-1]
	if !isSelfSigned(top) {
		v.Logger.Info("Top certificate is not self-signed")
	}
	if !isTrustedTopCert(top, v.TrustRoots) {
		v.Logger.Error(nil, "Top certificate is not a trusted root")
		return false
	}

	// Check EKU on leaf
	if intendedUsageOID != nil {
		leaf := chain[0]
		if !checkExtendedKeyUsage(leaf, *intendedUsageOID) {
			v.Logger.Error(nil, "Leaf certificate missing required EKU OID", "oid", *intendedUsageOID)
			return false
		}
	}

	v.Logger.Info("Chain rules verification succeeded")
	return true
}

func (v *CertificateVerifier) CheckRevocationForChain(chain []*x509.Certificate) bool {
	for i := 0; i < len(chain)-1; i++ {
		cert := chain[i]
		issuer := chain[i+1]
		v.Logger.Info("Checking revocation", "subject", cert.Subject.String())
		ocspStatus := checkOCSPRevocation(cert, issuer, v.Logger)
		if ocspStatus != nil && *ocspStatus {
			v.Logger.Error(nil, "Cert revoked via OCSP")
			return true
		} else if ocspStatus != nil && !*ocspStatus {
			v.Logger.V(1).Info("OCSP reports cert good")
			continue
		}
		crlStatus := checkCRLRevocation(cert, v.Logger)
		if crlStatus != nil && *crlStatus {
			v.Logger.Error(nil, "Cert revoked via CRL")
			return true
		} else if crlStatus != nil && !*crlStatus {
			v.Logger.V(1).Info("CRL reports cert not revoked")
			continue
		}
		v.Logger.Error(nil, "Unable to determine revocation status; strict mode -> fail")
		return true
	}
	return false
}

func (v *CertificateVerifier) VerifyRemoteTLS(host string, port int, intendedUsage string, timeout time.Duration) bool {
	intendedOID, ok := usageOIDs[intendedUsage]
	if !ok {
		v.Logger.Error(nil, "Invalid intended usage", "usage", intendedUsage)
		return false
	}
	v.Logger.Info("Starting TLS verify", "host", host, "port", port, "usage", intendedUsage)

	// Get leaf cert
	config := &tls.Config{InsecureSkipVerify: true}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", fmt.Sprintf("%s:%d", host, port), config)
	if err != nil {
		v.Logger.Error(err, "Failed to connect and fetch cert")
		return false
	}
	defer conn.Close()
	leaf := conn.ConnectionState().PeerCertificates[0]

	chain, err := buildChainFromLeaf(leaf, 10, v.Logger)
	if err != nil || len(chain) == 0 {
		v.Logger.Error(err, "Failed to build chain or empty chain")
		return false
	}

	if !v.VerifyChainRules(chain, &intendedOID) {
		v.Logger.Error(nil, "Chain rule verification failed")
		return false
	}

	if v.CheckRevocationForChain(chain) {
		v.Logger.Error(nil, "Revocation check failed")
		return false
	}

	v.Logger.Info("TLS certificate verification succeeded", "host", host, "port", port)
	return true
}

func main() {
	verifier := NewCertificateVerifier(3)
	targets := [][3]interface{}{
		{"192.168.166.12", 5601, "server_auth"},
	}
	for _, target := range targets {
		host := target[0].(string)
		port := target[1].(int)
		usage := target[2].(string)
		start := time.Now()
		ok := verifier.VerifyRemoteTLS(host, port, usage, 10*time.Second)
		duration := time.Since(start)
		verifier.Logger.Info("Verification result", "host", host, "port", port, "ok", ok, "duration", duration.Seconds())
	}
}
