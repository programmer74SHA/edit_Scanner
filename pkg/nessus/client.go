package nessus

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

// Client represents a Nessus API client
type Client struct {
	baseURL    string
	httpClient *http.Client
	apiKey     string
	username   string
	password   string
	token      string
}

// NewClient creates a new Nessus client with API key authentication
func NewClient(baseURL, apiKey string) *Client {
	return &Client{
		baseURL:    baseURL,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		apiKey:     apiKey,
	}
}

// NewClientWithCredentials creates a new Nessus client with username/password authentication
func NewClientWithCredentials(baseURL, username, password string) *Client {
	return &Client{
		baseURL:    baseURL,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		username:   username,
		password:   password,
	}
}

// NewClientInsecure creates a new Nessus client with API key authentication and insecure TLS
func NewClientInsecure(baseURL, apiKey string) *Client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	return &Client{
		baseURL:    baseURL,
		httpClient: &http.Client{Timeout: 30 * time.Second, Transport: tr},
		apiKey:     apiKey,
	}
}

// NewClientWithCredentialsInsecure creates a new Nessus client with username/password authentication and insecure TLS
func NewClientWithCredentialsInsecure(baseURL, username, password string) *Client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	return &Client{
		baseURL:    baseURL,
		httpClient: &http.Client{Timeout: 30 * time.Second, Transport: tr},
		username:   username,
		password:   password,
	}
}

// Login authenticates with username/password and gets session token
func (c *Client) Login(ctx context.Context) error {
	if c.username == "" || c.password == "" {
		return fmt.Errorf("username and password required for login")
	}

	loginData := map[string]string{
		"username": c.username,
		"password": c.password,
	}

	resp, err := c.doRequest(ctx, "POST", "/session", loginData, false)
	if err != nil {
		return fmt.Errorf("login failed: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Token string `json:"token"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("failed to decode login response: %w", err)
	}

	c.token = result.Token
	return nil
}

// Logout destroys the session
func (c *Client) Logout(ctx context.Context) error {
	if c.token == "" {
		return nil
	}

	_, err := c.doRequest(ctx, "DELETE", "/session", nil, true)
	c.token = ""
	return err
}

// GetFolders returns the list of scan folders
func (c *Client) GetFolders(ctx context.Context) (*FoldersResponse, error) {
	resp, err := c.doRequest(ctx, "GET", "/folders", nil, true)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result FoldersResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode folders response: %w", err)
	}

	return &result, nil
}

// GetScanners returns the list of scanners
func (c *Client) GetScanners(ctx context.Context) (*ScannersResponse, error) {
	resp, err := c.doRequest(ctx, "GET", "/scanners", nil, true)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result ScannersResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode scanners response: %w", err)
	}

	return &result, nil
}

// GetScans returns the list of scans
func (c *Client) GetScans(ctx context.Context, folderID *int) (*ScansResponse, error) {
	endpoint := "/scans"
	if folderID != nil {
		endpoint += "?folder_id=" + strconv.Itoa(*folderID)
	}

	resp, err := c.doRequest(ctx, "GET", endpoint, nil, true)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result ScansResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode scans response: %w", err)
	}

	return &result, nil
}

// GetScanDetails returns detailed information about a specific scan
func (c *Client) GetScanDetails(ctx context.Context, scanID int, includeHostDetails bool) (*ScanDetails, error) {
	endpoint := fmt.Sprintf("/scans/%d", scanID)
	if includeHostDetails {
		endpoint += "?includeHostDetailsForHostDiscovery=true"
	}

	resp, err := c.doRequest(ctx, "GET", endpoint, nil, true)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result ScanDetails
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode scan details response: %w", err)
	}

	return &result, nil
}

// GetHostDetails returns detailed information about a specific host in a scan
func (c *Client) GetHostDetails(ctx context.Context, scanID, hostID int) (*HostDetails, error) {
	endpoint := fmt.Sprintf("/scans/%d/hosts/%d", scanID, hostID)

	resp, err := c.doRequest(ctx, "GET", endpoint, nil, true)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result HostDetails
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode host details response: %w", err)
	}

	return &result, nil
}

// GetPluginOutput returns the plugin output for a specific host/plugin combination
func (c *Client) GetPluginOutput(ctx context.Context, scanID, hostID, pluginID int) (*PluginOutput, error) {
	endpoint := fmt.Sprintf("/scans/%d/hosts/%d/plugins/%d", scanID, hostID, pluginID)

	resp, err := c.doRequest(ctx, "GET", endpoint, nil, true)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result PluginOutput
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode plugin output response: %w", err)
	}

	return &result, nil
}

// GetPluginDetails returns detailed information about a specific plugin
func (c *Client) GetPluginDetails(ctx context.Context, pluginID int) (*PluginDetails, error) {
	endpoint := fmt.Sprintf("/plugins/plugin/%d", pluginID)

	resp, err := c.doRequest(ctx, "GET", endpoint, nil, true)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result PluginDetails
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode plugin details response: %w", err)
	}

	return &result, nil
}

// doRequest performs HTTP requests with proper authentication
func (c *Client) doRequest(ctx context.Context, method, endpoint string, data interface{}, requireAuth bool) (*http.Response, error) {
	fullURL := c.baseURL + endpoint

	var body io.Reader
	if data != nil {
		jsonData, err := json.Marshal(data)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request data: %w", err)
		}
		body = bytes.NewBuffer(jsonData)
	}

	req, err := http.NewRequestWithContext(ctx, method, fullURL, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	// Add authentication
	if requireAuth {
		if c.apiKey != "" {
			// API Key authentication
			req.Header.Set("X-ApiKeys", fmt.Sprintf("accessKey=%s; secretKey=%s", c.apiKey, c.apiKey))
		} else if c.token != "" {
			// Session token authentication
			req.Header.Set("X-Cookie", fmt.Sprintf("token=%s", c.token))
		} else {
			return nil, fmt.Errorf("no authentication method available")
		}
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	return resp, nil
}
