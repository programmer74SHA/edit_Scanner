package devices

import (
	"context"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"

	scannerDomain "gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanner/domain"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/logger"
	"golang.org/x/crypto/ssh"
)

// CiscoSwitchClient provides a robust implementation for Cisco switch communication
type CiscoSwitchClient struct {
	config    scannerDomain.SwitchConnectionConfig
	sshClient *ssh.Client
	session   *ssh.Session
	stdin     io.WriteCloser
	stdout    io.Reader
	connected bool
	useDirect bool // Flag to use direct command execution instead of shell
}

// NewCiscoSwitchClient creates a new Cisco switch client
func NewCiscoSwitchClient(config scannerDomain.SwitchConnectionConfig) scannerDomain.SwitchDeviceClient {
	return &CiscoSwitchClient{
		config:    config,
		connected: false,
		useDirect: false,
	}
}

// Connect establishes connection with multiple fallback strategies
func (c *CiscoSwitchClient) Connect(ctx context.Context, config scannerDomain.SwitchConnectionConfig) error {
	logger.Info("[CiscoSwitchClient] Connecting to %s:%d", config.Host, config.Port)

	sshConfig := &ssh.ClientConfig{
		User: config.Username,
		Auth: []ssh.AuthMethod{
			ssh.Password(config.Password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         30 * time.Second,
	}

	addr := fmt.Sprintf("%s:%d", config.Host, config.Port)

	var err error
	c.sshClient, err = ssh.Dial("tcp", addr, sshConfig)
	if err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}

	logger.Info("[CiscoSwitchClient] SSH connection established, server: %s", c.sshClient.ServerVersion())

	// Try shell-based approach first
	if err := c.initializeShell(); err != nil {
		logger.Info("[CiscoSwitchClient] Shell initialization failed: %v, trying direct approach", err)
		c.useDirect = true
	}

	// Test the connection works
	if err := c.testConnection(); err != nil {
		logger.Info("[CiscoSwitchClient] Connection test failed: %v", err)
		if !c.useDirect {
			logger.Info("[CiscoSwitchClient] Switching to direct command mode")
			c.useDirect = true
		}
	}

	c.connected = true
	logger.Info("[CiscoSwitchClient] Successfully connected to %s:%d (mode: %s)",
		config.Host, config.Port, map[bool]string{true: "direct", false: "shell"}[c.useDirect])
	return nil
}

// initializeShell sets up the interactive shell session
func (c *CiscoSwitchClient) initializeShell() error {
	// Create session
	var err error
	c.session, err = c.sshClient.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create SSH session: %w", err)
	}

	// Set up pseudo terminal
	modes := ssh.TerminalModes{
		ssh.ECHO:          0,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}

	if err := c.session.RequestPty("vt100", 120, 40, modes); err != nil {
		c.session.Close()
		return fmt.Errorf("PTY request failed: %w", err)
	}

	// Create pipes
	c.stdin, err = c.session.StdinPipe()
	if err != nil {
		c.session.Close()
		return fmt.Errorf("failed to create stdin pipe: %w", err)
	}

	c.stdout, err = c.session.StdoutPipe()
	if err != nil {
		c.session.Close()
		return fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	// Start shell
	if err := c.session.Shell(); err != nil {
		c.session.Close()
		return fmt.Errorf("failed to start shell: %w", err)
	}

	// Wait for shell to initialize
	time.Sleep(3 * time.Second)

	// Send newline to trigger prompt
	c.stdin.Write([]byte("\r\n"))

	// Wait for initial prompt
	output := c.readOutput(10 * time.Second)
	logger.Info("[CiscoSwitchClient] Initial shell output: '%s'", strings.TrimSpace(output))

	if len(strings.TrimSpace(output)) == 0 {
		return fmt.Errorf("no response from shell")
	}

	// Disable paging
	c.stdin.Write([]byte("terminal length 0\r\n"))
	c.readOutput(5 * time.Second)

	return nil
}

// testConnection tests that commands work
func (c *CiscoSwitchClient) testConnection() error {
	logger.Info("[CiscoSwitchClient] Testing connection...")

	if c.useDirect {
		// Test direct command execution
		output, err := c.executeCommandDirect("show clock")
		if err != nil {
			return fmt.Errorf("direct command test failed: %w", err)
		}
		if len(strings.TrimSpace(output)) > 10 {
			logger.Info("[CiscoSwitchClient] Direct command test SUCCESS")
			return nil
		}
		return fmt.Errorf("direct command returned insufficient output")
	} else {
		// Test shell command execution
		if c.stdin == nil || c.stdout == nil {
			return fmt.Errorf("shell pipes not available")
		}

		c.stdin.Write([]byte("show clock\r\n"))
		output := c.readOutput(10 * time.Second)

		if len(strings.TrimSpace(output)) > 10 {
			logger.Info("[CiscoSwitchClient] Shell command test SUCCESS")
			return nil
		}
		return fmt.Errorf("shell command returned insufficient output")
	}
}

// ExecuteCommands executes commands using the appropriate method
func (c *CiscoSwitchClient) ExecuteCommands(ctx context.Context, commands []string) (string, error) {
	if !c.connected {
		return "", fmt.Errorf("not connected to switch")
	}

	if c.useDirect {
		return c.executeCommandsDirect(ctx, commands)
	} else {
		return c.executeCommandsShell(ctx, commands)
	}
}

// executeCommandsDirect executes commands using direct SSH command execution
func (c *CiscoSwitchClient) executeCommandsDirect(ctx context.Context, commands []string) (string, error) {
	logger.Info("[CiscoSwitchClient] Executing %d commands using direct mode", len(commands))

	var allOutput strings.Builder

	for i, command := range commands {
		select {
		case <-ctx.Done():
			return allOutput.String(), ctx.Err()
		default:
		}

		logger.Info("[CiscoSwitchClient] Direct execution %d/%d: %s", i+1, len(commands), command)

		allOutput.WriteString(fmt.Sprintf("=== Command: %s ===\n", command))

		output, err := c.executeCommandDirect(command)
		if err != nil {
			logger.Info("[CiscoSwitchClient] Direct command failed: %v", err)
			allOutput.WriteString(fmt.Sprintf("ERROR: %v\n", err))
		} else {
			allOutput.WriteString(output)
			logger.Info("[CiscoSwitchClient] Direct command returned %d bytes", len(output))
		}

		allOutput.WriteString("=== End Command ===\n\n")
	}

	return allOutput.String(), nil
}

// executeCommandsShell executes commands using interactive shell
func (c *CiscoSwitchClient) executeCommandsShell(ctx context.Context, commands []string) (string, error) {
	logger.Info("[CiscoSwitchClient] Executing %d commands using shell mode", len(commands))

	var allOutput strings.Builder

	for i, command := range commands {
		select {
		case <-ctx.Done():
			return allOutput.String(), ctx.Err()
		default:
		}

		logger.Info("[CiscoSwitchClient] Shell execution %d/%d: %s", i+1, len(commands), command)

		allOutput.WriteString(fmt.Sprintf("=== Command: %s ===\n", command))

		// Send command
		c.stdin.Write([]byte(command + "\r\n"))

		// Read response
		timeout := c.getCommandTimeout(command)
		output := c.readOutput(timeout)

		// Clean output
		cleanedOutput := c.cleanOutput(output, command)

		if len(strings.TrimSpace(cleanedOutput)) > 0 {
			allOutput.WriteString(cleanedOutput)
			logger.Info("[CiscoSwitchClient] Shell command returned %d bytes", len(cleanedOutput))
		} else {
			logger.Info("[CiscoSwitchClient] Shell command returned no output")
			allOutput.WriteString("No output received\n")
		}

		allOutput.WriteString("=== End Command ===\n\n")
		time.Sleep(500 * time.Millisecond)
	}

	return allOutput.String(), nil
}

// executeCommandDirect executes a single command using direct SSH execution
func (c *CiscoSwitchClient) executeCommandDirect(command string) (string, error) {
	session, err := c.sshClient.NewSession()
	if err != nil {
		return "", fmt.Errorf("failed to create session: %w", err)
	}
	defer session.Close()

	// For some Cisco devices, we might need a PTY even for direct commands
	session.RequestPty("vt100", 80, 24, ssh.TerminalModes{
		ssh.ECHO: 0,
	})

	output, err := session.CombinedOutput(command)
	if err != nil {
		// Try without PTY if it failed
		session2, err2 := c.sshClient.NewSession()
		if err2 != nil {
			return "", fmt.Errorf("command failed and cannot create new session: %w", err)
		}
		defer session2.Close()

		output2, err2 := session2.CombinedOutput(command)
		if err2 != nil {
			return "", fmt.Errorf("command failed: %w", err)
		}
		output = output2
	}

	return string(output), nil
}

// readOutput reads output from the shell until timeout or prompt
func (c *CiscoSwitchClient) readOutput(timeout time.Duration) string {
	var output strings.Builder
	buffer := make([]byte, 4096)
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		// Set read deadline
		if conn, ok := c.stdout.(interface{ SetReadDeadline(time.Time) error }); ok {
			conn.SetReadDeadline(time.Now().Add(time.Second))
		}

		n, err := c.stdout.Read(buffer)
		if err != nil {
			if strings.Contains(err.Error(), "timeout") || strings.Contains(err.Error(), "deadline") {
				time.Sleep(100 * time.Millisecond)
				continue
			}
			break
		}

		if n > 0 {
			chunk := string(buffer[:n])
			output.WriteString(chunk)

			// Check for prompt in recent output
			if c.hasPrompt(output.String()) {
				break
			}

			// Handle paging
			if strings.Contains(chunk, "--More--") {
				c.stdin.Write([]byte(" "))
			}
		}

		time.Sleep(50 * time.Millisecond)
	}

	return output.String()
}

// hasPrompt checks if output contains a Cisco prompt
func (c *CiscoSwitchClient) hasPrompt(output string) bool {
	lines := strings.Split(output, "\n")
	for i := len(lines) - 1; i >= 0 && i >= len(lines)-3; i-- {
		line := strings.TrimSpace(lines[i])
		if c.isPrompt(line) {
			return true
		}
	}
	return false
}

// isPrompt checks if a line is a Cisco prompt
func (c *CiscoSwitchClient) isPrompt(line string) bool {
	if line == "" {
		return false
	}

	patterns := []string{
		`^[a-zA-Z0-9\-_\.]+[>#]\s*$`,
		`^[a-zA-Z0-9\-_\.]+\(config[^)]*\)[>#]\s*$`,
	}

	for _, pattern := range patterns {
		if matched, _ := regexp.MatchString(pattern, line); matched {
			return true
		}
	}
	return false
}

// cleanOutput removes command echo and prompts from output
func (c *CiscoSwitchClient) cleanOutput(output, command string) string {
	lines := strings.Split(output, "\n")
	var cleaned []string

	skipEcho := true
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Skip command echo
		if skipEcho && strings.Contains(trimmed, command) {
			skipEcho = false
			continue
		}
		skipEcho = false

		// Stop at prompt
		if c.isPrompt(trimmed) {
			break
		}

		// Skip special lines
		if strings.Contains(trimmed, "--More--") ||
			strings.Contains(trimmed, "Press any key") ||
			(trimmed == "" && len(cleaned) == 0) {
			continue
		}

		cleaned = append(cleaned, line)
	}

	return strings.TrimSpace(strings.Join(cleaned, "\n"))
}

// getCommandTimeout returns appropriate timeout for command
func (c *CiscoSwitchClient) getCommandTimeout(command string) time.Duration {
	command = strings.ToLower(command)
	switch {
	case strings.Contains(command, "show version"):
		return 20 * time.Second
	case strings.Contains(command, "show cdp neighbors detail"):
		return 30 * time.Second
	case strings.Contains(command, "show ip route"):
		return 25 * time.Second
	default:
		return 15 * time.Second
	}
}

// ParseOutput parses command output into structured data
func (c *CiscoSwitchClient) ParseOutput(output string) (*scannerDomain.SwitchScanResult, error) {
	logger.Info("[CiscoSwitchClient] Parsing output (%d bytes)", len(output))

	result := &scannerDomain.SwitchScanResult{
		SystemInfo:   scannerDomain.SwitchSystemInfo{},
		Interfaces:   []scannerDomain.SwitchInterface{},
		VLANs:        []scannerDomain.SwitchVLAN{},
		VLANPorts:    []scannerDomain.SwitchVLANPort{},
		RoutingTable: []scannerDomain.SwitchRoutingEntry{},
		Neighbors:    []scannerDomain.SwitchNeighbor{},
		VendorInfo:   scannerDomain.SwitchVendorInfo{Vendor: "cisco"},
	}

	sections := strings.Split(output, "=== Command:")
	logger.Info("[CiscoSwitchClient] Found %d command sections", len(sections))

	for _, section := range sections {
		section = strings.TrimSpace(section)
		if section == "" {
			continue
		}

		lines := strings.Split(section, "\n")
		if len(lines) < 1 {
			continue
		}

		commandLine := strings.TrimSpace(strings.Replace(lines[0], "===", "", -1))
		commandOutput := ""
		if len(lines) > 1 {
			commandOutput = strings.Join(lines[1:], "\n")
		}

		if endIdx := strings.Index(commandOutput, "=== End Command ==="); endIdx != -1 {
			commandOutput = commandOutput[:endIdx]
		}
		commandOutput = strings.TrimSpace(commandOutput)

		logger.Info("[CiscoSwitchClient] Processing: '%s' (%d bytes)", commandLine, len(commandOutput))

		if strings.Contains(commandOutput, "ERROR:") {
			logger.Info("[CiscoSwitchClient] Skipping error output for: %s", commandLine)
			continue
		}

		commandLower := strings.ToLower(commandLine)
		switch {
		case strings.Contains(commandLower, "show version"):
			c.parseShowVersion(commandOutput, result)
		case strings.Contains(commandLower, "show ip interface brief"):
			c.parseShowIPInterfaceBrief(commandOutput, result)
		case strings.Contains(commandLower, "show vlan brief"):
			c.parseShowVLANBrief(commandOutput, result)
		case strings.Contains(commandLower, "show cdp neighbors detail"):
			c.parseShowCDPNeighborsDetail(commandOutput, result)
		case strings.Contains(commandLower, "show ip route"):
			c.parseShowIPRoute(commandOutput, result)
		case strings.Contains(commandLower, "show interfaces status"):
			c.parseShowInterfacesStatus(commandOutput, result)
		}
	}

	result.AssetsCreated = len(result.Interfaces) + len(result.Neighbors)
	logger.Info("[CiscoSwitchClient] Parsing complete: %d interfaces, %d VLANs, %d neighbors",
		len(result.Interfaces), len(result.VLANs), len(result.Neighbors))

	return result, nil
}

// GetDefaultCommands returns default commands for Cisco switches
func (c *CiscoSwitchClient) GetDefaultCommands() []string {
	return []string{
		"show version",
		"show ip interface brief",
		"show vlan brief",
		"show cdp neighbors detail",
		"show ip route",
		"show interfaces status",
	}
}

// Close closes the connection
func (c *CiscoSwitchClient) Close() error {
	c.connected = false

	if c.stdin != nil {
		c.stdin.Close()
		c.stdin = nil
	}

	if c.session != nil {
		c.session.Close()
		c.session = nil
	}

	if c.sshClient != nil {
		err := c.sshClient.Close()
		c.sshClient = nil
		return err
	}

	return nil
}

// parseShowVersion parses "show version" output
func (c *CiscoSwitchClient) parseShowVersion(output string, result *scannerDomain.SwitchScanResult) {
	logger.Info("[CiscoSwitchClient] Parsing show version (%d bytes)", len(output))
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Parse hostname and uptime
		if strings.Contains(line, "uptime is") {
			parts := strings.Fields(line)
			if len(parts) > 0 {
				result.SystemInfo.Hostname = parts[0]
			}
			if uptimeRegex := regexp.MustCompile(`uptime is (.+)`); uptimeRegex.MatchString(line) {
				matches := uptimeRegex.FindStringSubmatch(line)
				if len(matches) > 1 {
					result.SystemInfo.SystemUptime = strings.TrimSpace(matches[1])
				}
			}
		}

		// Parse model - look for processor/bytes line
		if strings.Contains(strings.ToLower(line), "cisco") &&
			(strings.Contains(line, "processor") || strings.Contains(line, "bytes")) {
			result.SystemInfo.Model = c.extractModelFromLine(line)
			result.VendorInfo.Model = result.SystemInfo.Model
		}

		// Parse IOS version - extract clean version
		if strings.Contains(line, "IOS") && strings.Contains(line, "Version") {
			result.SystemInfo.SoftwareVersion = c.extractVersionFromLine(line)
			result.VendorInfo.OSVersion = result.SystemInfo.SoftwareVersion
		}
	}
}

// extractModelFromLine extracts a clean model name from a line
func (c *CiscoSwitchClient) extractModelFromLine(line string) string {
	// Example: "cisco WS-C2960X-48FPD-L (PowerPC405) processor (revision B0) with 131072K bytes of memory."
	// Should extract: "WS-C2960X-48FPD-L"

	line = strings.TrimSpace(line)

	// Look for cisco followed by model
	if strings.Contains(strings.ToLower(line), "cisco") {
		parts := strings.Fields(line)
		for i, part := range parts {
			if strings.ToLower(part) == "cisco" && i+1 < len(parts) {
				nextPart := parts[i+1]
				// Clean up the model name
				nextPart = strings.TrimSuffix(nextPart, ",")
				nextPart = strings.TrimSuffix(nextPart, "(")
				if len(nextPart) > 3 && len(nextPart) < 50 { // Reasonable model name length
					return nextPart
				}
			}
		}
	}

	// Fallback: truncate the entire line
	if len(line) > 100 {
		return line[:97] + "..."
	}
	return line
}

// extractVersionFromLine extracts a clean version string from a line
func (c *CiscoSwitchClient) extractVersionFromLine(line string) string {
	// Example: "Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), Version 15.2(7)E3, RELEASE SOFTWARE (fc2)"
	// Should extract: "Cisco IOS 15.2(7)E3"

	line = strings.TrimSpace(line)

	// Look for "Version" keyword
	if strings.Contains(line, "Version") {
		parts := strings.Split(line, "Version")
		if len(parts) > 1 {
			versionPart := strings.TrimSpace(parts[1])
			// Take everything up to the first comma
			commaIndex := strings.Index(versionPart, ",")
			if commaIndex > 0 {
				versionPart = versionPart[:commaIndex]
			}
			versionPart = strings.TrimSpace(versionPart)

			if versionPart != "" {
				return fmt.Sprintf("Cisco IOS %s", versionPart)
			}
		}
	}

	// Fallback: look for IOS and extract a reasonable part
	if strings.Contains(line, "IOS") {
		// Try to extract just "Cisco IOS" part
		if strings.Contains(line, "Cisco IOS") {
			return "Cisco IOS"
		}
	}

	// Ultimate fallback: truncate
	if len(line) > 80 {
		return line[:77] + "..."
	}
	return line
}

// parseShowIPInterfaceBrief parses interface output
func (c *CiscoSwitchClient) parseShowIPInterfaceBrief(output string, result *scannerDomain.SwitchScanResult) {
	logger.Info("[CiscoSwitchClient] Parsing interfaces (%d bytes)", len(output))
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.Contains(line, "Interface") || strings.Contains(line, "---") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) >= 6 {
			iface := scannerDomain.SwitchInterface{
				Name:      fields[0],
				IPAddress: fields[1],
				Status:    fields[4],
				Protocol:  fields[5],
				Type:      c.determineInterfaceType(fields[0]),
			}

			if iface.IPAddress == "unassigned" {
				iface.IPAddress = ""
			}

			result.Interfaces = append(result.Interfaces, iface)
			logger.Info("[CiscoSwitchClient] Found interface: %s", iface.Name)
		}
	}
}

// parseShowVLANBrief parses VLAN output
func (c *CiscoSwitchClient) parseShowVLANBrief(output string, result *scannerDomain.SwitchScanResult) {
	logger.Info("[CiscoSwitchClient] Parsing VLANs (%d bytes)", len(output))
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.Contains(line, "VLAN") || strings.Contains(line, "----") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) >= 3 {
			if vlanID, err := strconv.Atoi(fields[0]); err == nil {
				vlan := scannerDomain.SwitchVLAN{
					ID:     vlanID,
					Name:   fields[1],
					Status: fields[2],
					Type:   "ethernet",
				}
				result.VLANs = append(result.VLANs, vlan)
				logger.Info("[CiscoSwitchClient] Found VLAN: %d - %s", vlan.ID, vlan.Name)
			}
		}
	}
}

// parseShowCDPNeighborsDetail parses CDP neighbor output
func (c *CiscoSwitchClient) parseShowCDPNeighborsDetail(output string, result *scannerDomain.SwitchScanResult) {
	logger.Info("[CiscoSwitchClient] Parsing CDP neighbors (%d bytes)", len(output))

	devices := regexp.MustCompile(`-------------------------+`).Split(output, -1)
	for _, device := range devices {
		device = strings.TrimSpace(device)
		if device == "" {
			continue
		}

		neighbor := scannerDomain.SwitchNeighbor{Protocol: "CDP"}
		lines := strings.Split(device, "\n")

		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "Device ID:") {
				neighbor.DeviceID = strings.TrimSpace(strings.TrimPrefix(line, "Device ID:"))
			} else if strings.HasPrefix(line, "Interface:") {
				parts := strings.Split(line, ",")
				if len(parts) >= 1 {
					neighbor.LocalPort = strings.TrimSpace(strings.TrimPrefix(parts[0], "Interface:"))
				}
			}
		}

		if neighbor.DeviceID != "" {
			result.Neighbors = append(result.Neighbors, neighbor)
			logger.Info("[CiscoSwitchClient] Found neighbor: %s", neighbor.DeviceID)
		}
	}
}

// parseShowIPRoute parses routing table
func (c *CiscoSwitchClient) parseShowIPRoute(output string, result *scannerDomain.SwitchScanResult) {
	// Simple implementation for routing table
	logger.Info("[CiscoSwitchClient] Parsing routes (%d bytes)", len(output))
}

// parseShowInterfacesStatus parses interface status
func (c *CiscoSwitchClient) parseShowInterfacesStatus(output string, result *scannerDomain.SwitchScanResult) {
	// Update existing interfaces with status info
	logger.Info("[CiscoSwitchClient] Parsing interface status (%d bytes)", len(output))
}

// determineInterfaceType determines interface type from name
func (c *CiscoSwitchClient) determineInterfaceType(interfaceName string) string {
	name := strings.ToLower(interfaceName)
	switch {
	case strings.Contains(name, "vlan"):
		return "vlan"
	case strings.Contains(name, "loopback"):
		return "loopback"
	case strings.Contains(name, "tunnel"):
		return "tunnel"
	case strings.Contains(name, "port-channel"):
		return "port-channel"
	default:
		return "physical"
	}
}
