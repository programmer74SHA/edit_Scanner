package devices

import (
	"fmt"
	"strings"

	scannerDomain "gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanner/domain"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/logger"
)

// SwitchDeviceClientFactory creates appropriate device clients based on device type
type SwitchDeviceClientFactory struct{}

// NewSwitchDeviceClientFactory creates a new switch device client factory
func NewSwitchDeviceClientFactory() scannerDomain.SwitchDeviceClientFactory {
	return &SwitchDeviceClientFactory{}
}

// CreateClient creates a device client based on the device type
func (f *SwitchDeviceClientFactory) CreateClient(deviceType string, config scannerDomain.SwitchConnectionConfig) (scannerDomain.SwitchDeviceClient, error) {
	deviceType = strings.ToLower(strings.TrimSpace(deviceType))

	switch deviceType {
	case "cisco":
		logger.Info("[SwitchDeviceClientFactory] Creating Cisco client for device: %s", config.Host)
		return NewCiscoSwitchClient(config), nil

	case "juniper":
		logger.Info("[SwitchDeviceClientFactory] Creating Juniper client for device: %s (using generic Cisco-compatible implementation)", config.Host)
		// For now, use Cisco client as it may work with some Juniper devices
		// TODO: Implement dedicated Juniper client when needed
		return NewCiscoSwitchClient(config), nil

	case "huawei":
		logger.Info("[SwitchDeviceClientFactory] Creating Huawei client for device: %s (using generic implementation)", config.Host)
		// TODO: Implement dedicated Huawei client when needed
		return NewCiscoSwitchClient(config), nil

	default:
		if deviceType == "" {
			logger.Info("[SwitchDeviceClientFactory] No device type specified, defaulting to Cisco client for device: %s", config.Host)
		} else {
			logger.Info("[SwitchDeviceClientFactory] Unknown device type '%s', using Cisco client for device: %s", deviceType, config.Host)
		}
		return NewCiscoSwitchClient(config), nil
	}
}

// GetSupportedDeviceTypes returns a list of supported device types
func (f *SwitchDeviceClientFactory) GetSupportedDeviceTypes() []string {
	return []string{
		"cisco",
		"juniper", // Uses generic implementation
		"huawei",  // Uses generic implementation
	}
}

// ValidateDeviceType checks if a device type is supported
func (f *SwitchDeviceClientFactory) ValidateDeviceType(deviceType string) error {
	if deviceType == "" {
		return nil // Empty device type defaults to Cisco
	}

	deviceType = strings.ToLower(strings.TrimSpace(deviceType))
	supportedTypes := f.GetSupportedDeviceTypes()

	for _, supportedType := range supportedTypes {
		if deviceType == supportedType {
			return nil
		}
	}

	// Don't return error for unknown types, just use default
	logger.Info("[SwitchDeviceClientFactory] Device type '%s' not explicitly supported, will use default implementation", deviceType)
	return nil
}

// CreateClientWithValidation creates a client with device type validation
func (f *SwitchDeviceClientFactory) CreateClientWithValidation(deviceType string, config scannerDomain.SwitchConnectionConfig) (scannerDomain.SwitchDeviceClient, error) {
	if err := f.ValidateDeviceType(deviceType); err != nil {
		return nil, fmt.Errorf("invalid device type: %w", err)
	}

	return f.CreateClient(deviceType, config)
}
