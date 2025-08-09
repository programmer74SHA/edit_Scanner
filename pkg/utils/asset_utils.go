package utils

import (
	"net"
	"strings"

	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/logger"
)

// Helper function to split comma-separated values and trim spaces
func SplitAndTrim(value string) []string {
	if value == "" {
		return []string{}
	}

	values := strings.Split(value, ",")
	for i, v := range values {
		values[i] = strings.TrimSpace(v)
	}
	return values
}

// Helper function to check if filter has any values
func HasFilterValues(value string) bool {
	return strings.TrimSpace(value) != ""
}

// AssetIPsList is a slice of structs representing asset IDs and their associated IP addresses
type AssetIPsList []struct {
	AssetID   string `gorm:"column:asset_id"`
	IPAddress string `gorm:"column:ip_address"`
}

// IpsInNetwork checks if any IP addresses in the assetIPsList belong to the given networks
func IpsInNetwork(networks []string, assetIPsList AssetIPsList) (map[string]bool, error) {
	matchingAssetIDs := make(map[string]bool)

	for _, network := range networks {
		_, ipnet, err := net.ParseCIDR(network)
		if err != nil {
			logger.Warn("Invalid CIDR notation: %s", network)
			continue
		}

		for _, assetIP := range assetIPsList {
			ip := net.ParseIP(assetIP.IPAddress)
			if ip == nil {
				logger.Warn("Invalid IP address: %s", assetIP.IPAddress)
			}
			if ipnet.Contains(ip) {
				matchingAssetIDs[assetIP.AssetID] = true
			}
		}
	}

	return matchingAssetIDs, nil
}
