package http

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/gofiber/fiber/v2"
	jwt2 "github.com/golang-jwt/jwt/v5"
	"gitlab.apk-group.net/siem/backend/asset-discovery/api/pb"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/jwt"
)

func userClaims(ctx *fiber.Ctx) *jwt.UserClaims {
	if u := ctx.Locals("user"); u != nil {
		userClaims, ok := u.(*jwt2.Token).Claims.(*jwt.UserClaims)
		if ok {
			return userClaims
		}
	}

	return nil
}

type ServiceGetter[T any] func(context.Context) T

// extractSorts processes the sort parameters from fiber.Ctx queries
// If no sort parameters are provided, it returns a default sort by created_at desc
func extractSorts(queries map[string]string) []*pb.SortField {
	var sorts []*pb.SortField
	hasSortParams := false

	for key, value := range queries {
		if !strings.HasPrefix(key, "sort[") || !strings.Contains(key, "][") {
			continue
		}

		hasSortParams = true

		indexEnd := strings.Index(key, "][")
		if indexEnd <= 5 {
			continue
		}

		indexStr := key[5:indexEnd]
		fieldType := key[indexEnd+2 : len(key)-1]

		index, err := strconv.Atoi(indexStr)
		if err != nil || index < 0 {
			continue
		}

		for len(sorts) <= index {
			sorts = append(sorts, &pb.SortField{
				Field: "created_at",
				Order: "desc",
			})
		}

		if fieldType == "field" {
			sorts[index].Field = value
		} else if fieldType == "order" && (value == "asc" || value == "desc") {
			sorts[index].Order = value
		}
	}

	// Set default sort if no sort parameters were provided
	if !hasSortParams {
		sorts = append(sorts, &pb.SortField{
			Field: "created_at",
			Order: "desc",
		})
	}

	return sorts
}

// extractAssetFilters processes the asset filter parameters from fiber.Ctx queries
func extractAssetFilters(queries map[string]string) *pb.Filter {
	filter := &pb.Filter{}

	for key, value := range queries {
		if !strings.HasPrefix(key, "filter[") || !strings.HasSuffix(key, "]") || len(key) <= 8 {
			continue
		}

		fieldName := key[7 : len(key)-1]

		switch fieldName {
		case "name":
			filter.Name = value
		case "domain":
			filter.Domain = value
		case "hostname":
			filter.Hostname = value
		case "os_name":
			filter.OsName = value
		case "os_version":
			filter.OsVersion = value
		case "type":
			filter.Type = value
		case "ip":
			filter.Ip = value
		case "scanner_type":
			filter.ScannerType = value
		case "network":
			filter.Network = value
		}
	}

	return filter
}

// extractScanJobFilters processes the scan jobs filter parameters from fiber.Ctx queries
func extractScanJobFilters(queries map[string]string) *pb.ScanJobFilter {
	filter := &pb.ScanJobFilter{}

	for key, value := range queries {
		if !strings.HasPrefix(key, "filter[") || !strings.HasSuffix(key, "]") || len(key) <= 8 {
			continue
		}

		fieldName := key[7 : len(key)-1]

		switch fieldName {
		case "name":
			filter.Name = value
		case "status":
			filter.Status = value
		case "start_time_from":
			filter.StartTimeFrom = value
		case "start_time_to":
			filter.StartTimeTo = value
		case "type":
			filter.Type = value
		}
	}

	return filter
}

// extractDiffJobSorts processes sort parameters for diff jobs with asset-specific fields
func extractDiffJobSorts(queries map[string]string) []*pb.SortField {
	var sorts []*pb.SortField
	hasSortParams := false

	// Valid sort fields for assets in diff jobs
	validFields := map[string]bool{
		"name":       true,
		"ip_address": true,
		"domain":     true,
		"asset_type": true,
		"os_name":    true,
	}

	for key, value := range queries {
		if !strings.HasPrefix(key, "sort[") || !strings.Contains(key, "][") {
			continue
		}

		hasSortParams = true

		indexEnd := strings.Index(key, "][")
		if indexEnd <= 5 {
			continue
		}

		indexStr := key[5:indexEnd]
		fieldType := key[indexEnd+2 : len(key)-1]

		index, err := strconv.Atoi(indexStr)
		if err != nil || index < 0 {
			continue
		}

		for len(sorts) <= index {
			sorts = append(sorts, &pb.SortField{
				Field: "name",
				Order: "asc",
			})
		}

		if fieldType == "field" {
			if validFields[value] {
				sorts[index].Field = value
			} else {
			}
		} else if fieldType == "order" && (value == "asc" || value == "desc") {
			sorts[index].Order = value
		}
	}

	// Set default sort if no sort parameters were provided
	if !hasSortParams {
		sorts = append(sorts, &pb.SortField{
			Field: "name",
			Order: "asc",
		})
	}

	return sorts
}

// transformGetAssetsResponse transforms the standard asset response
func transformGetAssetsResponse(response *pb.GetAssetsResponse) map[string]interface{} {
	result := map[string]interface{}{
		"count": response.Count,
	}

	// Transform contents
	contents := make([]map[string]interface{}, 0, len(response.Contents))
	for _, asset := range response.Contents {
		assetMap := make(map[string]interface{})

		assetMap["id"] = asset.Id
		assetMap["name"] = asset.Name
		assetMap["domain"] = asset.Domain
		assetMap["hostname"] = asset.Hostname
		assetMap["os_name"] = asset.OsName
		assetMap["os_version"] = asset.OsVersion
		assetMap["asset_type"] = asset.Type
		assetMap["description"] = asset.Description
		assetMap["created_at"] = asset.CreatedAt
		assetMap["updated_at"] = asset.UpdatedAt
		assetMap["risk"] = asset.Risk
		assetMap["logging_completed"] = asset.LoggingCompleted
		assetMap["asset_value"] = asset.AssetValue

		// asset Ips - structured as nested object with arrays
		assetIPs := map[string]interface{}{
			"ip_address":  []string{},
			"mac_address": []string{},
		}

		for _, assetIP := range asset.AssetIps {
			assetIPs["ip_address"] = append(assetIPs["ip_address"].([]string), assetIP.Ip)
			assetIPs["mac_address"] = append(assetIPs["mac_address"].([]string), assetIP.MacAddress)
		}

		assetMap["asset_ips"] = assetIPs

		// Add empty scanner info
		scannerInfo := map[string]interface{}{
			"type": "",
		}

		if asset.Scanner != nil {
			scannerInfo["type"] = asset.Scanner.Type
		}

		assetMap["scanner"] = scannerInfo

		// asset Vmware Vms - structured as nested object with arrays
		vmwareVMs := map[string]interface{}{
			"vm_id":          []string{},
			"vm_name":        []string{},
			"hypervisor":     []string{},
			"cpu_count":      []string{},
			"memory_mb":      []string{},
			"disk_size_gb":   []string{},
			"power_state":    []string{},
			"last_synced_at": []string{},
		}

		for _, vm := range asset.VmwareVms {
			vmwareVMs["vm_id"] = append(vmwareVMs["vm_id"].([]string), vm.VmId)
			vmwareVMs["vm_name"] = append(vmwareVMs["vm_name"].([]string), vm.VmName)
			vmwareVMs["hypervisor"] = append(vmwareVMs["hypervisor"].([]string), vm.Hypervisor)
			vmwareVMs["cpu_count"] = append(vmwareVMs["cpu_count"].([]string), fmt.Sprintf("%d", vm.CpuCount))
			vmwareVMs["memory_mb"] = append(vmwareVMs["memory_mb"].([]string), fmt.Sprintf("%d", vm.MemoryMb))
			vmwareVMs["disk_size_gb"] = append(vmwareVMs["disk_size_gb"].([]string), fmt.Sprintf("%d", vm.DiskSizeGb))
			vmwareVMs["power_state"] = append(vmwareVMs["power_state"].([]string), vm.PowerState)
			vmwareVMs["last_synced_at"] = append(vmwareVMs["last_synced_at"].([]string), vm.LastSyncedAt)
		}

		assetMap["vmware_vms"] = vmwareVMs

		contents = append(contents, assetMap)
	}

	result["contents"] = contents
	return result
}
