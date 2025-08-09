package api

import (
	"fmt"

	"github.com/google/uuid"
	"gitlab.apk-group.net/siem/backend/asset-discovery/api/pb"
)

// NewTestCreateAssetRequest creates a basic test create asset request
func NewTestCreateAssetRequest() *pb.CreateAssetRequest {
	return &pb.CreateAssetRequest{
		Name:             "Test Asset",
		Domain:           "test.local",
		Hostname:         "test-host",
		OsName:           "Ubuntu",
		OsVersion:        "20.04",
		Type:             "Server",
		Description:      "Test asset for unit tests",
		Risk:             1,
		LoggingCompleted: false,
		AssetValue:       100,
		Ports:            []*pb.Port{},
		AssetIps:         []*pb.AssetIP{},
	}
}

// NewTestCreateAssetRequestWithPorts creates test request with specified ports
func NewTestCreateAssetRequestWithPorts(portCount int) *pb.CreateAssetRequest {
	req := NewTestCreateAssetRequest()
	for i := 0; i < portCount; i++ {
		req.Ports = append(req.Ports, NewTestPort(80+int32(i)))
	}
	return req
}

// NewTestCreateAssetRequestWithIPs creates test request with specified IPs
func NewTestCreateAssetRequestWithIPs(ips []string) *pb.CreateAssetRequest {
	req := NewTestCreateAssetRequest()
	for i, ip := range ips {
		req.AssetIps = append(req.AssetIps, &pb.AssetIP{
			Ip:         ip,
			MacAddress: NewTestMACAddress(i),
		})
	}
	return req
}

// NewTestPort creates a test port for requests
func NewTestPort(portNumber int32) *pb.Port {
	return &pb.Port{
		Id:             uuid.New().String(),
		PortNumber:     portNumber,
		Protocol:       "tcp",
		State:          "open",
		ServiceName:    "http",
		ServiceVersion: "1.0",
		Description:    "Test port",
	}
}

// NewTestMACAddress generates a test MAC address for API requests
func NewTestMACAddress(index int) string {
	return fmt.Sprintf("00:11:22:33:44:%02d", index%100)
}

// NewTestCreateAssetRequestMinimal creates minimal valid request
func NewTestCreateAssetRequestMinimal() *pb.CreateAssetRequest {
	return &pb.CreateAssetRequest{
		Hostname: "minimal-host",
		Type:     "Server",
	}
}

// NewTestCreateAssetRequestInvalid creates request with invalid data for testing validation
func NewTestCreateAssetRequestInvalid() *pb.CreateAssetRequest {
	return &pb.CreateAssetRequest{
		// Missing required hostname
		Type: "Server",
	}
}

// NewTestCreateAssetRequestWithHostname creates request with specific hostname
func NewTestCreateAssetRequestWithHostname(hostname string) *pb.CreateAssetRequest {
	req := NewTestCreateAssetRequest()
	req.Hostname = hostname
	return req
}

// NewTestCreateAssetRequestWithIP creates request with specific IP
func NewTestCreateAssetRequestWithIP(ip string) *pb.CreateAssetRequest {
	req := NewTestCreateAssetRequest()
	req.AssetIps = []*pb.AssetIP{
		{
			Ip:         ip,
			MacAddress: "00:11:22:33:44:55",
		},
	}
	return req
}

// NewTestCreateAssetResponse creates a test response
func NewTestCreateAssetResponse(id string) *pb.CreateAssetResponse {
	return &pb.CreateAssetResponse{
		Id: id,
	}
}
