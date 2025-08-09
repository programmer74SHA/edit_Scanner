package port

import (
	"context"

	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/firewall/domain"
)

// Repo defines the interface for firewall data persistence
type Repo interface {
	Create(ctx context.Context, firewall domain.FirewallDomain) (domain.FirewallUUID, error)
	GetByID(ctx context.Context, firewallID domain.FirewallUUID) (*domain.FirewallDomain, error)
	List(ctx context.Context, limit int, offset int) (*domain.ListFirewalls, error)
	Update(ctx context.Context, firewallID domain.FirewallUUID, firewall domain.FirewallDomain) error
	Delete(ctx context.Context, firewallID domain.FirewallUUID) error
	DeleteBatch(ctx context.Context, firewallIDs []domain.FirewallUUID) error
	DeleteAll(ctx context.Context) error
	CheckVendorExists(ctx context.Context, vendorCode string) (bool, error)
	CheckManagementIPExists(ctx context.Context, managementIP string) (bool, error)
	CheckManagementIPExistsExcludingFirewall(ctx context.Context, managementIP string, firewallID domain.FirewallUUID) (bool, error)
}
