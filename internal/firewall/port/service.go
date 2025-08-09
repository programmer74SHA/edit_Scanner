package port

import (
	"context"

	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/firewall/domain"
)

// Service defines the interface for firewall business logic
type Service interface {
	CreateFirewall(ctx context.Context, firewall domain.FirewallDomain) (domain.FirewallUUID, error)
	GetFirewallByID(ctx context.Context, firewallID domain.FirewallUUID) (*domain.FirewallDomain, error)
	ListFirewalls(ctx context.Context, limit int, offset int) (*domain.ListFirewalls, error)
	UpdateFirewall(ctx context.Context, firewallID domain.FirewallUUID, firewall domain.FirewallDomain) error
	DeleteFirewall(ctx context.Context, firewallID domain.FirewallUUID) error
	DeleteFirewallBatch(ctx context.Context, firewallIDs []domain.FirewallUUID) error
	DeleteAllFirewalls(ctx context.Context) error
}
