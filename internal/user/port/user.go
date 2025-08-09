package port

import (
	"context"

	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/user/domain"
)

type Repo interface {
	Create(ctx context.Context, user domain.User) (domain.UserID, error)
	GetByUsername(ctx context.Context, filter domain.UserFilter) (*domain.User, error)
	StoreSession(ctx context.Context, session domain.Sessions) error
	InvalidateSession(ctx context.Context, refreshToken string) error
}
