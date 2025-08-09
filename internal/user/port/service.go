package port

import (
	"context"

	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/user/domain"
)

type Service interface {
	CreateUser(ctx context.Context, user domain.User) (domain.UserID, error)
	GetUserByUsername(ctx context.Context, fliter domain.UserFilter) (*domain.User, error)
	StoreUserSession(ctx context.Context, session domain.Sessions) error
	InvalidateUserSession(ctx context.Context, refreshToken string) error
}
