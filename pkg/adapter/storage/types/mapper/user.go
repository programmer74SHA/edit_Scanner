package mapper

import (
	"github.com/google/uuid"
	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/user/domain"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/adapter/storage/types"
)

func UserDomain2Storage(user domain.User) *types.User {
	return &types.User{
		ID:        user.ID.String(),
		FirstName: &user.FirstName,
		LastName:  &user.LastName,
		Username:  user.Username,
		Password:  user.Password,
		CreatedAt: user.CreatedAt,
		UpdatedAt: &user.UpdatedAt,
		DeletedAt: &user.DeletedAt,
	}
}

func UserStorage2Domain(user types.User) (*domain.User, error) {
	uid, err := domain.UserIDFromString(user.ID)

	return &domain.User{
		ID:        uid,
		FirstName: *user.FirstName,
		LastName:  *user.LastName,
		Username:  user.Username,
		Password:  user.Password,
		CreatedAt: user.CreatedAt,
		UpdatedAt: *user.UpdatedAt,
		DeletedAt: *user.DeletedAt,
	}, err
}

func UserFilterStorage2Domain(filter types.UserFilter) *domain.UserFilter {
	return &domain.UserFilter{
		FirstName: filter.FirstName,
		LastName:  filter.LastName,
		Username:  filter.Username,
	}
}

func UserFilterDomain2Storage(filter domain.UserFilter) *types.UserFilter {
	return &types.UserFilter{
		FirstName: filter.FirstName,
		LastName:  filter.LastName,
		Username:  filter.Username,
	}
}

func UserSessionStorage2Domain(session types.Session) (*domain.Sessions, error) {
	uid, err := uuid.Parse(session.UserID)
	return &domain.Sessions{
		UserID:       uid,
		AccessToken:  session.AccessToken,
		RefreshToken: session.RefreshToken,
		IsLogin:      session.IsLogin,
		CreatedAt:    session.CreatedAt,
		LoggedOutAt:  *session.LoggedOutAt,
	}, err
}

func UserSessionDomain2Storage(session domain.Sessions) *types.Session {
	return &types.Session{
		UserID:       session.UserID.String(),
		AccessToken:  session.AccessToken,
		RefreshToken: session.RefreshToken,
		IsLogin:      session.IsLogin,
		CreatedAt:    session.CreatedAt,
		LoggedOutAt:  &session.LoggedOutAt,
	}
}
