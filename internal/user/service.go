package user

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/user/domain"
	userRepo "gitlab.apk-group.net/siem/backend/asset-discovery/internal/user/port"
)

var (
	ErrUserOnCreate           = errors.New("error on creating new user")
	ErrUserCreationValidation = errors.New("validation failed")
	ErrUserNotFound           = errors.New("user not found")
	ErrSessionOnCreate        = errors.New("error on create session")
	ErrSessionOnInvalidate    = errors.New("error on invalidate session")
)

type userService struct {
	repo userRepo.Repo
}

func NewUserService(repo userRepo.Repo) userRepo.Service {
	return &userService{
		repo: repo,
	}
}

func (s *userService) CreateUser(ctx context.Context, user domain.User) (domain.UserID, error) {
	user.ID = uuid.New()
	uid, err := s.repo.Create(ctx, user)
	if err != nil {
		return uuid.Nil, ErrUserOnCreate
	}
	return uid, nil
}

func (s *userService) GetUserByUsername(ctx context.Context, filter domain.UserFilter) (*domain.User, error) {
	user, err := s.repo.GetByUsername(ctx, filter)
	if err != nil {
		return &domain.User{}, err
	}

	if user == nil {
		return &domain.User{}, ErrUserNotFound
	}

	return user, nil
}

func (s *userService) StoreUserSession(ctx context.Context, session domain.Sessions) error {
	err := s.repo.StoreSession(ctx, session)
	if err != nil {
		return ErrSessionOnCreate
	}
	return nil
}

func (s *userService) InvalidateUserSession(ctx context.Context, refreshToken string) error {
	err := s.repo.InvalidateSession(ctx, refreshToken)
	if err != nil {
		return ErrSessionOnInvalidate
	}
	return nil
}
