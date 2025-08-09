package service

import (
	"context"
	"errors"
	"time"

	jwt2 "github.com/golang-jwt/jwt/v5"
	"gitlab.apk-group.net/siem/backend/asset-discovery/api/pb"
	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/user"
	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/user/domain"
	userPort "gitlab.apk-group.net/siem/backend/asset-discovery/internal/user/port"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/jwt"
	timeutils "gitlab.apk-group.net/siem/backend/asset-discovery/pkg/time"
)

var (
	ErrUserOnCreate           = user.ErrUserOnCreate
	ErrUserCreationValidation = user.ErrUserCreationValidation
	ErrUserNotFound           = user.ErrUserNotFound
	ErrSessionOnCreate        = user.ErrSessionOnCreate
	ErrSessionOnInvalidate    = user.ErrSessionOnInvalidate

	ErrInvalidUserPassword = errors.New("invalid username or password")
)

type UserService struct {
	service               userPort.Service
	authSecret            string
	expMin, refreshExpMin uint
}

func NewUserService(srv userPort.Service, authSecret string, expMin, refreshExpMin uint) *UserService {
	return &UserService{
		service:       srv,
		authSecret:    authSecret,
		expMin:        expMin,
		refreshExpMin: refreshExpMin,
	}
}

func (s *UserService) SignUp(ctx context.Context, req *pb.UserSignUpRequest) (*pb.UserSignUpResponse, error) {
	hPassword, err := domain.HashPassword(req.GetPassword())
	if err != nil {
		return nil, err
	}
	uid, err := s.service.CreateUser(ctx, domain.User{
		FirstName: req.GetFirstName(),
		LastName:  req.GetLastName(),
		Username:  req.GetUsername(),
		Password:  hPassword,
		CreatedAt: time.Now(),
	})
	if err != nil {
		return nil, err
	}

	accessToken, err := jwt.CreateToken([]byte(s.authSecret), &jwt.UserClaims{
		RegisteredClaims: jwt2.RegisteredClaims{
			ExpiresAt: jwt2.NewNumericDate(timeutils.AddMinutes(s.expMin, true)),
		},
		UserID: uid.String(),
	})
	if err != nil {
		return nil, err
	}

	refershToken, err := jwt.CreateToken([]byte(s.authSecret), &jwt.UserClaims{
		RegisteredClaims: jwt2.RegisteredClaims{
			ExpiresAt: jwt2.NewNumericDate(timeutils.AddMinutes(s.refreshExpMin, true)),
		},
		UserID: uid.String(),
	})
	if err != nil {
		return nil, err
	}
	return &pb.UserSignUpResponse{
		AccessToken:  accessToken,
		RefreshToken: refershToken,
	}, nil
}

func (s *UserService) SignIn(ctx context.Context, req *pb.UserSignInRequest) (*pb.UserSignInResponse, error) {
	user, err := s.service.GetUserByUsername(ctx, domain.UserFilter{
		Username: req.GetUsername(),
	})

	if err != nil {
		return nil, err
	}

	if user == nil {
		return nil, ErrUserNotFound
	}

	if !user.CheckPasswordHash(req.GetPassword(), user.Password) {
		return nil, ErrInvalidUserPassword
	}
	access, refresh, err := s.createTokens(user.ID)
	if err != nil {
		return nil, err
	}
	err = s.service.StoreUserSession(ctx, domain.Sessions{
		UserID:       user.ID,
		AccessToken:  access,
		RefreshToken: refresh,
		IsLogin:      true,
		CreatedAt:    time.Now(),
	})
	if err != nil {
		return nil, ErrSessionOnCreate
	}

	return &pb.UserSignInResponse{
		AccessToken:  access,
		RefreshToken: refresh,
	}, nil

}

func (s *UserService) SignOut(ctx context.Context, req *pb.UserSignOutRequest) error {
	err := s.service.InvalidateUserSession(ctx, req.GetRefreshToken())
	if err != nil {
		return ErrSessionOnInvalidate
	}
	return nil
}
func (s *UserService) createTokens(userID domain.UserID) (access, refresh string, err error) {
	access, err = jwt.CreateToken([]byte(s.authSecret), &jwt.UserClaims{
		RegisteredClaims: jwt2.RegisteredClaims{
			ExpiresAt: jwt2.NewNumericDate(timeutils.AddMinutes(s.expMin, true)),
		},
		UserID: userID.String(),
	})
	if err != nil {
		return
	}

	refresh, err = jwt.CreateToken([]byte(s.authSecret), &jwt.UserClaims{
		RegisteredClaims: jwt2.RegisteredClaims{
			ExpiresAt: jwt2.NewNumericDate(timeutils.AddMinutes(s.refreshExpMin, true)),
		},
		UserID: userID.String(),
	})

	if err != nil {
		return
	}

	return
}
