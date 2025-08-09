package storage

import (
	"context"
	"errors"
	"log"
	"time"

	"github.com/google/uuid"
	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/user/domain"
	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/user/port"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/adapter/storage/types/mapper"
	"gorm.io/gorm"
)

type userRepo struct {
	db *gorm.DB
}

func NewUserRepo(db *gorm.DB) port.Repo {
	return &userRepo{
		db: db,
	}
}

func (r *userRepo) Create(ctx context.Context, user domain.User) (domain.UserID, error) {
	u := mapper.UserDomain2Storage(user)
	u.UpdatedAt = nil
	u.DeletedAt = nil
	userID, err := uuid.Parse(u.ID)
	if err != nil {
		// TODO error handling
		panic("cannot pars uuid")
	}
	return userID, r.db.Table("users").WithContext(ctx).Create(&u).Error
}

func (r *userRepo) GetByUsername(ctx context.Context, filter domain.UserFilter) (*domain.User, error) {
	uf := mapper.UserFilterDomain2Storage(filter)
	var user domain.User
	q := r.db.Table("users").Debug().WithContext(ctx)
	if len(uf.FirstName) > 0 {
		q.Where("firstname = ?", uf.FirstName)
	}

	if len(uf.LastName) > 0 {
		q.Where("lastname = ?", uf.LastName)
	}

	if len(uf.Username) > 0 {
		q.Where("username = ?", uf.Username)
	}

	err := q.Find(&user).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return &user, nil
		}
		return &user, err
	}
	return &user, nil
}

func (r *userRepo) StoreSession(ctx context.Context, session domain.Sessions) error {
	s := mapper.UserSessionDomain2Storage(session)
	s.LoggedOutAt = nil
	err := r.db.Table("sessions").WithContext(ctx).Create(&s).Error
	if err!=nil{
		log.Println(err.Error())
		return err
	}
	return nil
}

func (r *userRepo) InvalidateSession(ctx context.Context, refreshToken string) error {
	loggedOutDate := time.Now()
	result := r.db.WithContext(ctx).Table("sessions").Where("refresh_token = ?", refreshToken).Update("is_login", false).Update("logged_out_at", loggedOutDate)
	if result.Error != nil {
		log.Println(result.Error.Error())
		return result.Error
	}
	if result.RowsAffected == 0 {
		return errors.New("session not found")
	}
	return nil
}
