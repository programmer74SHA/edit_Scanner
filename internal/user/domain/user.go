package domain

import (
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type UserID = uuid.UUID

type User struct {
	ID        UserID
	FirstName string
	LastName  string
	Username  string
	Password  string
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt time.Time
}

type UserFilter struct {
	FirstName string
	LastName  string
	Username  string
}

type Sessions struct {
	UserID       UserID
	AccessToken  string
	RefreshToken string
	IsLogin      bool
	CreatedAt    time.Time
	LoggedOutAt  time.Time
	// ExpiresAt    time.Time
}

func UserIDFromString(s string) (uuid.UUID, error) {
	return uuid.Parse(s)
}

// HashPassword creates a bcrypt hash of the password
func HashPassword(password string) (string, error) {
	// Cost factor of 12 is a good starting point (adjust based on your security needs)
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	return string(bytes), err
}

// CheckPasswordHash compares a password with a hash to check if they match
func (u *User) CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}
