package types

import (
	"time"
)

type User struct {
	ID        string     `gorm:"column:id;size:50;primaryKey"`
	FirstName *string    `gorm:"column:first_name;size:100"`
	LastName  *string    `gorm:"column:last_name;size:100"`
	Username  string     `gorm:"column:username;size:100;not null;uniqueIndex"`
	Password  string     `gorm:"column:password;size:200;not null"`
	Email     *string    `gorm:"column:email;size:100"`
	Role      string     `gorm:"column:role;size:100;not null"`
	CreatedAt time.Time  `gorm:"column:created_at;type:datetime;not null"`
	UpdatedAt *time.Time `gorm:"column:updated_at;type:datetime"`
	DeletedAt *time.Time `gorm:"index"`

	Scanner  Scanner   `gorm:"foreignKey:UserID"`
	Sessions []Session `gorm:"foreignKey:UserID"`
}

type Session struct {
	UserID       string     `gorm:"column:user_id;size:50;not null;index"`
	AccessToken  string     `gorm:"column:access_token;size:500;not null;"`
	RefreshToken string     `gorm:"column:refresh_token;size:500;not null;"`
	CreatedAt    time.Time  `gorm:"column:created_at;type:datetime;not null"`
	LoggedOutAt  *time.Time `gorm:"column:logged_out_at;type:datetime;"`
	IsLogin      bool       `gorm:"column:is_login;default:1"`

	User User `gorm:"foreignKey:UserID"`
}

type UserFilter struct {
	FirstName string
	LastName  string
	Username  string
}
