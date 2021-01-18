package models

import (
	"github.com/pitabwire/frame"
	"time"
)

type Login struct {
	ProfileHash  string `gorm:"type:varchar(255)"`
	PasswordHash []byte
	Locked       *time.Time
	frame.BaseModel
}


type LoginEvent struct {
	LoginID      string `gorm:"type:varchar(50)"`
	AccessID     string `gorm:"type:varchar(50)"`
	IPAddress    string
	UserAgent    string
	Client       string
	Status       int
	Context      string `gorm:"type:text"`
	frame.BaseModel
}

type Session struct {
	SessionID    string `gorm:"type:varchar(50);primary_key"`
	LoginEventID string `gorm:"type:varchar(50)"`
	ExpiresAt    time.Time
	IssuedAt     time.Time
	ProfileID    string `gorm:"type:varchar(50)"`
	frame.BaseModel
}
