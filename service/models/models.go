package models

import (
	"github.com/pitabwire/frame"
	"gorm.io/datatypes"
	"time"
)

type Login struct {
	frame.BaseModel
	ProfileHash  string `gorm:"type:varchar(255)"`
	PasswordHash []byte
	Locked       datatypes.Date
}

type LoginEvent struct {
	frame.BaseModel
	LoginID   string `gorm:"type:varchar(50)"`
	AccessID  string `gorm:"type:varchar(50)"`
	IPAddress string
	UserAgent string
	Client    string
	Status    int
	Context   string `gorm:"type:text"`
}

type Session struct {
	SessionID    string `gorm:"type:varchar(50);primary_key"`
	LoginEventID string `gorm:"type:varchar(50)"`
	ExpiresAt    time.Time
	IssuedAt     time.Time
	ProfileID    string `gorm:"type:varchar(50)"`
	frame.BaseModel
}

type APIKey struct {
	frame.BaseModel
	Name      string `gorm:"type:varchar(255)"`
	ClientID  string `gorm:"type:varchar(50)"`
	ProfileID string `gorm:"type:varchar(50)"`
	Key       string `gorm:"type:varchar(255)"`
	Hash      string `gorm:"type:varchar(255)"`
	Scope     string `gorm:"type:text"`
	Audience  string `gorm:"type:text"`
	Metadata  string `gorm:"type:text"`
}
