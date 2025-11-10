package models

import (
	"time"

	"github.com/pitabwire/frame/data"
)

type LoginSource string

const (
	LoginSourceDirect LoginSource = "direct"
	LoginSourceGoogle LoginSource = "google"
	LoginSourceMeta   LoginSource = "facebook"
)

type Login struct {
	data.BaseModel
	ProfileID string `gorm:"type:varchar(255)"`
	ClientID  string `gorm:"type:varchar(255)"`
	Source    string `gorm:"type:varchar(255)"`
	Locked    time.Time
}

type LoginEvent struct {
	data.BaseModel
	LoginID          string `gorm:"type:varchar(50)"`
	LoginChallengeID string `gorm:"type:TEXT"`
	VerificationID   string `gorm:"type:varchar(50)"`
	AccessID         string `gorm:"type:varchar(50)"`
	ContactID        string `gorm:"type:varchar(50)"`
	Properties       data.JSONMap
	Client           string
	Status           int
}

type Session struct {
	LoginEventID string `gorm:"type:varchar(50)"`
	ExpiresAt    time.Time
	IssuedAt     time.Time
	ProfileID    string `gorm:"type:varchar(50)"`
	data.BaseModel
}

type APIKey struct {
	data.BaseModel
	Name      string `gorm:"type:varchar(255)"`
	ProfileID string `gorm:"type:varchar(50)"`
	Key       string `gorm:"type:varchar(255);uniqueIndex"`
	Hash      string `gorm:"type:TEXT"`
	Scope     string `gorm:"type:text"`
	Audience  string `gorm:"type:text"`
	Metadata  data.JSONMap
}
