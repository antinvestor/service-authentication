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
	ProfileID string    `gorm:"type:varchar(255);index"`
	ClientID  string    `gorm:"type:varchar(255);index"`
	Source    string    `gorm:"type:varchar(255)"`
	Locked    time.Time `gorm:"index"`
}

type LoginEvent struct {
	data.BaseModel
	ClientID         string `gorm:"type:varchar(50);index"`
	LoginID          string `gorm:"type:varchar(50);index"`
	LoginChallengeID string `gorm:"type:TEXT;index"`
	VerificationID   string `gorm:"type:varchar(50);index"`
	AccessID         string `gorm:"type:varchar(50);index"`
	ContactID        string `gorm:"type:varchar(50);index"`
	ProfileID        string `gorm:"type:varchar(50);index"`
	SessionID        string `gorm:"type:varchar(50);index"`
	Oauth2SessionID  string `gorm:"type:varchar(250);index"`
	DeviceID         string `gorm:"type:varchar(50);index"`
	Properties       data.JSONMap
	Client           string
	IP               string
	Status           int `gorm:"index"`
}

func (l LoginEvent) GetTenantID() string {
	return l.TenantID
}

func (l LoginEvent) GetPartitionID() string {
	return l.PartitionID
}

func (l LoginEvent) GetProfileID() string {
	return l.ProfileID
}

func (l LoginEvent) GetAccessID() string {
	return l.AccessID
}

func (l LoginEvent) GetContactID() string {
	return l.ContactID
}

func (l LoginEvent) GetSessionID() string {
	return l.SessionID
}

func (l LoginEvent) GetDeviceID() string {
	return l.DeviceID
}

func (l LoginEvent) GetRoles() []string {
	return []string{}
}

type Session struct {
	LoginEventID string `gorm:"type:varchar(50)"`
	ExpiresAt    time.Time
	IssuedAt     time.Time
	ProfileID    string `gorm:"type:varchar(50)"`
	data.BaseModel
}
