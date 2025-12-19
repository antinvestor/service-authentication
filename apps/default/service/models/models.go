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
	ClientID         string `gorm:"type:varchar(50)"`
	LoginID          string `gorm:"type:varchar(50)"`
	LoginChallengeID string `gorm:"type:TEXT"`
	VerificationID   string `gorm:"type:varchar(50)"`
	AccessID         string `gorm:"type:varchar(50)"`
	ContactID        string `gorm:"type:varchar(50)"`
	ProfileID        string `gorm:"type:varchar(50)"`
	SessionID        string `gorm:"type:varchar(50)"`
	Oauth2SessionID  string `gorm:"type:varchar(250)"`
	DeviceID         string `gorm:"type:varchar(50)"`
	Properties       data.JSONMap
	Client           string
	IP               string
	Status           int
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
