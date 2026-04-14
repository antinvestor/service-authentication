// Copyright 2023-2026 Ant Investor Ltd
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package models

import (
	"time"

	"github.com/pitabwire/frame/data"
)

type LoginSource string

const (
	LoginSourceDirect         LoginSource = "direct"
	LoginSourceGoogle         LoginSource = "google"
	LoginSourceMeta           LoginSource = "facebook"
	LoginSourceApple          LoginSource = "apple"
	LoginSourceMicrosoft      LoginSource = "microsoft"
	LoginSourceServiceAccount LoginSource = "service_account"
	LoginSourceSessionRefresh LoginSource = "session_refresh"
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
