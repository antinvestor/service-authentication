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
	"github.com/pitabwire/frame/data"
)

// AuditEntry is an append-only, tamper-proof audit trail record.
// Each entry is hash-chained to its predecessor and digitally signed
// to detect and prevent tampering at the database level.
//
// Design invariants:
//   - No UPDATE or DELETE operations are permitted on this table.
//   - EntryHash = SHA-256(ProfileID + Action + ResourceType + ResourceID +
//     Service + Details + CreatedAt + PreviousHash)
//   - Signature = Ed25519(EntryHash) using a server-managed signing key.
type AuditEntry struct {
	data.BaseModel
	ProfileID       string       `gorm:"type:varchar(50);index;not null"`
	Action          string       `gorm:"type:varchar(100);index;not null"`
	ResourceType    string       `gorm:"type:varchar(100);index;not null"`
	ResourceID      string       `gorm:"type:varchar(100);index"`
	Service         string       `gorm:"type:varchar(100);index;not null"`
	Details         data.JSONMap `gorm:"type:jsonb"`
	IPAddress       string       `gorm:"type:varchar(45)"`
	UserAgent       string       `gorm:"type:text"`
	DeviceID        string       `gorm:"type:varchar(50);index"`
	TargetProfileID string       `gorm:"type:varchar(50);index"`
	TraceID         string       `gorm:"type:varchar(64);index"`
	PreviousHash    string       `gorm:"type:varchar(64);not null"`
	EntryHash       string       `gorm:"type:varchar(64);uniqueIndex;not null"`
	Signature       string       `gorm:"type:text;not null"`
}
