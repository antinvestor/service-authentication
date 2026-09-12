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

	"github.com/pitabwire/frame/v2/data"
	"github.com/pitabwire/frame/v2/tenancy"
)

// Intake states for AuditIntake.State.
const (
	IntakeStateAccepted  = "ACCEPTED"
	IntakeStateCommitted = "COMMITTED"
	IntakeStateFailed    = "FAILED"
)

// CanonVersionV2 is the canonical encoding recorded on AuditEntry.CanonVersion.
// Any change to the encoding is a new version, never an edit.
const CanonVersionV2 = 2

// AlgorithmEd25519 is the only signing algorithm currently supported.
const AlgorithmEd25519 = "ed25519"

// AuditEntry is an append-only, tamper-proof audit trail record.
// Each entry is hash-chained to its predecessor within its tenant and
// digitally signed by the key identified by KeyID.
//
// Design invariants:
//   - No UPDATE or DELETE is permitted on this table (database trigger).
//   - (TenantID, Seq) is unique and gap-free; Seq is assigned by the chain
//     writer under a per-tenant advisory lock.
//   - EntryHash = SHA-256(canon_v2(entry) ‖ PreviousHash) (see business/canon.go).
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

	// v2 chain position and encoding.
	Seq          int64  `gorm:"not null;default:0"`
	KeyID        string `gorm:"type:varchar(32);not null;default:''"`
	CanonVersion int16  `gorm:"not null;default:2"`

	// v2 provenance.
	EntryID               string    `gorm:"type:varchar(64);not null;default:''"`
	ActorServiceAccountID string    `gorm:"type:varchar(50)"`
	OnBehalfOf            string    `gorm:"type:varchar(50)"`
	OccurredAt            time.Time `gorm:"type:timestamptz"`
	ReceivedAt            time.Time `gorm:"type:timestamptz"`
	ManifestVersion       int32     `gorm:"not null;default:0"`
	Unmanifested          bool      `gorm:"not null;default:false"`

	// v2 typed evidence columns.
	CorrelationID     string       `gorm:"type:varchar(64)"`
	EventID           string       `gorm:"type:varchar(64)"`
	IntentID          string       `gorm:"type:varchar(64)"`
	InstanceID        string       `gorm:"type:varchar(64)"`
	PayloadHash       string       `gorm:"type:varchar(64)"`
	AuthorizationHash string       `gorm:"type:varchar(64)"`
	PolicyHash        string       `gorm:"type:varchar(64)"`
	DeviceKeyID       string       `gorm:"type:varchar(64)"`
	StateFrom         string       `gorm:"type:varchar(64)"`
	StateTo           string       `gorm:"type:varchar(64)"`
	ResourceVersion   int64        `gorm:"not null;default:0"`
	Relations         data.JSONMap `gorm:"type:jsonb"`
}

func (AuditEntry) TableName() string { return "audit_entries" }

// AuditIntake is the durable acceptance record for an entry that has not
// yet been sequenced into the chain. The RPC returns once this row exists.
type AuditIntake struct {
	data.BaseModel
	// (tenant_id, service, entry_id) is unique; the index is created in SQL
	// because tenant_id lives in the embedded BaseModel.
	Service      string       `gorm:"type:varchar(100);not null"`
	EntryID      string       `gorm:"type:varchar(64);not null"`
	Payload      data.JSONMap `gorm:"type:jsonb;not null"`
	ReceivedAt   time.Time    `gorm:"type:timestamptz;not null;index"`
	State        string       `gorm:"type:varchar(16);not null;index"`
	Attempts     int32        `gorm:"not null;default:0"`
	LastError    string       `gorm:"type:text"`
	CommittedSeq int64        `gorm:"not null;default:0"`
}

func (AuditIntake) TableName() string { return "audit_intake" }

// AuditChainHead is the per-tenant chain tip. ID equals TenantID so the
// primary key enforces one head per tenant; it is the only mutable chain
// table and is advanced by compare-and-swap on Seq.
type AuditChainHead struct {
	data.BaseModel
	Seq       int64  `gorm:"not null;default:0"`
	EntryHash string `gorm:"type:varchar(64);not null;default:''"`
}

func (AuditChainHead) TableName() string { return "audit_chain_heads" }

// AuditCheckpoint is a signed anchor of the chain at Seq. Append-only.
type AuditCheckpoint struct {
	data.BaseModel
	// (tenant_id, seq) is unique; index created in SQL (see intake note).
	Seq       int64  `gorm:"not null"`
	EntryHash string `gorm:"type:varchar(64);not null"`
	KeyID     string `gorm:"type:varchar(32);not null"`
	Signature string `gorm:"type:text;not null"`
}

func (AuditCheckpoint) TableName() string { return "audit_checkpoints" }

// AuditSigningKey is a global (non-tenant) record of a signing public key.
// The private key never enters the database. Only RetiredAt may change.
type AuditSigningKey struct {
	data.BaseModel
	tenancy.UnscopedMarker
	KeyID     string     `gorm:"type:varchar(32);not null;uniqueIndex"`
	Algorithm string     `gorm:"type:varchar(16);not null;default:'ed25519'"`
	PublicKey []byte     `gorm:"type:bytea;not null"`
	ValidFrom time.Time  `gorm:"type:timestamptz;not null"`
	RetiredAt *time.Time `gorm:"type:timestamptz"`
}

func (AuditSigningKey) TableName() string { return "audit_signing_keys" }

// AuditManifest is a global, versioned vocabulary declaration for one
// producing service. Versions are append-only.
type AuditManifest struct {
	data.BaseModel
	tenancy.UnscopedMarker
	Service      string       `gorm:"type:varchar(100);not null;index:idx_audit_manifests_service_version,unique,composite:sv"`
	ManifestVer  int32        `gorm:"column:manifest_version;not null;index:idx_audit_manifests_service_version,unique,composite:sv"`
	ContentHash  string       `gorm:"type:varchar(64);not null"`
	Content      data.JSONMap `gorm:"type:jsonb;not null"`
	RegisteredBy string       `gorm:"type:varchar(50)"`
}

func (AuditManifest) TableName() string { return "audit_manifests" }

// AuditRejection records that a producer sent an entry the validator
// refused. It never stores the offending content.
type AuditRejection struct {
	data.BaseModel
	Service    string    `gorm:"type:varchar(100);not null;index:idx_audit_rejections_service_received"`
	Reason     string    `gorm:"type:varchar(64);not null"`
	Field      string    `gorm:"type:varchar(64)"`
	EntryID    string    `gorm:"type:varchar(64)"`
	ReceivedAt time.Time `gorm:"type:timestamptz;not null;index:idx_audit_rejections_service_received"`
}

func (AuditRejection) TableName() string { return "audit_rejections" }
