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

package repository

import (
	"testing"
	"time"

	"github.com/antinvestor/service-authentication/apps/audit/service/models"
	"github.com/stretchr/testify/require"
)

const migrationPath = "../../migrations/0001"

func allModels() []any {
	return []any{
		&models.AuditEntry{}, &models.AuditIntake{}, &models.AuditChainHead{}, &models.AuditCheckpoint{},
		&models.AuditSigningKey{}, &models.AuditManifest{}, &models.AuditRejection{},
	}
}

// TestMigrate_StartsGreenfieldAndInstallsGuards applies the migration set on
// a database that still holds pre-v2 rows and asserts they are discarded
// (the chain is greenfield), the unique chain position index exists, the
// migration is re-runnable, and the append-only triggers hold.
func TestMigrate_StartsGreenfieldAndInstallsGuards(t *testing.T) {
	ctx := t.Context()
	dbPool := newAuditRepositoryTestPool(t)

	// Pre-v2 schema with a row that carries no chain position.
	require.NoError(t, dbPool.DB(ctx, false).AutoMigrate(&legacyAuditEntry{}))
	now := time.Now().UTC()
	require.NoError(t, dbPool.DB(ctx, false).Table("audit_entries").Create(&legacyAuditEntry{
		ID: "old-1", TenantID: "tenant-a", CreatedAt: now, ModifiedAt: now, Version: 1,
		ProfileID: "profile", Action: "create", ResourceType: "thing", Service: "svc", EntryHash: "h", Signature: "s",
	}).Error)

	require.NoError(t, dbPool.Migrate(ctx, migrationPath, allModels()...))

	var count int64
	require.NoError(t, dbPool.DB(ctx, true).Model(&models.AuditEntry{}).Count(&count).Error)
	require.Zero(t, count, "pre-v2 rows are not part of the chain and are discarded")

	// Re-running is a no-op and keeps v2 rows.
	require.NoError(t, dbPool.Migrate(ctx, migrationPath, allModels()...))

	e := newAuditEntry("v2-1", now, "profile", "create", "hash-1")
	e.Seq = 1
	require.NoError(t, dbPool.DB(ctx, false).Create(e).Error)
	dup := newAuditEntry("v2-2", now, "profile", "create", "hash-2")
	dup.Seq = 1
	require.ErrorContains(t, dbPool.DB(ctx, false).Create(dup).Error, "idx_audit_entries_tenant_seq")

	// Immutability trigger blocks UPDATE and DELETE.
	require.ErrorContains(t, dbPool.DB(ctx, false).Exec("UPDATE audit_entries SET action = 'x' WHERE id = 'v2-1'").Error, "append-only")
	require.ErrorContains(t, dbPool.DB(ctx, false).Exec("DELETE FROM audit_entries WHERE id = 'v2-1'").Error, "append-only")

	// Signing keys: retire once, never delete.
	key := &models.AuditSigningKey{KeyID: "k1", Algorithm: "ed25519", PublicKey: []byte("0123456789abcdef0123456789abcdef"), ValidFrom: now}
	require.NoError(t, dbPool.DB(ctx, false).Create(key).Error)
	require.NoError(t, dbPool.DB(ctx, false).Exec("UPDATE audit_signing_keys SET retired_at = now() WHERE key_id = 'k1'").Error)
	require.ErrorContains(t, dbPool.DB(ctx, false).Exec("UPDATE audit_signing_keys SET retired_at = NULL WHERE key_id = 'k1'").Error, "retired_at")
	require.ErrorContains(t, dbPool.DB(ctx, false).Exec("DELETE FROM audit_signing_keys WHERE key_id = 'k1'").Error, "not permitted")
}

// legacyAuditEntry mirrors the pre-v2 audit_entries columns.
type legacyAuditEntry struct {
	ID              string    `gorm:"type:varchar(50);primary_key"`
	CreatedAt       time.Time `gorm:"not null"`
	ModifiedAt      time.Time `gorm:"not null"`
	Version         uint
	TenantID        string `gorm:"type:varchar(50)"`
	PartitionID     string `gorm:"type:varchar(50)"`
	AccessID        string `gorm:"type:varchar(50)"`
	ProfileID       string `gorm:"type:varchar(50);not null"`
	Action          string `gorm:"type:varchar(100);not null"`
	ResourceType    string `gorm:"type:varchar(100);not null"`
	ResourceID      string `gorm:"type:varchar(100)"`
	Service         string `gorm:"type:varchar(100);not null"`
	IPAddress       string `gorm:"type:varchar(45)"`
	UserAgent       string `gorm:"type:text"`
	DeviceID        string `gorm:"type:varchar(50)"`
	TargetProfileID string `gorm:"type:varchar(50)"`
	TraceID         string `gorm:"type:varchar(64)"`
	PreviousHash    string `gorm:"type:varchar(64);not null"`
	EntryHash       string `gorm:"type:varchar(64);not null"`
	Signature       string `gorm:"type:text;not null"`
}

func (legacyAuditEntry) TableName() string { return "audit_entries" }
