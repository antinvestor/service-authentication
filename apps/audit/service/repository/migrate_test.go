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
	"fmt"
	"testing"
	"time"

	"github.com/antinvestor/service-authentication/apps/audit/service/models"
	"github.com/stretchr/testify/require"
)

const migrationPath = "../../migrations/0001"

// TestMigrate_BackfillsSeqAndHeadsForLegacyRows applies the full migration
// set on a database that already holds pre-v2 rows (no seq, no entry_id)
// and asserts the backfill assigns dense per-tenant sequences, writes one
// head per tenant, and installs the immutability trigger.
func TestMigrate_BackfillsSeqAndHeadsForLegacyRows(t *testing.T) {
	ctx := t.Context()
	dbPool := newAuditRepositoryTestPool(t)

	// Legacy schema: only the v1 model.
	require.NoError(t, dbPool.DB(ctx, false).AutoMigrate(&legacyAuditEntry{}))
	base := time.Date(2026, 9, 1, 8, 0, 0, 0, time.UTC)
	for tenant, n := range map[string]int{"tenant-a": 3, "tenant-b": 2} {
		for i := range n {
			row := &legacyAuditEntry{
				ID: fmt.Sprintf("%s-%02d", tenant, i), TenantID: tenant, PartitionID: "p",
				CreatedAt: base.Add(time.Duration(i) * time.Minute), ModifiedAt: base, Version: 1,
				ProfileID: "profile", Action: "create", ResourceType: "thing", Service: "svc",
				PreviousHash: "", EntryHash: fmt.Sprintf("hash-%s-%02d", tenant, i), Signature: "sig",
			}
			require.NoError(t, dbPool.DB(ctx, false).Table("audit_entries").Create(row).Error)
		}
	}

	require.NoError(t, dbPool.Migrate(ctx, migrationPath,
		&models.AuditEntry{}, &models.AuditIntake{}, &models.AuditChainHead{},
		&models.AuditCheckpoint{}, &models.AuditSigningKey{}, &models.AuditManifest{}, &models.AuditRejection{}))

	var entries []models.AuditEntry
	require.NoError(t, dbPool.DB(ctx, true).Where("tenant_id = ?", "tenant-a").Order("seq").Find(&entries).Error)
	require.Len(t, entries, 3)
	for i, e := range entries {
		require.Equal(t, int64(i+1), e.Seq, "seq must be dense in created_at order")
		require.Equal(t, e.ID, e.EntryID, "legacy entry_id defaults to id")
		require.Equal(t, "k1", e.KeyID)
		require.Equal(t, int16(models.CanonVersionLegacy), e.CanonVersion)
		require.Equal(t, e.CreatedAt.UTC(), e.OccurredAt.UTC())
	}

	var heads []models.AuditChainHead
	require.NoError(t, dbPool.DB(ctx, true).Order("id").Find(&heads).Error)
	require.Len(t, heads, 2)
	require.Equal(t, "tenant-a", heads[0].ID)
	require.Equal(t, int64(3), heads[0].Seq)
	require.Equal(t, "hash-tenant-a-02", heads[0].EntryHash)
	require.Equal(t, int64(2), heads[1].Seq)

	// Re-running is a no-op for already sequenced rows.
	require.NoError(t, dbPool.Migrate(ctx, migrationPath, &models.AuditEntry{}))
	var count int64
	require.NoError(t, dbPool.DB(ctx, true).Model(&models.AuditEntry{}).Where("seq = 0").Count(&count).Error)
	require.Zero(t, count)

	// Immutability trigger blocks UPDATE and DELETE.
	err := dbPool.DB(ctx, false).Exec("UPDATE audit_entries SET action = 'x' WHERE id = 'tenant-a-00'").Error
	require.ErrorContains(t, err, "append-only")
	err = dbPool.DB(ctx, false).Exec("DELETE FROM audit_entries WHERE id = 'tenant-a-00'").Error
	require.ErrorContains(t, err, "append-only")
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
