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
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/antinvestor/service-authentication/apps/audit/service/models"
	"github.com/pitabwire/frame/v2/data"
	"github.com/pitabwire/frame/v2/datastore/pool"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	tcPostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

func TestAuditEntryRepository_ListAndSearchUseCreatedAtKeysetPagination(t *testing.T) {
	ctx := t.Context()
	dbPool := newAuditRepositoryTestPool(t)
	require.NoError(t, dbPool.DB(ctx, false).AutoMigrate(&models.AuditEntry{}))

	repo := NewAuditEntryRepository(dbPool)
	base := time.Date(2026, 6, 18, 4, 30, 0, 0, time.UTC)
	fixtures := []*models.AuditEntry{
		newAuditEntry("z-old", base.Add(-2*time.Hour), "profile-1", "login.started", "hash-old"),
		newAuditEntry("m-mid", base.Add(-1*time.Hour), "profile-1", "login.completed", "hash-mid"),
		newAuditEntry("a-new", base, "profile-1", "login.completed", "hash-new"),
	}
	for i, entry := range fixtures {
		entry.Seq = int64(i + 1)
		require.NoError(t, dbPool.DB(ctx, false).Create(entry).Error)
	}

	firstPage, err := repo.List(ctx, &AuditFilter{ProfileID: "profile-1", Limit: 2})
	require.NoError(t, err)
	require.Equal(t, []string{"a-new", "m-mid"}, auditEntryIDs(firstPage))

	secondPage, err := repo.List(ctx, &AuditFilter{ProfileID: "profile-1", Cursor: "m-mid", Limit: 2})
	require.NoError(t, err)
	require.Equal(t, []string{"z-old"}, auditEntryIDs(secondPage))

	searchPage, err := repo.Search(ctx, "login", nil, nil, 2, "a-new")
	require.NoError(t, err)
	require.Equal(t, []string{"m-mid", "z-old"}, auditEntryIDs(searchPage))
}

func TestAuditEntryRepository_SeqQueriesWalkTheChainInOrder(t *testing.T) {
	ctx := t.Context()
	dbPool := newAuditRepositoryTestPool(t)
	require.NoError(t, dbPool.DB(ctx, false).AutoMigrate(&models.AuditEntry{}))

	repo := NewAuditEntryRepository(dbPool)
	base := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	for i := range 25 {
		id := fmt.Sprintf("batch-%02d", i)
		e := newAuditEntry(id, base.Add(time.Duration(i)*time.Second), "profile-batch", "audit.batch_test", fmt.Sprintf("hash-batch-%02d", i))
		e.Seq = int64(i + 1)
		require.NoError(t, dbPool.DB(ctx, false).Create(e).Error)
	}

	page, err := repo.ListChainBySeq(ctx, "tenant-1", 5, 0, 10)
	require.NoError(t, err)
	require.Len(t, page, 10)
	require.Equal(t, int64(5), page[0].Seq)
	require.Equal(t, int64(14), page[9].Seq)

	bounded, err := repo.ListChainBySeq(ctx, "tenant-1", 20, 22, 1000)
	require.NoError(t, err)
	require.Equal(t, []string{"batch-19", "batch-20", "batch-21"}, auditEntryIDs(bounded))

	one, err := repo.GetBySeq(ctx, "tenant-1", 7)
	require.NoError(t, err)
	require.Equal(t, "batch-06", one.ID)

	from, err := repo.SeqAtOrAfter(ctx, "tenant-1", base.Add(10*time.Second))
	require.NoError(t, err)
	require.Equal(t, int64(11), from)
	to, err := repo.SeqAtOrBefore(ctx, "tenant-1", base.Add(10*time.Second))
	require.NoError(t, err)
	require.Equal(t, int64(11), to)
	none, err := repo.SeqAtOrAfter(ctx, "tenant-1", base.Add(time.Hour))
	require.NoError(t, err)
	require.Zero(t, none)

	bySeq, err := repo.List(ctx, &AuditFilter{SeqFrom: 3, SeqTo: 6, Limit: 2})
	require.NoError(t, err)
	require.Equal(t, []string{"batch-02", "batch-03"}, auditEntryIDs(bySeq))
	next, err := repo.List(ctx, &AuditFilter{SeqFrom: 3, SeqTo: 6, Limit: 2, Cursor: "batch-03"})
	require.NoError(t, err)
	require.Equal(t, []string{"batch-04", "batch-05"}, auditEntryIDs(next))
}

func newAuditRepositoryTestPool(t *testing.T) pool.Pool {
	t.Helper()
	ctx := t.Context()

	container, err := tcPostgres.Run(
		ctx,
		"postgres:16-alpine",
		tcPostgres.WithDatabase("audit_repository_test"),
		tcPostgres.WithUsername("audit"),
		tcPostgres.WithPassword("audit"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(60*time.Second),
		),
	)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		require.NoError(t, container.Terminate(cleanupCtx))
	})

	dsn, err := container.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)

	dbPool := pool.NewPool(ctx, pool.WithTenancyProvider(nil))
	require.NoError(t, dbPool.AddConnection(ctx, pool.WithConnection(dsn, false),
		pool.WithPreferSimpleProtocol(true), pool.WithPreparedStatements(false)))
	t.Cleanup(func() {
		dbPool.Close(context.Background())
	})

	return dbPool
}

func newAuditEntry(id string, createdAt time.Time, profileID, action, hash string) *models.AuditEntry {
	return &models.AuditEntry{
		BaseModel: data.BaseModel{
			ID:          id,
			CreatedAt:   createdAt,
			ModifiedAt:  createdAt,
			Version:     1,
			TenantID:    "tenant-1",
			PartitionID: "partition-1",
		},
		ProfileID:    profileID,
		Action:       action,
		ResourceType: "session",
		ResourceID:   id,
		Service:      "service-authentication",
		PreviousHash: "previous-" + id,
		EntryHash:    hash,
		Signature:    "signature-" + id,
	}
}

func auditEntryIDs(entries []*models.AuditEntry) []string {
	ids := make([]string, 0, len(entries))
	for _, entry := range entries {
		ids = append(ids, entry.ID)
	}
	return ids
}
