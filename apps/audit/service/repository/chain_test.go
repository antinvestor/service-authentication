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
	"sync"
	"testing"
	"time"

	"github.com/antinvestor/service-authentication/apps/audit/service/models"
	"github.com/stretchr/testify/require"
)

// TestChainRepository_CommitBatchSerialisesPerTenant proves the advisory
// lock plus FOR UPDATE head read give every committer a fresh head: two
// concurrent CommitBatch calls on one tenant observe seq 0 then seq 1.
func TestChainRepository_CommitBatchSerialisesPerTenant(t *testing.T) {
	ctx := t.Context()
	dbPool := newAuditRepositoryTestPool(t)
	require.NoError(t, dbPool.Migrate(ctx, migrationPath, &models.AuditEntry{}, &models.AuditIntake{},
		&models.AuditChainHead{}, &models.AuditCheckpoint{}, &models.AuditSigningKey{}, &models.AuditManifest{}, &models.AuditRejection{}))
	repo := NewChainRepository(dbPool)

	var mu sync.Mutex
	var observed []int64
	var wg sync.WaitGroup
	for i := range 2 {
		wg.Add(1)
		go func(delay time.Duration) {
			defer wg.Done()
			err := repo.CommitBatch(ctx, "t-lock", func(tx ChainTx) error {
				mu.Lock()
				observed = append(observed, tx.Head().Seq)
				mu.Unlock()
				time.Sleep(delay)
				return tx.AdvanceHead(tx.Head().Seq+1, "h")
			})
			require.NoError(t, err)
		}(time.Duration(300-100*i) * time.Millisecond)
		time.Sleep(20 * time.Millisecond)
	}
	wg.Wait()
	require.Equal(t, []int64{0, 1}, observed, "second committer must see the first commit")

	head := &models.AuditChainHead{}
	require.NoError(t, dbPool.DB(ctx, true).Where("id = ?", "t-lock").First(head).Error)
	require.Equal(t, int64(2), head.Seq)

	// A CAS with a stale expectation is refused.
	err := repo.CommitBatch(ctx, "t-lock", func(tx ChainTx) error {
		tx.Head().Seq = 0
		return tx.AdvanceHead(9, "x")
	})
	require.ErrorIs(t, err, ErrHeadConflict)
}
