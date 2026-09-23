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

package authz

import (
	"context"
	"fmt"

	"github.com/pitabwire/frame/v2"
	"github.com/pitabwire/frame/v2/datastore"
	"github.com/pitabwire/frame/v2/datastore/pool"
	"github.com/pitabwire/frame/v2/security"
	"gorm.io/gorm"
)

// Cross-process Postgres advisory lock identifying "Keto relation-tuple
// mutation in flight" for the tenancy service.
//
// Why this exists: Keto v0.12 stores relation tuples with no uniqueness
// constraint on tuple content (only a random shard_id primary key), and
// Frame's authorizer implements WriteTuples as read-then-insert — a
// ListRelationTuples existence check followed by TransactRelationTuples
// ACTION_INSERT. That sequence is not atomic: two writers of the same tuple
// running concurrently both observe "missing" and both insert, silently and
// permanently duplicating the tuple. Deploys guarantee such concurrency —
// every service's setup Job registers its permission manifest, each
// registration re-queues authorization.service_account.sync events, and those
// events are consumed in parallel (and concurrently with the tenancy setup
// Job's own bootstrap/reconciliation).
//
// Every tenancy process (setup Jobs and runtime pods) shares one Postgres
// database, so a transaction-scoped advisory lock held around each tuple
// mutation makes read-then-insert atomic across all of them without adding
// custom constraints to Keto's Ory-managed schema. The lock is released
// automatically on commit/rollback — including when a process dies mid-write.
const (
	ketoTupleMutationLockClass int32 = 0x7e9a
	ketoTupleMutationLockKey   int32 = 0x0001
)

// serialisedTupleAuthorizer decorates a security.Authorizer so tuple
// mutations run under the shared advisory lock. Read paths (Check,
// BatchCheck, ListRelations, Expand, …) delegate unchanged via embedding.
type serialisedTupleAuthorizer struct {
	security.Authorizer
	dbPool pool.Pool
}

// NewSerialisedTupleAuthorizer wraps base so that WriteTuple(s) and
// DeleteTuple(s) execute under a Postgres advisory lock shared by every
// tenancy process. Mutations fail closed when the lock cannot be acquired.
func NewSerialisedTupleAuthorizer(base security.Authorizer, dbPool pool.Pool) security.Authorizer {
	return &serialisedTupleAuthorizer{Authorizer: base, dbPool: dbPool}
}

// SerialisedAuthorizer returns the service's authorizer wrapped with
// cross-process tuple-write serialisation. All tenancy code that mutates
// Keto tuples must obtain its authorizer through this helper (or
// NewSerialisedTupleAuthorizer) — never from SecurityManager directly.
func SerialisedAuthorizer(ctx context.Context, svc *frame.Service) security.Authorizer {
	return NewSerialisedTupleAuthorizer(
		svc.SecurityManager().GetAuthorizer(ctx),
		svc.DatastoreManager().GetPool(ctx, datastore.DefaultPoolName),
	)
}

func (a *serialisedTupleAuthorizer) WriteTuple(ctx context.Context, tuple security.RelationTuple) error {
	return a.withTupleMutationLock(ctx, "write_tuple", func(ctx context.Context) error {
		return a.Authorizer.WriteTuple(ctx, tuple)
	})
}

func (a *serialisedTupleAuthorizer) WriteTuples(ctx context.Context, tuples []security.RelationTuple) error {
	if len(tuples) == 0 {
		return nil
	}
	return a.withTupleMutationLock(ctx, "write_tuples", func(ctx context.Context) error {
		return a.Authorizer.WriteTuples(ctx, tuples)
	})
}

func (a *serialisedTupleAuthorizer) DeleteTuple(ctx context.Context, tuple security.RelationTuple) error {
	return a.withTupleMutationLock(ctx, "delete_tuple", func(ctx context.Context) error {
		return a.Authorizer.DeleteTuple(ctx, tuple)
	})
}

func (a *serialisedTupleAuthorizer) DeleteTuples(ctx context.Context, tuples []security.RelationTuple) error {
	if len(tuples) == 0 {
		return nil
	}
	return a.withTupleMutationLock(ctx, "delete_tuples", func(ctx context.Context) error {
		return a.Authorizer.DeleteTuples(ctx, tuples)
	})
}

// withTupleMutationLock runs fn while holding the advisory lock inside a
// database transaction. The transaction exists only to scope the lock; fn
// performs Keto RPCs, not database work, so no queries join it. Chunked
// callers acquire the lock once per chunk, which keeps other writers from
// starving during large bootstraps.
func (a *serialisedTupleAuthorizer) withTupleMutationLock(
	ctx context.Context,
	op string,
	fn func(ctx context.Context) error,
) error {
	if a.dbPool == nil {
		return fmt.Errorf("authz %s: database pool is required to serialise keto tuple mutations", op)
	}
	db := a.dbPool.DB(ctx, false)
	if db == nil {
		return fmt.Errorf("authz %s: writable database connection is required to serialise keto tuple mutations", op)
	}
	return db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec(
			"SELECT pg_advisory_xact_lock(?, ?)",
			ketoTupleMutationLockClass, ketoTupleMutationLockKey,
		).Error; err != nil {
			return fmt.Errorf("authz %s: acquire keto tuple mutation lock: %w", op, err)
		}
		return fn(ctx)
	})
}
