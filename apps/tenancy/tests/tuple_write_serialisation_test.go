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

package tests

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/antinvestor/service-authentication/apps/tenancy/service/authz"
	"github.com/pitabwire/frame/v2/datastore"
	"github.com/pitabwire/frame/v2/frametests/definition"
	"github.com/pitabwire/frame/v2/security"
	"github.com/pitabwire/util"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

// TupleWriteSerialisationTestSuite proves that Keto relation-tuple writes are
// idempotent under concurrency and retries.
//
// Keto v0.12 has no uniqueness constraint on tuple content, and Frame's
// WriteTuples is read-then-insert. Without cross-process serialisation,
// concurrent writers of the same tuple (service setup Jobs racing runtime
// reconcilers at deploy time) each pass the existence check and each insert,
// growing exact-duplicate tuples by ~1 per deploy. authz.SerialisedAuthorizer
// closes that window with a shared Postgres advisory lock.
type TupleWriteSerialisationTestSuite struct {
	BaseTestSuite
}

func TestTupleWriteSerialisationTestSuite(t *testing.T) {
	suite.Run(t, new(TupleWriteSerialisationTestSuite))
}

// racyTupleStore reproduces the Keto + Frame write path shape: an existence
// check followed, after a window, by a blind append with no uniqueness
// enforcement. The delay makes the read-then-insert race deterministic.
type racyTupleStore struct {
	security.Authorizer // unused methods are never called

	checkDelay time.Duration

	mu     sync.Mutex
	tuples []security.RelationTuple
}

func (s *racyTupleStore) WriteTuples(_ context.Context, tuples []security.RelationTuple) error {
	missing := make([]security.RelationTuple, 0, len(tuples))
	for _, t := range tuples {
		if s.count(t) == 0 {
			missing = append(missing, t)
		}
	}
	time.Sleep(s.checkDelay)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tuples = append(s.tuples, missing...)
	return nil
}

func (s *racyTupleStore) WriteTuple(ctx context.Context, tuple security.RelationTuple) error {
	return s.WriteTuples(ctx, []security.RelationTuple{tuple})
}

func (s *racyTupleStore) count(tuple security.RelationTuple) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, t := range s.tuples {
		if t == tuple {
			n++
		}
	}
	return n
}

func writeSameTupleConcurrently(t *testing.T, ctx context.Context, auth security.Authorizer, tuple security.RelationTuple, writers int) {
	t.Helper()
	start := make(chan struct{})
	errs := make(chan error, writers)
	var wg sync.WaitGroup
	for range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs <- auth.WriteTuples(ctx, []security.RelationTuple{tuple})
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
}

// TestUnserialisedWritesDuplicate documents the root cause: without the
// advisory lock, every concurrent writer passes the existence check before
// any of them inserts, so the same tuple is stored once per writer.
func (suite *TupleWriteSerialisationTestSuite) TestUnserialisedWritesDuplicate() {
	t := suite.T()
	ctx := t.Context()

	const writers = 4
	store := &racyTupleStore{checkDelay: 100 * time.Millisecond}
	tuple := authz.BuildServiceAccessTuple("tenant-x/partition-x", "bot-profile-x")

	writeSameTupleConcurrently(t, ctx, store, tuple, writers)

	require.Equal(t, writers, store.count(tuple),
		"read-then-insert without serialisation must duplicate once per concurrent writer — "+
			"if this fails the fixture no longer models the race")
}

// TestSerialisedWritesStayExactUnderConcurrency proves the fix on the same
// deterministic race fixture: with the advisory lock, exactly one copy is
// stored no matter how many writers race.
func (suite *TupleWriteSerialisationTestSuite) TestSerialisedWritesStayExactUnderConcurrency() {
	t := suite.T()
	ctx, svc, _ := suite.CreateService(t, definition.NewDependancyOption(
		"tuple_serialisation", util.RandomAlphaNumericString(8), nil))

	const writers = 4
	store := &racyTupleStore{checkDelay: 100 * time.Millisecond}
	dbPool := svc.DatastoreManager().GetPool(ctx, datastore.DefaultPoolName)
	serialised := authz.NewSerialisedTupleAuthorizer(store, dbPool)
	tuple := authz.BuildServiceAccessTuple("tenant-y/partition-y", "bot-profile-y")

	writeSameTupleConcurrently(t, ctx, serialised, tuple, writers)

	require.Equal(t, 1, store.count(tuple),
		"serialised writes must store exactly one copy under concurrent writers")

	// Retried / re-deployed writes stay idempotent.
	require.NoError(t, serialised.WriteTuples(ctx, []security.RelationTuple{tuple}))
	require.Equal(t, 1, store.count(tuple), "re-running the same write must not duplicate")
}

// TestSerialisedWritesAgainstKetoStayExact runs the production write path —
// authz.SerialisedAuthorizer over Frame's Keto adapter against a real Keto —
// with concurrent writers and a re-run, asserting Keto never accumulates
// duplicate tuples for the service-bot bootstrap tuple shape.
func (suite *TupleWriteSerialisationTestSuite) TestSerialisedWritesAgainstKetoStayExact() {
	t := suite.T()
	ctx, svc, _ := suite.CreateService(t, definition.NewDependancyOption(
		"tuple_serialisation_keto", util.RandomAlphaNumericString(8), nil))

	serialised := authz.SerialisedAuthorizer(ctx, svc)

	tenancyPath := "tenant-keto/partition-keto"
	profileID := "bot-profile-keto"
	tuple := authz.BuildServiceAccessTuple(tenancyPath, profileID)

	const writers = 6
	writeSameTupleConcurrently(t, ctx, serialised, tuple, writers)

	countStored := func() int {
		stored, err := serialised.ListRelations(ctx, tuple.Object)
		require.NoError(t, err)
		n := 0
		for _, st := range stored {
			if st.Relation == tuple.Relation && st.Subject.ID == tuple.Subject.ID {
				n++
			}
		}
		return n
	}

	require.Equal(t, 1, countStored(),
		"concurrent bootstrap writers must leave exactly one tuple in Keto")

	// Simulate the next deploy re-running the bootstrap.
	require.NoError(t, serialised.WriteTuples(ctx, []security.RelationTuple{tuple}))
	require.Equal(t, 1, countStored(),
		"re-running the bootstrap must not grow the tuple count")
}
