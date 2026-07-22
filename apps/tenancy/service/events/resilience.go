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

package events

import (
	"context"
	"errors"
	"time"

	"github.com/pitabwire/frame/v2/security"
	"github.com/pitabwire/frame/v2/security/authorizer"
	"github.com/pitabwire/util"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gorm.io/gorm"
)

const (
	// eventExecutionTimeout is the maximum time an event handler may run
	// once it has started real work (after any concurrency-slot wait).
	// Keto batch writes for large SA trees can exceed 30s under load.
	eventExecutionTimeout = 2 * time.Minute

	// serviceAccountSyncTimeout covers partition_tree materialisation of
	// multi-namespace SA policies (hundreds of granted_* tuples) without
	// competing with short-lived partition/access sync handlers.
	serviceAccountSyncTimeout = 5 * time.Minute

	// maxKetoRetries is the number of times a transient Keto write is
	// retried within a single handler execution before giving up.
	maxKetoRetries = 3

	// ketoRetryBaseDelay is the initial backoff between Keto retries.
	ketoRetryBaseDelay = 500 * time.Millisecond

	// ketoWriteChunkSize bounds each WriteTuples call. Frame's authorizer
	// does a ListRelationTuples existence check per tuple before the batch
	// insert; huge single calls blow past queue push deadlines under load.
	ketoWriteChunkSize = 32
)

// isPermanentError returns true for errors that should not be retried inside
// one handler execution. Stateful reconcilers record these failures before
// acknowledging asynchronous events; startup reconciliation still fails closed.
func isPermanentError(err error) bool {
	if err == nil {
		return false
	}

	// GORM record-not-found: the DB row was deleted between emit and execute.
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return true
	}

	// gRPC status codes that indicate bad data or missing resources.
	if st, ok := status.FromError(err); ok {
		switch st.Code() {
		case codes.NotFound,
			codes.InvalidArgument,
			codes.AlreadyExists,
			codes.PermissionDenied,
			codes.Unauthenticated,
			codes.FailedPrecondition,
			codes.Unimplemented:
			return true
		}
	}

	// Unwrap AuthzServiceError and check the inner gRPC status.
	var authzErr *authorizer.AuthzServiceError
	if errors.As(err, &authzErr) {
		return isPermanentError(authzErr.Unwrap())
	}

	return false
}

// withEventTimeout returns a child context with eventExecutionTimeout,
// detached from the parent. Frame queue push handlers default to a ~25s
// request deadline; without detaching, Keto schema writes fail with
// "context deadline exceeded" long before eventExecutionTimeout elapses.
func withEventTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), eventExecutionTimeout)
}

// withServiceAccountSyncTimeout is the SA materialisation variant of
// withEventTimeout — longer ceiling, still detached from queue push parent.
func withServiceAccountSyncTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), serviceAccountSyncTimeout)
}

// writeTuplesWithRetry wraps an authorizer WriteTuples call with bounded
// retries for transient errors and immediate exit for permanent ones. Errors
// are returned to the event manager so failed mutations are never acknowledged
// as successful; queue retry/dead-letter policy and periodic reconciliation
// provide bounded recovery.
func writeTuplesWithRetry(ctx context.Context, eventName string, fn func(ctx context.Context) error) error {
	logger := util.Log(ctx).WithField("event", eventName)

	var lastErr error
	for attempt := 1; attempt <= maxKetoRetries; attempt++ {
		lastErr = fn(ctx)
		if lastErr == nil {
			return nil
		}

		if isPermanentError(lastErr) {
			logger.WithError(lastErr).WithField("attempt", attempt).
				Error("authorization mutation rejected")
			return lastErr
		}

		if attempt < maxKetoRetries {
			delay := ketoRetryBaseDelay * time.Duration(1<<(attempt-1))
			logger.WithError(lastErr).WithFields(map[string]any{
				"attempt":    attempt,
				"next_delay": delay,
			}).Warn("transient error in authz sync — retrying")

			select {
			case <-ctx.Done():
				logger.WithError(ctx.Err()).Warn("context cancelled during retry backoff")
				return ctx.Err()
			case <-time.After(delay):
			}
		}
	}

	// All retries exhausted. Return the cause so the event is not falsely ACKed.
	logger.WithError(lastErr).WithField("max_retries", maxKetoRetries).
		Error("authorization mutation failed after bounded retries")
	return lastErr
}

// writeTupleChunks writes relation tuples in fixed-size chunks so each
// authorizer.WriteTuples call stays short (existence-check + insert).
// Chunks are independently retried; completed chunks are not re-written
// on a later chunk failure (WriteTuples is idempotent).
func writeTupleChunks(
	ctx context.Context,
	eventName string,
	tuples []security.RelationTuple,
	write func(ctx context.Context, chunk []security.RelationTuple) error,
) error {
	if len(tuples) == 0 {
		return nil
	}
	for i := 0; i < len(tuples); i += ketoWriteChunkSize {
		end := i + ketoWriteChunkSize
		if end > len(tuples) {
			end = len(tuples)
		}
		chunk := tuples[i:end]
		chunkName := eventName
		if len(tuples) > ketoWriteChunkSize {
			chunkName = eventName + ".chunk"
		}
		if err := writeTuplesWithRetry(ctx, chunkName, func(ctx context.Context) error {
			return write(ctx, chunk)
		}); err != nil {
			return err
		}
	}
	return nil
}
