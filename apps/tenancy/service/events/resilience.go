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

	"github.com/pitabwire/frame/v2/security/authorizer"
	"github.com/pitabwire/util"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gorm.io/gorm"
)

const (
	// eventExecutionTimeout is the maximum time an event handler may run
	// before the context is cancelled. This prevents handlers from hanging
	// indefinitely on slow downstream calls.
	eventExecutionTimeout = 30 * time.Second

	// maxKetoRetries is the number of times a transient Keto write is
	// retried within a single handler execution before giving up.
	maxKetoRetries = 3

	// ketoRetryBaseDelay is the initial backoff between Keto retries.
	ketoRetryBaseDelay = 500 * time.Millisecond
)

// isPermanentError returns true for errors that should not be retried inside
// one handler execution. The handler still returns the error so queue policy,
// policy status, startup reconciliation, and operational alerts remain active.
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

// withEventTimeout returns a child context with eventExecutionTimeout.
func withEventTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, eventExecutionTimeout)
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
