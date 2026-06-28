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
	"testing"

	"github.com/pitabwire/frame/security/authorizer"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gorm.io/gorm"
)

func TestIsPermanentError(t *testing.T) {
	tests := []struct {
		name      string
		err       error
		permanent bool
	}{
		{"nil error", nil, false},
		{"generic error", errors.New("something broke"), false},
		{"gorm not found", gorm.ErrRecordNotFound, true},
		{"grpc not found", status.Error(codes.NotFound, "not found"), true},
		{"grpc invalid argument", status.Error(codes.InvalidArgument, "bad arg"), true},
		{"grpc already exists", status.Error(codes.AlreadyExists, "exists"), true},
		{"grpc permission denied", status.Error(codes.PermissionDenied, "denied"), true},
		{"grpc unauthenticated", status.Error(codes.Unauthenticated, "unauth"), true},
		{"grpc failed precondition", status.Error(codes.FailedPrecondition, "precondition"), true},
		{"grpc unimplemented", status.Error(codes.Unimplemented, "not impl"), true},
		{"grpc unavailable (transient)", status.Error(codes.Unavailable, "down"), false},
		{"grpc deadline exceeded (transient)", status.Error(codes.DeadlineExceeded, "timeout"), false},
		{"grpc internal (transient)", status.Error(codes.Internal, "oops"), false},
		{"wrapped authz error permanent", authorizer.NewAuthzServiceError("write", status.Error(codes.NotFound, "ns missing")), true},
		{"wrapped authz error transient", authorizer.NewAuthzServiceError("write", status.Error(codes.Unavailable, "down")), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.permanent, isPermanentError(tt.err))
		})
	}
}

func TestWriteTuplesWithRetry_Success(t *testing.T) {
	ctx := context.Background()
	calls := 0
	err := writeTuplesWithRetry(ctx, "test", func(_ context.Context) error {
		calls++
		return nil
	})
	assert.NoError(t, err)
	assert.Equal(t, 1, calls)
}

func TestWriteTuplesWithRetry_PermanentError(t *testing.T) {
	ctx := context.Background()
	calls := 0
	err := writeTuplesWithRetry(ctx, "test", func(_ context.Context) error {
		calls++
		return status.Error(codes.NotFound, "namespace not found")
	})
	assert.Error(t, err)
	assert.Equal(t, 1, calls, "should not retry permanent errors")
}

func TestWriteTuplesWithRetry_TransientThenSuccess(t *testing.T) {
	ctx := context.Background()
	calls := 0
	err := writeTuplesWithRetry(ctx, "test", func(_ context.Context) error {
		calls++
		if calls < 3 {
			return status.Error(codes.Unavailable, "keto down")
		}
		return nil
	})
	assert.NoError(t, err)
	assert.Equal(t, 3, calls)
}

func TestWriteTuplesWithRetry_ExhaustsRetries(t *testing.T) {
	ctx := context.Background()
	calls := 0
	err := writeTuplesWithRetry(ctx, "test", func(_ context.Context) error {
		calls++
		return status.Error(codes.Unavailable, "keto down")
	})
	assert.Error(t, err)
	assert.Equal(t, maxKetoRetries, calls)
}

func TestWriteTuplesWithRetry_ContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	err := writeTuplesWithRetry(ctx, "test", func(_ context.Context) error {
		calls++
		cancel() // cancel during first retry backoff
		return status.Error(codes.Unavailable, "keto down")
	})
	assert.ErrorIs(t, err, context.Canceled)
}

func TestWithEventTimeout(t *testing.T) {
	ctx := context.Background()
	tctx, cancel := withEventTimeout(ctx)
	defer cancel()

	deadline, ok := tctx.Deadline()
	assert.True(t, ok, "should have a deadline")
	assert.False(t, deadline.IsZero())
}
