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

package handlers

import (
	"errors"
	"fmt"
	"testing"

	"connectrpc.com/connect/v2"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/repository"
	"github.com/stretchr/testify/require"
)

func TestToAPIError_UpdateConflictMapsToAborted(t *testing.T) {
	srv := &TenancyServer{}

	err := srv.toAPIError(fmt.Errorf("%w: id=x version=0", repository.ErrUpdateConflict))

	var cerr *connect.Error
	require.True(t, errors.As(err, &cerr), "expected a connect error, got %T", err)
	require.Equal(t, connect.CodeAborted, cerr.Code())
	require.ErrorIs(t, err, repository.ErrUpdateConflict)
}
