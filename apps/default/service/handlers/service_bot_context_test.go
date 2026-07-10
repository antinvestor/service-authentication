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
	"context"
	"testing"

	"github.com/antinvestor/service-authentication/apps/default/service/models"
	"github.com/pitabwire/frame/v2/data"
	"github.com/pitabwire/util"
	"github.com/stretchr/testify/require"
)

func TestServiceBotContext_ClearsSecondaryTenancy(t *testing.T) {
	t.Parallel()

	evt := &models.LoginEvent{
		BaseModel: data.BaseModel{
			TenantID:    "d7gi6lkpf2t67dlsqre0",
			PartitionID: "d7gi6lkpf2t67dlsqreg",
		},
	}
	ctx := util.SetTenancy(context.Background(), evt)
	require.NotNil(t, util.GetTenancy(ctx))
	require.Equal(t, evt.GetPartitionID(), util.GetTenancy(ctx).GetPartitionID())

	botCtx := serviceBotContext(ctx)
	// Secondary tenancy must not survive; plane-1 checks use JWT home path.
	require.Nil(t, util.GetTenancy(botCtx))
}

func TestWithUserLoginTenancy(t *testing.T) {
	t.Parallel()

	evt := &models.LoginEvent{
		BaseModel: data.BaseModel{
			TenantID:    "tenant-a",
			PartitionID: "part-a",
		},
	}
	ctx := withUserLoginTenancy(context.Background(), evt)
	ti := util.GetTenancy(ctx)
	require.NotNil(t, ti)
	require.Equal(t, "tenant-a", ti.GetTenantID())
	require.Equal(t, "part-a", ti.GetPartitionID())

	require.Nil(t, util.GetTenancy(withUserLoginTenancy(context.Background(), nil)))
}
