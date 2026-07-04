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

package handlers_test

import (
	"testing"

	"github.com/antinvestor/service-authentication/apps/default/service/handlers"
	"github.com/antinvestor/service-authentication/apps/default/service/models"
	"github.com/pitabwire/frame/v2/data"
	"github.com/stretchr/testify/require"
)

func TestBuildUserTokenClaims_IncludesAllRequiredKeys(t *testing.T) {
	ev := &models.LoginEvent{
		ClientID:        "client_A",
		ProfileID:       "prof_1",
		Oauth2SessionID: "oauth_sess_1",
		ContactID:       "contact_1",
		AccessID:        "access_1",
		DeviceID:        "dev_1",
	}
	ev.BaseModel = data.BaseModel{}
	ev.ID = "login_evt_1"
	ev.TenantID = "tenant_1"
	ev.PartitionID = "part_1"

	claims := handlers.BuildUserTokenClaims(ev, "prof_1", "dev_1", []string{"user"})

	require.Equal(t, "tenant_1", claims["tenant_id"])
	require.Equal(t, "part_1", claims["partition_id"])
	require.Equal(t, "prof_1", claims["profile_id"])
	require.Equal(t, "dev_1", claims["device_id"])
	require.Equal(t, "login_evt_1", claims["login_event_id"])
	require.Equal(t, "oauth_sess_1", claims["oauth2_session_id"])
	require.Equal(t, "contact_1", claims["contact_id"])
	require.Equal(t, "access_1", claims["access_id"])
	require.Equal(t, []string{"user"}, claims["roles"])
}
