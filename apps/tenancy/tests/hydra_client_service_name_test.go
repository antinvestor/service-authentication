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
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/pitabwire/frame/v3/client"
	"github.com/pitabwire/frame/v3/data"
	"github.com/pitabwire/frame/v3/frametests/definition"
	"github.com/pitabwire/frame/v3/security"
	"github.com/pitabwire/util"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	aconfig "github.com/antinvestor/service-authentication/apps/tenancy/config"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/events"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/models"
)

// HydraClientServiceNameTestSuite checks that syncing a service-account
// client to Hydra records the service account's name in the client metadata,
// where the token hook reads it to emit the service_name claim.
type HydraClientServiceNameTestSuite struct {
	BaseTestSuite
}

func TestHydraClientServiceNameTestSuite(t *testing.T) {
	suite.Run(t, new(HydraClientServiceNameTestSuite))
}

func (suite *HydraClientServiceNameTestSuite) TestClientSyncRecordsServiceNameInHydraMetadata() {
	t := suite.T()
	ctx, svc, deps := suite.CreateService(t, definition.NewDependancyOption("hydra_service_name", util.RandomAlphaNumericString(8), nil))
	ctx = security.SkipTenancyChecksOnClaims(ctx)
	cfg, ok := svc.Config().(*aconfig.TenancyConfig)
	require.True(t, ok)

	hydraCli := client.NewManager(t.Context())
	defer hydraCli.Close()

	saCtx := suite.WithAuthClaims(ctx, "tenant-sn", "partition-sn", "profile-sn")
	clientID := "svc-name-" + util.RandomAlphaNumericString(8)
	profileID := util.IDString()

	sa := &models.ServiceAccount{Name: "service_identity", ProfileID: profileID, ClientID: clientID, Type: "internal"}
	sa.GenID(saCtx)
	cl := &models.Client{
		Name:                    "sa-service_identity",
		ClientID:                clientID,
		ClientSecret:            util.RandomAlphaNumericString(24),
		Type:                    "internal",
		GrantTypes:              data.JSONMap{"types": []any{"client_credentials"}},
		Scopes:                  "system_int openid",
		TokenEndpointAuthMethod: "client_secret_post",
		ServiceAccountID:        sa.GetID(),
	}
	cl.GenID(saCtx)
	sa.ClientRef = cl.GetID()
	require.NoError(t, deps.ServiceAccountRepo.Create(saCtx, sa))
	require.NoError(t, deps.ClientRepo.Create(saCtx, cl))

	handler := events.NewClientSynchronizationEventHandler(
		ctx, cfg, hydraCli, deps.ClientRepo, deps.OAuthRecipientRepo, deps.ServiceAccountRepo,
	)
	// The sync event may carry profile_id already; the service name must
	// still be resolved from the service account record.
	payload := map[string]any{"id": cl.GetID(), "profile_id": profileID}
	require.NoError(t, handler.Execute(ctx, &payload))

	url := fmt.Sprintf("%s/admin/clients/%s", cfg.GetOauth2ServiceAdminURI(), clientID)
	resp, err := hydraCli.Invoke(ctx, http.MethodGet, url, nil, nil)
	require.NoError(t, err)
	body, err := resp.ToContent(ctx)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode, "hydra client: %s", body)

	var hydraClient struct {
		Metadata map[string]any `json:"metadata"`
	}
	require.NoError(t, json.Unmarshal(body, &hydraClient))
	require.Equal(t, "service_identity", hydraClient.Metadata["service_name"])
	require.Equal(t, profileID, hydraClient.Metadata["profile_id"])
}
