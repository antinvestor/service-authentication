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

package business_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/pitabwire/frame/v3/security"
	"github.com/stretchr/testify/require"

	"github.com/antinvestor/service-authentication/apps/audit/service/business"
)

// serviceTokenClaims decodes an access-token payload shaped like the one
// Hydra mints from the token hook's service-account claims.
func serviceTokenClaims(t *testing.T, payload string) context.Context {
	t.Helper()
	claims := &security.AuthenticationClaims{}
	require.NoError(t, json.Unmarshal([]byte(payload), claims))
	return claims.ClaimsToContext(context.Background())
}

// A service-account producer is bound to the service_name claim the token
// hook emits; it may log under that name and no other.
func TestCallerFromClaims_ServiceTokenBindsToServiceNameClaim(t *testing.T) {
	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)

	const (
		// Top-level claims mirrored from ext (Hydra mirror_top_level_claims).
		mirrored = `{"sub":"service-identity","tenant_id":"t1","partition_id":"p1","profile_id":"sa-profile",
			"roles":["internal"],"service_name":"service_identity",
			"ext":{"tenant_id":"t1","partition_id":"p1","profile_id":"sa-profile","roles":["internal"],
			"service_account_id":"sa-1","service_name":"service_identity"}}`
		// Claims under ext only.
		extOnly = `{"sub":"service-identity","ext":{"tenant_id":"t1","partition_id":"p1","profile_id":"sa-profile",
			"roles":["internal"],"service_account_id":"sa-1","service_name":"service_identity"}}`
		// What v1.54.97's token hook issued: no service_name at all.
		noServiceName = `{"sub":"service-identity","tenant_id":"t1","partition_id":"p1","profile_id":"sa-profile",
			"roles":["internal"],"ext":{"service_account_id":"sa-1"}}`
	)

	cases := []struct {
		name        string
		payload     string
		service     string
		wantBinding bool
	}{
		{name: "mirrored claim may log as its service", payload: mirrored, service: "service_identity"},
		{name: "ext-only claim may log as its service", payload: extOnly, service: "service_identity"},
		{name: "claim does not allow another service", payload: mirrored, service: "service_loans", wantBinding: true},
		{name: "token without service_name is refused", payload: noServiceName, service: "service_identity", wantBinding: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			caller := business.CallerFromClaims(serviceTokenClaims(t, tc.payload))
			require.Equal(t, "sa-1", caller.ServiceAccountID)

			req := validRequest()
			req.SetService(tc.service)
			req.SetProfileId("person-9")
			req.SetOnBehalfOf("person-9")

			v := business.NewValidator(fixedLookup(nil), false, business.DefaultDegradedWindow)
			got, verr := v.Validate(context.Background(), caller, req, now)
			if tc.wantBinding {
				require.NotNil(t, verr)
				require.Equal(t, business.ReasonServiceBinding, verr.Reason)
				require.Nil(t, got)
				return
			}
			require.Nil(t, verr, "expected acceptance, got %v", verr)
			require.Equal(t, "service_identity", caller.ServiceName)
			require.Equal(t, tc.service, got.Entry.Service)
		})
	}
}
