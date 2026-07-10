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

	"github.com/pitabwire/util"
)

// serviceBotContext returns a context for service-to-service calls made by the
// authentication service bot during login orchestration.
//
// Why this exists (three authorization planes):
//
//  1. Plane 1 (tenancy_access): system_internal callers are checked with the
//     "service" relation on claims.TenantID/PartitionID. Frame's
//     ClaimsFromContext merges util.GetTenancy secondary claims for internal
//     bots. If login code does util.SetTenancy(ctx, loginEvent) with the
//     OAuth client's product partition, Plane 1 is evaluated on that path
//     (e.g. opportunities). The bot typically only has service on its home
//     (root) partition → permission_denied: cannot service on tenancy_access:…
//
//  2. Plane 2 (RPC / function permissions): remains enforced against the bot's
//     JWT home path after clearing secondary tenancy.
//
//  3. Plane 3 (resource): not used on profile GetByContact/Create for login.
//
// Clearing secondary tenancy restores JWT home tenancy for outbound profile /
// device / notification calls. Callers that need user-partition tenancy for
// access provisioning should use withUserLoginTenancy after S2S identity work.
func serviceBotContext(ctx context.Context) context.Context {
	// nil TenancyInfo clears secondary claims so ClaimsFromContext uses JWT.
	return util.SetTenancy(ctx, nil)
}

// withUserLoginTenancy sets secondary tenancy from the login event for
// operations that must run in the OAuth client's partition (e.g. creating
// Access rows). Prefer serviceBotContext for pure identity S2S lookups.
func withUserLoginTenancy(ctx context.Context, tenancy util.TenancyInfo) context.Context {
	if tenancy == nil {
		return serviceBotContext(ctx)
	}
	return util.SetTenancy(ctx, tenancy)
}
