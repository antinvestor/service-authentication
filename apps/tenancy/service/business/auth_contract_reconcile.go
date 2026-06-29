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

package business

import (
	"context"

	"github.com/antinvestor/service-authentication/apps/tenancy/service/events"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/repository"
	"github.com/pitabwire/frame/v2/data"
	fevents "github.com/pitabwire/frame/v2/events"
)

func ReQueueClientsForHydraSync(
	ctx context.Context,
	clientRepo repository.ClientRepository,
	eventsMan fevents.Manager,
	query *data.SearchQuery,
) error {
	jobResult, err := clientRepo.Search(ctx, query)
	if err != nil {
		return err
	}
	for {
		result, ok := jobResult.ReadResult(ctx)
		if !ok {
			return nil
		}
		if result.IsError() {
			return result.Error()
		}
		for _, client := range result.Item() {
			if emitErr := eventsMan.Emit(ctx, events.EventKeyClientSynchronization, data.JSONMap{"id": client.GetID()}); emitErr != nil {
				return emitErr
			}
		}
	}
}

func ReQueueServiceAccountPolicies(
	ctx context.Context,
	serviceAccountRepo repository.ServiceAccountRepository,
	policyRepo repository.ServiceAccountAuthorizationPolicyRepository,
	eventsMan fevents.Manager,
	query *data.SearchQuery,
) error {
	jobResult, err := serviceAccountRepo.Search(ctx, query)
	if err != nil {
		return err
	}
	for {
		result, ok := jobResult.ReadResult(ctx)
		if !ok {
			return nil
		}
		if result.IsError() {
			return result.Error()
		}
		for _, serviceAccount := range result.Item() {
			policy, policyErr := policyRepo.GetByServiceAccountID(ctx, serviceAccount.GetID())
			if policyErr != nil {
				return policyErr
			}
			if emitErr := eventsMan.Emit(ctx, events.EventKeyAuthzServiceAccountSync, data.JSONMap{
				"id":         serviceAccount.GetID(),
				"generation": policy.Policy.Generation,
				"reason":     "periodic_repair",
			}); emitErr != nil {
				return emitErr
			}
		}
	}
}
