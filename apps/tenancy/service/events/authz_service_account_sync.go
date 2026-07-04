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
	"fmt"

	"github.com/antinvestor/service-authentication/apps/tenancy/service/authz"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/repository"
	"github.com/pitabwire/frame/v2/data"
	fevents "github.com/pitabwire/frame/v2/events"
	"github.com/pitabwire/frame/v2/security"
	"github.com/pitabwire/util"
)

const EventKeyAuthzServiceAccountSync = "authorization.service_account.sync"

// AuthzServiceAccountSyncEvent writes Keto tuples for a service account after
// it is created or during bulk sync.
//
// For each service account it writes:
//   - tenancy_access:tenancyPath#member ← profile_user:profileID  (data access)
//   - tenancy_access:tenancyPath#service ← profile_user:profileID (service marker)
//   - Per-audience explicit permission tuples: ns:tenancyPath#granted_{perm} ← profile_user:profileID
type AuthzServiceAccountSyncEvent struct {
	serviceAccountRepo repository.ServiceAccountRepository
	authorizer         security.Authorizer
}

func NewAuthzServiceAccountSyncEventHandler(
	serviceAccountRepo repository.ServiceAccountRepository,
	auth security.Authorizer,
) fevents.EventI {
	return &AuthzServiceAccountSyncEvent{
		serviceAccountRepo: serviceAccountRepo,
		authorizer:         auth,
	}
}

func (e *AuthzServiceAccountSyncEvent) Name() string {
	return EventKeyAuthzServiceAccountSync
}

func (e *AuthzServiceAccountSyncEvent) PayloadType() any {
	var payloadT map[string]any
	return &payloadT
}

func (e *AuthzServiceAccountSyncEvent) Validate(_ context.Context, payload any) error {
	d, ok := payload.(*map[string]any)
	if !ok {
		return fmt.Errorf("invalid payload type, expected *map[string]any got %T", payload)
	}
	m := data.JSONMap(*d)
	if m.GetString("id") == "" {
		return errors.New("service account id is required")
	}
	return nil
}

func (e *AuthzServiceAccountSyncEvent) Execute(ictx context.Context, payload any) error {
	d, ok := payload.(*map[string]any)
	if !ok {
		return fmt.Errorf("invalid payload type, expected *map[string]any got %T", payload)
	}

	jsonPayload := data.JSONMap(*d)
	ctx := security.SkipTenancyChecksOnClaims(ictx)
	ctx, cancel := withEventTimeout(ctx)
	defer cancel()

	serviceAccountID := jsonPayload.GetString("id")
	logger := util.Log(ctx).WithFields(map[string]any{
		"service_account_id": serviceAccountID,
		"type":               e.Name(),
	})

	sa, err := e.serviceAccountRepo.GetByID(ctx, serviceAccountID)
	if err != nil {
		if isPermanentError(err) {
			logger.WithError(err).Warn("service account not found — skipping sync")
			return nil
		}
		return fmt.Errorf("failed to get service account %s: %w", serviceAccountID, err)
	}

	tenancyPath := fmt.Sprintf("%s/%s", sa.TenantID, sa.PartitionID)
	subjectID := sa.ProfileID

	// Data access is always keyed by the service account's stable profile
	// identity. Hydra is configured to issue that identity as the token subject;
	// OAuth client IDs are credentials, not authorization principals.
	tuples := []security.RelationTuple{
		authz.BuildAccessTuple(tenancyPath, subjectID),
		authz.BuildServiceAccessTuple(tenancyPath, subjectID),
	}

	namespaces := authz.DeployedServiceNamespaceRecords()
	requestedGrants := authz.SelectRegisteredServiceGrants(
		authz.ParseAudiencePermissions(sa.Audiences),
		namespaces,
	)
	grants, err := authz.ResolveServiceGrants(requestedGrants, namespaces)
	if err != nil {
		return fmt.Errorf("invalid service account authorization grants: %w", err)
	}
	for namespace, permissions := range grants {
		tuples = append(tuples, authz.BuildServicePermissionTuples(
			tenancyPath,
			subjectID,
			namespace,
			permissions,
		)...)
	}
	authz.SortRelationTuples(tuples)

	return writeTuplesWithRetry(ctx, e.Name(), func(ctx context.Context) error {
		return e.authorizer.WriteTuples(ctx, tuples)
	})
}
