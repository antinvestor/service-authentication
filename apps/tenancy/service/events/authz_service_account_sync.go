package events

import (
	"context"
	"errors"
	"fmt"

	"github.com/antinvestor/service-authentication/apps/tenancy/service/authz"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/repository"
	"github.com/pitabwire/frame/data"
	fevents "github.com/pitabwire/frame/events"
	"github.com/pitabwire/frame/security"
	"github.com/pitabwire/util"
)

const EventKeyAuthzServiceAccountSync = "authorization.service_account.sync"

// AuthzServiceAccountSyncEvent writes Keto tuples for a service account after
// it is created or during bulk sync. This is separate from the partition sync
// event so that service account authorization is decoupled from partition
// management.
//
// For each service account it writes:
//   - tenancy_access:tenancyPath#member ← profile_user:profileID
//   - tenancy_access:tenancyPath#service ← profile_user:profileID
//   - Per-audience bridge tuples: ns:tenancyPath#service ← tenancy_access:tenancyPath#service
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

	serviceAccountID := jsonPayload.GetString("id")
	logger := util.Log(ctx).
		WithField("service_account_id", serviceAccountID).
		WithField("type", e.Name())

	sa, err := e.serviceAccountRepo.GetByID(ctx, serviceAccountID)
	if err != nil {
		return fmt.Errorf("failed to get service account %s: %w", serviceAccountID, err)
	}

	tenancyPath := fmt.Sprintf("%s/%s", sa.TenantID, sa.PartitionID)

	// Write per-bot tuples: member access and service access
	tuples := []security.RelationTuple{
		authz.BuildAccessTuple(tenancyPath, sa.ProfileID),
		authz.BuildServiceAccessTuple(tenancyPath, sa.ProfileID),
	}

	// Write per-audience bridge tuples
	if namespaces, ok := sa.Audiences["namespaces"]; ok {
		if nsList, ok := namespaces.([]any); ok {
			nsStrings := make([]string, 0, len(nsList))
			for _, ns := range nsList {
				if s, ok := ns.(string); ok {
					nsStrings = append(nsStrings, s)
				}
			}
			if len(nsStrings) > 0 {
				tuples = append(tuples, authz.BuildServiceInheritanceTuples(tenancyPath, nsStrings)...)
			}
		}
	}

	if writeErr := e.authorizer.WriteTuples(ctx, tuples); writeErr != nil {
		return fmt.Errorf("failed to write service account tuples: %w", writeErr)
	}

	logger.
		WithField("tenancy_path", tenancyPath).
		WithField("profile_id", sa.ProfileID).
		WithField("tuple_count", len(tuples)).
		Info("wrote service account authorization tuples")

	return nil
}
