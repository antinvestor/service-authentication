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

	serviceAccountID := jsonPayload.GetString("id")
	logger := util.Log(ctx).
		WithField("service_account_id", serviceAccountID).
		WithField("type", e.Name())

	sa, err := e.serviceAccountRepo.GetByID(ctx, serviceAccountID)
	if err != nil {
		return fmt.Errorf("failed to get service account %s: %w", serviceAccountID, err)
	}

	tenancyPath := fmt.Sprintf("%s/%s", sa.TenantID, sa.PartitionID)
	subjectID := sa.ProfileID

	// Layer 1: data access tuples (member + service marker)
	tuples := []security.RelationTuple{
		authz.BuildAccessTuple(tenancyPath, subjectID),
		authz.BuildServiceAccessTuple(tenancyPath, subjectID),
	}

	// Layer 2: explicit per-namespace permission tuples
	audiencePerms := authz.ParseAudiencePermissions(sa.Audiences)
	for ns, perms := range audiencePerms {
		tuples = append(tuples, authz.BuildServicePermissionTuples(tenancyPath, subjectID, ns, perms)...)
	}

	if writeErr := e.authorizer.WriteTuples(ctx, tuples); writeErr != nil {
		return fmt.Errorf("failed to write service account tuples: %w", writeErr)
	}

	logger.
		WithField("tenancy_path", tenancyPath).
		WithField("subject_id", subjectID).
		WithField("namespace_count", len(audiencePerms)).
		WithField("tuple_count", len(tuples)).
		Info("wrote service account authorization tuples")

	return nil
}
