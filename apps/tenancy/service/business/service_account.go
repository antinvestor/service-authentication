package business

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/antinvestor/service-authentication/apps/tenancy/service/authz"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/events"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/models"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/repository"
	"github.com/pitabwire/frame/data"
	fevents "github.com/pitabwire/frame/events"
	"github.com/pitabwire/frame/security"
	"github.com/pitabwire/util"
)

// ServiceAccountResult is the result of creating a service account.
// ClientSecret is only populated on creation.
type ServiceAccountResult struct {
	ServiceAccount *models.ServiceAccount
	ClientSecret   string
}

type ServiceAccountBusiness interface {
	CreateServiceAccount(ctx context.Context, partitionID, profileID, name, saType string, audiences []string, publicKeys, properties map[string]any) (*ServiceAccountResult, error)
	GetServiceAccount(ctx context.Context, id, clientID, profileID string) (*models.ServiceAccount, error)
	GetServiceAccountByClientID(ctx context.Context, clientID string) (*models.ServiceAccount, error)
	ListServiceAccounts(ctx context.Context, partitionID string) ([]*models.ServiceAccount, error)
	RemoveServiceAccount(ctx context.Context, id string) error
}

func NewServiceAccountBusiness(
	eventsMan fevents.Manager,
	authorizer security.Authorizer,
	partitionRepo repository.PartitionRepository,
	serviceAccountRepo repository.ServiceAccountRepository,
) ServiceAccountBusiness {
	return &serviceAccountBusiness{
		eventsMan:          eventsMan,
		authorizer:         authorizer,
		partitionRepo:      partitionRepo,
		serviceAccountRepo: serviceAccountRepo,
	}
}

type serviceAccountBusiness struct {
	eventsMan          fevents.Manager
	authorizer         security.Authorizer
	partitionRepo      repository.PartitionRepository
	serviceAccountRepo repository.ServiceAccountRepository
}

func (sb *serviceAccountBusiness) CreateServiceAccount(
	ctx context.Context,
	partitionID, profileID, name, saType string,
	audiences []string,
	publicKeys, properties map[string]any,
) (*ServiceAccountResult, error) {
	log := util.Log(ctx).
		WithField("partition_id", partitionID).
		WithField("profile_id", profileID)

	// Validate target partition exists
	partition, err := sb.partitionRepo.GetByID(ctx, partitionID)
	if err != nil {
		return nil, fmt.Errorf("target partition not found: %w", err)
	}

	tenantID := partition.TenantID

	// Default type to "internal"
	if saType == "" {
		saType = "internal"
	}
	if saType != "internal" && saType != "external" {
		return nil, fmt.Errorf("invalid service account type %q: must be \"internal\" or \"external\"", saType)
	}

	// Validate audiences — each must be a non-empty string matching a known service namespace pattern.
	for i, aud := range audiences {
		if aud == "" {
			return nil, fmt.Errorf("audience at index %d is empty", i)
		}
	}

	// Generate client secret
	clientSecret, err := generateClientSecret()
	if err != nil {
		return nil, fmt.Errorf("failed to generate client secret: %w", err)
	}

	// Derive name if not provided
	if name == "" {
		suffix := profileID
		if len(suffix) > 8 {
			suffix = suffix[:8]
		}
		name = fmt.Sprintf("svc-%s", suffix)
	}

	// Build child partition properties for client_credentials
	audienceInterfaces := toAnySlice(audiences)

	scope := "system_int openid"
	if saType == "external" {
		scope = "system_ext openid"
	}

	childProps := data.JSONMap{
		"grant_types":    []string{"client_credentials"},
		"response_types": []string{"token"},
		"scope":          scope,
		"subject":        profileID,
	}
	if len(audienceInterfaces) > 0 {
		childProps["audience"] = audienceInterfaces
	}

	// Create the child partition
	childPartition := &models.Partition{
		ParentID:     partitionID,
		Name:         name,
		Description:  fmt.Sprintf("Service account for %s", profileID),
		ClientSecret: clientSecret,
		Properties:   childProps,
	}
	childPartition.GenID(ctx)
	childPartition.TenantID = tenantID
	childPartition.PartitionID = partition.PartitionID

	if createErr := sb.partitionRepo.Create(ctx, childPartition); createErr != nil {
		return nil, fmt.Errorf("failed to create child partition: %w", createErr)
	}

	childPartitionID := childPartition.GetID()
	log = log.WithField("child_partition_id", childPartitionID)

	// Emit partition sync event → creates Hydra OAuth2 client with client_credentials.
	// This is critical — without it the service account has no Hydra client and cannot authenticate.
	if emitErr := sb.eventsMan.Emit(ctx, events.EventKeyPartitionSynchronization, data.JSONMap{"id": childPartitionID}); emitErr != nil {
		return nil, fmt.Errorf("failed to emit partition sync event: %w", emitErr)
	}

	// Emit authz partition sync → writes bridge + inheritance tuples for the child partition.
	// Non-fatal: can be recovered via bulk sync endpoint.
	if emitErr := sb.eventsMan.Emit(ctx, events.EventKeyAuthzPartitionSync, data.JSONMap{"id": childPartitionID}); emitErr != nil {
		log.WithError(emitErr).Warn("failed to emit authz partition sync event for service account")
	}

	// Create ServiceAccount record (must exist before emitting service account sync)
	audienceMap := data.JSONMap{}
	if len(audienceInterfaces) > 0 {
		audienceMap["namespaces"] = audienceInterfaces
	}

	if properties == nil {
		properties = map[string]any{}
	}

	var pubKeysMap data.JSONMap
	if publicKeys != nil {
		pubKeysMap = data.JSONMap(publicKeys)
	}

	sa := &models.ServiceAccount{
		ProfileID:  profileID,
		ClientID:   childPartitionID,
		Type:       saType,
		Audiences:  audienceMap,
		PublicKeys: pubKeysMap,
		Properties: data.JSONMap(properties),
		BaseModel: data.BaseModel{
			TenantID:    tenantID,
			PartitionID: partitionID,
		},
	}

	if createErr := sb.serviceAccountRepo.Create(ctx, sa); createErr != nil {
		return nil, fmt.Errorf("failed to create service account record: %w", createErr)
	}

	// Emit service account authz sync → writes per-bot tuples (access, service, audience bridges)
	if emitErr := sb.eventsMan.Emit(ctx, events.EventKeyAuthzServiceAccountSync, data.JSONMap{"id": sa.GetID()}); emitErr != nil {
		log.WithError(emitErr).Warn("failed to emit service account authz sync event")
	}

	log.Info("service account created successfully")

	return &ServiceAccountResult{
		ServiceAccount: sa,
		ClientSecret:   clientSecret,
	}, nil
}

func (sb *serviceAccountBusiness) GetServiceAccount(
	ctx context.Context,
	id, clientID, profileID string,
) (*models.ServiceAccount, error) {
	if id != "" {
		return sb.serviceAccountRepo.GetByID(ctx, id)
	}
	if clientID != "" && profileID != "" {
		return sb.serviceAccountRepo.GetByClientAndProfile(ctx, clientID, profileID)
	}
	return nil, fmt.Errorf("id or (client_id + profile_id) required")
}

func (sb *serviceAccountBusiness) GetServiceAccountByClientID(
	ctx context.Context,
	clientID string,
) (*models.ServiceAccount, error) {
	if clientID == "" {
		return nil, fmt.Errorf("client_id is required")
	}
	return sb.serviceAccountRepo.GetByClientID(ctx, clientID)
}

func (sb *serviceAccountBusiness) ListServiceAccounts(
	ctx context.Context,
	partitionID string,
) ([]*models.ServiceAccount, error) {
	return sb.serviceAccountRepo.ListByPartition(ctx, partitionID)
}

func (sb *serviceAccountBusiness) RemoveServiceAccount(
	ctx context.Context,
	id string,
) error {
	log := util.Log(ctx).WithField("service_account_id", id)

	sa, err := sb.serviceAccountRepo.GetByID(ctx, id)
	if err != nil {
		return fmt.Errorf("service account not found: %w", err)
	}

	// Soft-delete the child partition (triggers Hydra client deletion via sync event)
	if sa.ClientID != "" {
		if delErr := sb.partitionRepo.Delete(ctx, sa.ClientID); delErr != nil {
			log.WithError(delErr).Warn("failed to delete child partition")
		}

		// Emit partition sync to delete from Hydra
		if emitErr := sb.eventsMan.Emit(ctx, events.EventKeyPartitionSynchronization, data.JSONMap{"id": sa.ClientID}); emitErr != nil {
			log.WithError(emitErr).Warn("failed to emit partition sync for deletion")
		}
	}

	// Delete Keto tuples
	tenancyPath := fmt.Sprintf("%s/%s", sa.TenantID, sa.PartitionID)
	tuples := []security.RelationTuple{
		authz.BuildAccessTuple(tenancyPath, sa.ProfileID),
		authz.BuildServiceAccessTuple(tenancyPath, sa.ProfileID),
	}

	// Delete audience bridge tuples
	if namespaces, ok := sa.Audiences["namespaces"]; ok {
		if nsList, ok := namespaces.([]any); ok {
			nsStrings := make([]string, 0, len(nsList))
			for _, ns := range nsList {
				if s, ok := ns.(string); ok {
					nsStrings = append(nsStrings, s)
				}
			}
			tuples = append(tuples, authz.BuildServiceInheritanceTuples(tenancyPath, nsStrings)...)
		}
	}

	if delErr := sb.authorizer.DeleteTuples(ctx, tuples); delErr != nil {
		log.WithError(delErr).Warn("failed to delete service account tuples")
	}

	// Delete service account record
	if delErr := sb.serviceAccountRepo.Delete(ctx, id); delErr != nil {
		return fmt.Errorf("failed to delete service account: %w", delErr)
	}

	log.Info("service account removed successfully")
	return nil
}

func toAnySlice(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}

func generateClientSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(b), nil
}
