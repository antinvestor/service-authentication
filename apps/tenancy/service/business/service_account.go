package business

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"maps"

	partitionv1 "buf.build/gen/go/antinvestor/partition/protocolbuffers/go/partition/v1"
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
	Client         *models.Client
	ClientSecret   string
}

type ServiceAccountBusiness interface {
	CreateServiceAccount(ctx context.Context, partitionID, profileID, name, saType string,
		audiences, roles []string, publicKeys, properties map[string]any) (*ServiceAccountResult, error)
	GetServiceAccount(ctx context.Context, id, clientID, profileID string) (*models.ServiceAccount, error)
	GetServiceAccountByClientID(ctx context.Context, clientID string) (*models.ServiceAccount, error)
	UpdateServiceAccount(ctx context.Context, request *partitionv1.UpdateServiceAccountRequest) (*partitionv1.ServiceAccountObject, error)
	ListServiceAccounts(ctx context.Context, partitionID string) ([]*models.ServiceAccount, error)
	RemoveServiceAccount(ctx context.Context, id string) error
}

func NewServiceAccountBusiness(
	eventsMan fevents.Manager,
	authorizer security.Authorizer,
	partitionRepo repository.PartitionRepository,
	partitionRoleRepo repository.PartitionRoleRepository,
	clientRepo repository.ClientRepository,
	serviceAccountRepo repository.ServiceAccountRepository,
	accessRepo repository.AccessRepository,
	accessRoleRepo repository.AccessRoleRepository,
) ServiceAccountBusiness {
	return &serviceAccountBusiness{
		eventsMan:          eventsMan,
		authorizer:         authorizer,
		partitionRepo:      partitionRepo,
		partitionRoleRepo:  partitionRoleRepo,
		clientRepo:         clientRepo,
		serviceAccountRepo: serviceAccountRepo,
		accessRepo:         accessRepo,
		accessRoleRepo:     accessRoleRepo,
	}
}

type serviceAccountBusiness struct {
	eventsMan          fevents.Manager
	authorizer         security.Authorizer
	partitionRepo      repository.PartitionRepository
	partitionRoleRepo  repository.PartitionRoleRepository
	clientRepo         repository.ClientRepository
	serviceAccountRepo repository.ServiceAccountRepository
	accessRepo         repository.AccessRepository
	accessRoleRepo     repository.AccessRoleRepository
}

func (sb *serviceAccountBusiness) CreateServiceAccount(
	ctx context.Context,
	partitionID, profileID, name, saType string,
	audiences, roles []string,
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

	// Validate audiences
	for i, aud := range audiences {
		if aud == "" {
			return nil, fmt.Errorf("audience at index %d is empty", i)
		}
	}

	// Generate client credentials
	clientID := util.IDString()
	clientSecret, err := generateClientSecret()
	if err != nil {
		return nil, fmt.Errorf("failed to generate client secret: %w", err)
	}

	// Determine scopes based on type
	scope := "system_int openid"
	if saType == "external" {
		scope = "system_ext openid"
	}

	// Build the Client record (OAuth2 credential config)
	client := &models.Client{
		Name:         fmt.Sprintf("sa-%s", name),
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Type:         saType,
		GrantTypes:   toJSONMapSlice("types", []string{"client_credentials"}),
		Scopes:       scope,
		Audiences:    toJSONMapSlice("namespaces", audiences),
		Roles:        toJSONMapSlice("roles", roles),
		BaseModel: data.BaseModel{
			TenantID:    tenantID,
			PartitionID: partitionID,
		},
	}

	if createErr := sb.clientRepo.Create(ctx, client); createErr != nil {
		return nil, fmt.Errorf("failed to create client record: %w", createErr)
	}

	// Build the ServiceAccount record (identity)
	// Link the client back to the SA after both are created (see below)
	if properties == nil {
		properties = map[string]any{}
	}

	var pubKeysMap data.JSONMap
	if publicKeys != nil {
		pubKeysMap = data.JSONMap(publicKeys)
	}

	audienceInterfaces := toAnySlice(audiences)
	audienceMap := data.JSONMap{}
	if len(audienceInterfaces) > 0 {
		audienceMap["namespaces"] = audienceInterfaces
	}

	sa := &models.ServiceAccount{
		ProfileID:  profileID,
		ClientID:   clientID, // denormalized for lookup
		ClientRef:  client.GetID(),
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

	// Link client to its owning service account
	client.ServiceAccountID = sa.GetID()
	if _, updateErr := sb.clientRepo.Update(ctx, client, "service_account_id"); updateErr != nil {
		util.Log(ctx).WithError(updateErr).Warn("failed to set client service_account_id")
	}

	log = log.WithField("service_account_id", sa.GetID()).
		WithField("client_id", clientID).
		WithField("client_db_id", client.GetID())

	// Provision Access + AccessRoles for the SA's profile in the partition
	if provisionErr := sb.provisionAccessAndRoles(ctx, partition, profileID, roles); provisionErr != nil {
		log.WithError(provisionErr).Warn("failed to provision access roles for service account")
	}

	// Emit client sync event → registers Hydra OAuth2 client
	if emitErr := sb.eventsMan.Emit(ctx, events.EventKeyClientSynchronization, data.JSONMap{
		"id":         client.GetID(),
		"profile_id": profileID,
	}); emitErr != nil {
		return nil, fmt.Errorf("failed to emit client sync event: %w", emitErr)
	}

	// Emit service account authz sync → writes data-access tuples and audience bridges
	if emitErr := sb.eventsMan.Emit(ctx, events.EventKeyAuthzServiceAccountSync, data.JSONMap{"id": sa.GetID()}); emitErr != nil {
		log.WithError(emitErr).Warn("failed to emit service account authz sync event")
	}

	log.Info("service account created successfully")

	return &ServiceAccountResult{
		ServiceAccount: sa,
		Client:         client,
		ClientSecret:   clientSecret,
	}, nil
}

// provisionAccessAndRoles creates an Access record for the profile in the partition
// and assigns the specified roles as AccessRoles, emitting Keto tuples for each.
func (sb *serviceAccountBusiness) provisionAccessAndRoles(
	ctx context.Context,
	partition *models.Partition,
	profileID string,
	roleNames []string,
) error {
	log := util.Log(ctx).
		WithField("partition_id", partition.GetID()).
		WithField("profile_id", profileID)

	// Create or get existing access
	access, err := sb.accessRepo.GetByPartitionAndProfile(ctx, partition.GetID(), profileID)
	if err != nil {
		if !data.ErrorIsNoRows(err) {
			return fmt.Errorf("failed to check existing access: %w", err)
		}
		// Create new access
		access = &models.Access{
			ProfileID: profileID,
			BaseModel: data.BaseModel{
				TenantID:    partition.TenantID,
				PartitionID: partition.GetID(),
			},
		}
		if createErr := sb.accessRepo.Create(ctx, access); createErr != nil {
			return fmt.Errorf("failed to create access record: %w", createErr)
		}

		// Emit tenancy_access member tuple
		tenancyPath := fmt.Sprintf("%s/%s", partition.TenantID, partition.GetID())
		accessTuple := authz.BuildAccessTuple(tenancyPath, profileID)
		payload := events.TuplesToPayload([]security.RelationTuple{accessTuple})
		if emitErr := sb.eventsMan.Emit(ctx, events.EventKeyAuthzTupleWrite, payload); emitErr != nil {
			log.WithError(emitErr).Warn("failed to emit access tuple write event")
		}
	}

	if len(roleNames) == 0 {
		return nil
	}

	// Look up partition roles by name
	partitionRoles, err := sb.partitionRoleRepo.GetByPartitionAndNames(ctx, partition.GetID(), roleNames)
	if err != nil {
		return fmt.Errorf("failed to look up partition roles: %w", err)
	}

	tenancyPath := fmt.Sprintf("%s/%s", partition.TenantID, partition.GetID())
	for _, role := range partitionRoles {
		accessRole := &models.AccessRole{
			AccessID:        access.GetID(),
			PartitionRoleID: role.GetID(),
			BaseModel: data.BaseModel{
				TenantID:    partition.TenantID,
				PartitionID: partition.GetID(),
			},
		}
		if createErr := sb.accessRoleRepo.Create(ctx, accessRole); createErr != nil {
			log.WithError(createErr).WithField("role", role.Name).Warn("failed to create access role")
			continue
		}

		// Emit Keto role tuple
		tuples := authz.BuildRoleTuples(tenancyPath, profileID, role.Name)
		payload := events.TuplesToPayload(tuples)
		if emitErr := sb.eventsMan.Emit(ctx, events.EventKeyAuthzTupleWrite, payload); emitErr != nil {
			log.WithError(emitErr).WithField("role", role.Name).Warn("failed to emit role tuple write")
		}
	}

	return nil
}

func (sb *serviceAccountBusiness) UpdateServiceAccount(
	ctx context.Context,
	request *partitionv1.UpdateServiceAccountRequest,
) (*partitionv1.ServiceAccountObject, error) {
	sa, err := sb.serviceAccountRepo.GetByID(ctx, request.GetId())
	if err != nil {
		return nil, fmt.Errorf("service account not found: %w", err)
	}

	if request.GetType() != "" {
		if request.GetType() != "internal" && request.GetType() != "external" {
			return nil, fmt.Errorf("invalid service account type %q: must be \"internal\" or \"external\"", request.GetType())
		}
		sa.Type = request.GetType()
	}

	if len(request.GetAudiences()) > 0 {
		sa.Audiences = toJSONMapSlice("namespaces", request.GetAudiences())
	}

	if request.GetProperties() != nil {
		if sa.Properties == nil {
			sa.Properties = make(data.JSONMap)
		}
		maps.Copy(sa.Properties, data.JSONMap(request.GetProperties().AsMap()))
	}

	_, err = sb.serviceAccountRepo.Update(ctx, sa, "type", "audiences", "properties")
	if err != nil {
		return nil, fmt.Errorf("failed to update service account: %w", err)
	}

	// Update the associated client record if it exists
	if sa.ClientRef != "" {
		client, clientErr := sb.clientRepo.GetByID(ctx, sa.ClientRef)
		if clientErr == nil {
			if request.GetType() != "" {
				client.Type = request.GetType()
				scope := "system_int openid"
				if request.GetType() == "external" {
					scope = "system_ext openid"
				}
				client.Scopes = scope
			}
			if len(request.GetAudiences()) > 0 {
				client.Audiences = toJSONMapSlice("namespaces", request.GetAudiences())
			}
			if len(request.GetRoles()) > 0 {
				client.Roles = toJSONMapSlice("roles", request.GetRoles())
			}
			if _, updateErr := sb.clientRepo.Update(ctx, client, "type", "scopes", "audiences", "roles"); updateErr != nil {
				util.Log(ctx).WithError(updateErr).Warn("failed to update associated client record")
			}
			// Re-sync Hydra
			if emitErr := sb.eventsMan.Emit(ctx, events.EventKeyClientSynchronization, data.JSONMap{"id": client.GetID()}); emitErr != nil {
				util.Log(ctx).WithError(emitErr).Warn("failed to emit client sync after SA update")
			}
		}
	}

	return sa.ToAPI(), nil
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
	if clientID != "" {
		return sb.serviceAccountRepo.GetByClientID(ctx, clientID)
	}
	return nil, fmt.Errorf("id or client_id (optionally with profile_id) required")
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

	// Soft-delete the SA record first so the sync event handler sees DeletedAt
	if delErr := sb.serviceAccountRepo.Delete(ctx, id); delErr != nil {
		return fmt.Errorf("failed to delete service account: %w", delErr)
	}

	// Also delete the associated Client record if it exists
	if sa.ClientRef != "" {
		if delErr := sb.clientRepo.Delete(ctx, sa.ClientRef); delErr != nil {
			log.WithError(delErr).Warn("failed to delete associated client record")
		}
		// Emit client sync event for Hydra deletion
		if emitErr := sb.eventsMan.Emit(ctx, events.EventKeyClientSynchronization, data.JSONMap{"id": sa.ClientRef}); emitErr != nil {
			log.WithError(emitErr).Warn("failed to emit client sync for deletion")
		}
	} else if sa.ClientID != "" {
		// Legacy SA without ClientRef — emit SA sync for Hydra deletion
		if emitErr := sb.eventsMan.Emit(ctx, events.EventKeyServiceAccountSynchronization, data.JSONMap{"id": sa.GetID()}); emitErr != nil {
			log.WithError(emitErr).Warn("failed to emit service account sync for deletion")
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

// ReQueueServiceAccountsForHydraSync re-queues all service accounts for Hydra client registration/update.
func ReQueueServiceAccountsForHydraSync(ctx context.Context, saRepo repository.ServiceAccountRepository, eventsMan fevents.Manager, query *data.SearchQuery) error {
	return reQueueServiceAccounts(ctx, saRepo, eventsMan, query, events.EventKeyServiceAccountSynchronization)
}

// ReQueueServiceAccountsForSync re-queues all service accounts for authorization tuple sync.
func ReQueueServiceAccountsForSync(ctx context.Context, saRepo repository.ServiceAccountRepository, eventsMan fevents.Manager, query *data.SearchQuery) error {
	return reQueueServiceAccounts(ctx, saRepo, eventsMan, query, events.EventKeyAuthzServiceAccountSync)
}

func reQueueServiceAccounts(ctx context.Context, saRepo repository.ServiceAccountRepository, eventsMan fevents.Manager, query *data.SearchQuery, eventKey string) error {
	jobResult, err := saRepo.Search(ctx, query)
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
		for _, sa := range result.Item() {
			if emitErr := eventsMan.Emit(ctx, eventKey, data.JSONMap{"id": sa.GetID()}); emitErr != nil {
				return emitErr
			}
		}
	}
}
