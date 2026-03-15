package business

import (
	"context"
	"fmt"
	"maps"
	"strings"

	partitionv1 "buf.build/gen/go/antinvestor/partition/protocolbuffers/go/partition/v1"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/events"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/models"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/repository"
	"github.com/pitabwire/frame/data"
	fevents "github.com/pitabwire/frame/events"
	"github.com/pitabwire/util"
)

// ClientResult is the result of creating a client.
// ClientSecret is only populated on creation.
type ClientResult struct {
	Client       *models.Client
	ClientSecret string
}

type ClientBusiness interface {
	CreateClient(ctx context.Context, partitionID, name, clientType string,
		grantTypes, responseTypes, redirectURIs []string,
		scopes string,
		audiences, roles []string,
		properties map[string]any) (*ClientResult, error)
	GetClient(ctx context.Context, id string) (*models.Client, error)
	GetClientByClientID(ctx context.Context, clientID string) (*models.Client, error)
	UpdateClient(ctx context.Context, request *partitionv1.UpdateClientRequest) (*partitionv1.ClientObject, error)
	ListClients(ctx context.Context, partitionID string) ([]*models.Client, error)
	RemoveClient(ctx context.Context, id string) error
}

func NewClientBusiness(
	eventsMan fevents.Manager,
	partitionRepo repository.PartitionRepository,
	clientRepo repository.ClientRepository,
) ClientBusiness {
	return &clientBusiness{
		eventsMan:     eventsMan,
		partitionRepo: partitionRepo,
		clientRepo:    clientRepo,
	}
}

type clientBusiness struct {
	eventsMan     fevents.Manager
	partitionRepo repository.PartitionRepository
	clientRepo    repository.ClientRepository
}

func (cb *clientBusiness) CreateClient(
	ctx context.Context,
	partitionID, name, clientType string,
	grantTypes, responseTypes, redirectURIs []string,
	scopes string,
	audiences, roles []string,
	properties map[string]any,
) (*ClientResult, error) {
	log := util.Log(ctx).WithField("partition_id", partitionID)

	partition, err := cb.partitionRepo.GetByID(ctx, partitionID)
	if err != nil {
		return nil, fmt.Errorf("target partition not found: %w", err)
	}

	// Default type
	if clientType == "" {
		clientType = "public"
	}
	validTypes := map[string]bool{"public": true, "confidential": true, "internal": true, "external": true}
	if !validTypes[clientType] {
		return nil, fmt.Errorf("invalid client type %q: must be public, confidential, internal, or external", clientType)
	}

	// Default grant types based on client type
	if len(grantTypes) == 0 {
		switch clientType {
		case "internal", "external":
			grantTypes = []string{"client_credentials"}
		default:
			grantTypes = []string{"authorization_code", "refresh_token"}
		}
	}

	if len(responseTypes) == 0 {
		responseTypes = []string{"code"}
	}

	if scopes == "" {
		switch clientType {
		case "internal":
			scopes = "internal openid"
		case "external":
			scopes = "external openid"
		default:
			scopes = "openid offline_access profile"
		}
	}

	// Generate credentials
	clientID := util.IDString()
	var clientSecret string
	if clientType != "public" {
		clientSecret, err = generateClientSecret()
		if err != nil {
			return nil, fmt.Errorf("failed to generate client secret: %w", err)
		}
	}

	if properties == nil {
		properties = map[string]any{}
	}

	client := &models.Client{
		Name:          name,
		ClientID:      clientID,
		ClientSecret:  clientSecret,
		Type:          clientType,
		GrantTypes:    toJSONMapSlice("types", grantTypes),
		ResponseTypes: toJSONMapSlice("types", responseTypes),
		RedirectURIs:  toJSONMapSlice("uris", redirectURIs),
		Scopes:        scopes,
		Audiences:     toJSONMapSlice("namespaces", audiences),
		Roles:         toJSONMapSlice("roles", roles),
		// ServiceAccountID left empty — this is a partition client
		Properties: data.JSONMap(properties),
		BaseModel: data.BaseModel{
			TenantID:    partition.TenantID,
			PartitionID: partitionID,
		},
	}

	if createErr := cb.clientRepo.Create(ctx, client); createErr != nil {
		return nil, fmt.Errorf("failed to create client record: %w", createErr)
	}

	log = log.WithField("client_id", clientID).WithField("client_db_id", client.GetID())

	// Emit client sync event to register with Hydra
	if emitErr := cb.eventsMan.Emit(ctx, events.EventKeyClientSynchronization, data.JSONMap{"id": client.GetID()}); emitErr != nil {
		return nil, fmt.Errorf("failed to emit client sync event: %w", emitErr)
	}

	log.Info("client created successfully")

	return &ClientResult{
		Client:       client,
		ClientSecret: clientSecret,
	}, nil
}

func (cb *clientBusiness) GetClient(ctx context.Context, id string) (*models.Client, error) {
	return cb.clientRepo.GetByID(ctx, id)
}

func (cb *clientBusiness) GetClientByClientID(ctx context.Context, clientID string) (*models.Client, error) {
	if clientID == "" {
		return nil, fmt.Errorf("client_id is required")
	}
	return cb.clientRepo.GetByClientID(ctx, clientID)
}

func (cb *clientBusiness) ListClients(ctx context.Context, partitionID string) ([]*models.Client, error) {
	return cb.clientRepo.ListByPartition(ctx, partitionID)
}

func (cb *clientBusiness) UpdateClient(
	ctx context.Context,
	request *partitionv1.UpdateClientRequest,
) (*partitionv1.ClientObject, error) {
	log := util.Log(ctx).WithField("client_db_id", request.GetId())

	client, err := cb.clientRepo.GetByID(ctx, request.GetId())
	if err != nil {
		return nil, fmt.Errorf("client not found: %w", err)
	}

	if request.GetName() != "" {
		client.Name = request.GetName()
	}
	if len(request.GetGrantTypes()) > 0 {
		client.GrantTypes = toJSONMapSlice("types", request.GetGrantTypes())
	}
	if len(request.GetResponseTypes()) > 0 {
		client.ResponseTypes = toJSONMapSlice("types", request.GetResponseTypes())
	}
	if len(request.GetRedirectUris()) > 0 {
		client.RedirectURIs = toJSONMapSlice("uris", request.GetRedirectUris())
	}
	if request.GetScopes() != "" {
		client.Scopes = request.GetScopes()
	}
	if len(request.GetAudiences()) > 0 {
		client.Audiences = toJSONMapSlice("namespaces", request.GetAudiences())
	}
	if len(request.GetRoles()) > 0 {
		client.Roles = toJSONMapSlice("roles", request.GetRoles())
	}
	if request.GetProperties() != nil {
		if client.Properties == nil {
			client.Properties = make(data.JSONMap)
		}
		maps.Copy(client.Properties, data.JSONMap(request.GetProperties().AsMap()))
	}

	// Mark as needing Hydra re-sync
	client.SyncedAt = nil

	_, err = cb.clientRepo.Update(ctx, client,
		"name", "grant_types", "response_types", "redirect_uris",
		"scopes", "audiences", "roles", "logo_uri", "post_logout_redirect_uris",
		"token_endpoint_auth_method", "properties", "synced_at")
	if err != nil {
		return nil, fmt.Errorf("failed to update client: %w", err)
	}

	// Re-sync with Hydra
	if emitErr := cb.eventsMan.Emit(ctx, events.EventKeyClientSynchronization, data.JSONMap{"id": client.GetID()}); emitErr != nil {
		log.WithError(emitErr).Warn("failed to emit client sync after update")
	}

	log.Info("client updated successfully")
	return client.ToAPI(), nil
}

func (cb *clientBusiness) RemoveClient(ctx context.Context, id string) error {
	log := util.Log(ctx).WithField("client_id", id)

	client, err := cb.clientRepo.GetByID(ctx, id)
	if err != nil {
		return fmt.Errorf("client not found: %w", err)
	}

	if delErr := cb.clientRepo.Delete(ctx, id); delErr != nil {
		return fmt.Errorf("failed to delete client: %w", delErr)
	}

	// Emit sync event so handler sees soft-deleted client and deletes from Hydra
	if client.ClientID != "" {
		if emitErr := cb.eventsMan.Emit(ctx, events.EventKeyClientSynchronization, data.JSONMap{"id": client.GetID()}); emitErr != nil {
			log.WithError(emitErr).Warn("failed to emit client sync for deletion")
		}
	}

	log.Info("client removed successfully")
	return nil
}

func toJSONMapSlice(key string, values []string) data.JSONMap {
	if len(values) == 0 {
		return nil
	}
	anySlice := make([]any, len(values))
	for i, v := range values {
		anySlice[i] = v
	}
	return data.JSONMap{key: anySlice}
}

// ReQueueClientsForHydraSync re-queues all clients for Hydra OAuth2 client registration/update.
func ReQueueClientsForHydraSync(ctx context.Context, clientRepo repository.ClientRepository, eventsMan fevents.Manager, query *data.SearchQuery) error {
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
		for _, cl := range result.Item() {
			if emitErr := eventsMan.Emit(ctx, events.EventKeyClientSynchronization, data.JSONMap{"id": cl.GetID()}); emitErr != nil {
				return emitErr
			}
		}
	}
}

// GetStringSlice extracts a string slice from a JSONMap at the given key.
func GetStringSlice(m data.JSONMap, key string) []string {
	if m == nil {
		return nil
	}
	raw, ok := m[key]
	if !ok {
		return nil
	}
	switch typed := raw.(type) {
	case []any:
		result := make([]string, 0, len(typed))
		for _, v := range typed {
			if s, ok := v.(string); ok {
				result = append(result, s)
			}
		}
		return result
	case []string:
		return typed
	case string:
		if strings.Contains(typed, ",") {
			return strings.Split(typed, ",")
		}
		if typed != "" {
			return []string{typed}
		}
	}
	return nil
}
