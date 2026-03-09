package events

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/antinvestor/service-authentication/apps/tenancy/service/models"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/repository"
	"github.com/pitabwire/frame/client"
	"github.com/pitabwire/frame/config"
	"github.com/pitabwire/frame/data"
	fevents "github.com/pitabwire/frame/events"
	"github.com/pitabwire/frame/security"
	"github.com/pitabwire/util"
)

const EventKeyClientSynchronization = "client.synchronization.event"

type ClientSyncEvent struct {
	cfg                config.ConfigurationOAUTH2
	cli                client.Manager
	clientRepository   repository.ClientRepository
	serviceAccountRepo repository.ServiceAccountRepository
}

func NewClientSynchronizationEventHandler(
	_ context.Context,
	cfg config.ConfigurationOAUTH2,
	cli client.Manager,
	clientRepo repository.ClientRepository,
	saRepo repository.ServiceAccountRepository,
) fevents.EventI {
	return &ClientSyncEvent{
		cfg:                cfg,
		cli:                cli,
		clientRepository:   clientRepo,
		serviceAccountRepo: saRepo,
	}
}

func (e *ClientSyncEvent) Name() string {
	return EventKeyClientSynchronization
}

func (e *ClientSyncEvent) PayloadType() any {
	var payloadT map[string]any
	return &payloadT
}

func (e *ClientSyncEvent) Validate(_ context.Context, payload any) error {
	d, ok := payload.(*map[string]any)
	if !ok {
		return fmt.Errorf("invalid payload type, expected *map[string]any got %T", payload)
	}
	m := data.JSONMap(*d)
	if m.GetString("id") == "" {
		return errors.New("client id is required")
	}
	return nil
}

func (e *ClientSyncEvent) Execute(ictx context.Context, payload any) error {
	d, ok := payload.(*map[string]any)
	if !ok {
		return fmt.Errorf("invalid payload type, expected *map[string]any got %T", payload)
	}

	jsonPayload := data.JSONMap(*d)
	ctx := security.SkipTenancyChecksOnClaims(ictx)

	clientDBID := jsonPayload.GetString("id")
	profileID := jsonPayload.GetString("profile_id")

	logger := util.Log(ctx).
		WithField("client_db_id", clientDBID).
		WithField("type", e.Name())

	logger.Info("initiated synchronisation of client on Hydra")

	cl, err := e.clientRepository.GetByID(ctx, clientDBID)
	if err != nil {
		return fmt.Errorf("failed to get client %s: %w", clientDBID, err)
	}

	// For client_credentials clients, look up the SA to get the subject (profile_id)
	if (cl.Type == "internal" || cl.Type == "external") && profileID == "" {
		sa, saErr := e.serviceAccountRepo.GetByClientRef(ctx, cl.GetID())
		if saErr == nil && sa != nil {
			profileID = sa.ProfileID
		}
	}

	err = SyncClientOnHydra(ctx, e.cfg, e.cli, e.clientRepository, cl, profileID)
	if err != nil {
		return err
	}

	logger.Info("successfully synchronised client on Hydra")
	return nil
}

// SyncClientOnHydra registers, updates, or deletes a Client's Hydra OAuth2 client.
func SyncClientOnHydra(
	ctx context.Context,
	cfg config.ConfigurationOAUTH2,
	cli client.Manager,
	clientRepo repository.ClientRepository,
	cl *models.Client,
	profileID string,
) error {
	hydraBaseURL := cfg.GetOauth2ServiceAdminURI()
	hydraURL := fmt.Sprintf("%s/admin/clients", hydraBaseURL)
	clientID := cl.ClientID

	hydraIDURL := fmt.Sprintf("%s/%s", hydraURL, clientID)

	// Handle soft-deleted client → delete from Hydra
	if cl.DeletedAt.Valid {
		resp, err := cli.Invoke(ctx, http.MethodDelete, hydraIDURL, nil, nil)
		if err != nil {
			return err
		}
		util.CloseAndLogOnError(ctx, resp)
		return nil
	}

	// Check if client already exists
	httpMethod := http.MethodPost
	resp, err := cli.Invoke(ctx, http.MethodGet, hydraIDURL, nil, nil)
	if err != nil {
		return err
	}
	util.CloseAndLogOnError(ctx, resp)

	if resp.StatusCode == http.StatusOK {
		httpMethod = http.MethodPut
		hydraURL = hydraIDURL
	}

	// Build payload
	payload := buildClientHydraPayload(cl, profileID)

	resp, err = cli.Invoke(ctx, httpMethod, hydraURL, payload, nil)
	if err != nil {
		return err
	}
	defer util.CloseAndLogOnError(ctx, resp)

	result, err := resp.ToContent(ctx)
	if err != nil {
		return err
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("invalid response status %d: %s", resp.StatusCode, string(result))
	}

	// Update client properties with Hydra response data
	return updateClientWithResponse(ctx, clientRepo, cl, result)
}

func buildClientHydraPayload(cl *models.Client, profileID string) map[string]any {
	grantTypes := getStringSlice(cl.GrantTypes, "types")
	if len(grantTypes) == 0 {
		grantTypes = []string{"authorization_code", "refresh_token"}
	}

	responseTypes := getStringSlice(cl.ResponseTypes, "types")
	if len(responseTypes) == 0 {
		responseTypes = []string{"code"}
	}

	redirectURIs := getStringSlice(cl.RedirectURIs, "uris")
	audienceList := getStringSlice(cl.Audiences, "namespaces")

	scopes := cl.Scopes
	if scopes == "" {
		scopes = "openid offline_access profile"
	}

	payload := map[string]any{
		"client_name":    cl.Name,
		"client_id":      cl.ClientID,
		"grant_types":    grantTypes,
		"response_types": responseTypes,
		"scope":          scopes,
		"redirect_uris":  redirectURIs,
		"audience":       audienceList,
	}

	applyHydraClientAuthPayload(
		payload,
		cl.TokenEndpointAuthMethod,
		cl.ClientSecret,
		cl.Properties,
		nil,
		cl.Type == "public",
	)

	// Subject for client_credentials flow
	if profileID != "" {
		payload["subject"] = profileID
	}

	// Store metadata so the token enrichment webhook and other consumers can
	// resolve the tenant/partition context from the Hydra admin API without
	// calling the partition service (avoids circular dependency during token issuance).
	metadata := map[string]any{
		"tenant_id":    cl.TenantID,
		"partition_id": cl.PartitionID,
		"type":         cl.Type,
	}
	if profileID != "" {
		metadata["profile_id"] = profileID
	}
	if accessID := cl.Properties.GetString("access_id"); accessID != "" {
		metadata["access_id"] = accessID
	}
	payload["metadata"] = metadata

	// Logo URI
	if cl.LogoURI != "" {
		payload["logo_uri"] = cl.LogoURI
	}

	// Post-logout redirect URIs
	if postLogoutURIs := getStringSlice(cl.PostLogoutRedirectURIs, "uris"); len(postLogoutURIs) > 0 {
		payload["post_logout_redirect_uris"] = postLogoutURIs
	}

	return payload
}

func getStringSlice(m data.JSONMap, key string) []string {
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

func updateClientWithResponse(
	ctx context.Context,
	clientRepo repository.ClientRepository,
	cl *models.Client,
	result []byte,
) error {
	var response map[string]any
	if err := json.Unmarshal(result, &response); err != nil {
		return err
	}

	props := cl.Properties
	if props == nil {
		props = data.JSONMap{}
	}

	for k, v := range response {
		props[k] = v
	}

	cl.Properties = props
	now := time.Now()
	cl.SyncedAt = &now
	_, err := clientRepo.Update(ctx, cl, "properties", "synced_at")
	return err
}
