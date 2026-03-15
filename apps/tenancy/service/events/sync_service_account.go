package events

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/antinvestor/service-authentication/apps/tenancy/service/authz"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/models"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/repository"
	"github.com/pitabwire/frame/client"
	"github.com/pitabwire/frame/config"
	"github.com/pitabwire/frame/data"
	fevents "github.com/pitabwire/frame/events"
	"github.com/pitabwire/frame/security"
	"github.com/pitabwire/util"
)

const EventKeyServiceAccountSynchronization = "service_account.synchronization.event"

type ServiceAccountSyncEvent struct {
	cfg                 config.ConfigurationOAUTH2
	cli                 client.Manager
	serviceAccountRepo  repository.ServiceAccountRepository
	partitionRepository repository.PartitionRepository
}

func NewServiceAccountSynchronizationEventHandler(
	_ context.Context,
	cfg config.ConfigurationOAUTH2,
	cli client.Manager,
	serviceAccountRepo repository.ServiceAccountRepository,
	partitionRepo repository.PartitionRepository,
) fevents.EventI {
	return &ServiceAccountSyncEvent{
		cfg:                 cfg,
		cli:                 cli,
		serviceAccountRepo:  serviceAccountRepo,
		partitionRepository: partitionRepo,
	}
}

func (e *ServiceAccountSyncEvent) Name() string {
	return EventKeyServiceAccountSynchronization
}

func (e *ServiceAccountSyncEvent) PayloadType() any {
	var payloadT map[string]any
	return &payloadT
}

func (e *ServiceAccountSyncEvent) Validate(_ context.Context, payload any) error {
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

func (e *ServiceAccountSyncEvent) Execute(ictx context.Context, payload any) error {
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

	logger.Info("initiated synchronisation of service account on Hydra")

	sa, err := e.serviceAccountRepo.GetByID(ctx, serviceAccountID)
	if err != nil {
		return fmt.Errorf("failed to get service account %s: %w", serviceAccountID, err)
	}

	err = SyncServiceAccountOnHydra(ctx, e.cfg, e.cli, e.serviceAccountRepo, sa)
	if err != nil {
		return err
	}

	logger.Info("successfully synchronised service account on Hydra")
	return nil
}

// SyncServiceAccountOnHydra registers, updates, or deletes a service account's
// Hydra OAuth2 client. It follows the same pattern as SyncPartitionOnHydra.
func SyncServiceAccountOnHydra(
	ctx context.Context,
	cfg config.ConfigurationOAUTH2,
	cli client.Manager,
	saRepo repository.ServiceAccountRepository,
	sa *models.ServiceAccount,
) error {
	hydraBaseURL := cfg.GetOauth2ServiceAdminURI()
	hydraURL := fmt.Sprintf("%s/admin/clients", hydraBaseURL)
	clientID := sa.ClientID

	hydraIDURL := fmt.Sprintf("%s/%s", hydraURL, clientID)

	// Handle soft-deleted SA → delete from Hydra
	if sa.DeletedAt.Valid {
		return deleteServiceAccountOnHydra(ctx, cli, hydraIDURL)
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
	payload := buildServiceAccountHydraPayload(sa)

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

	// Update SA properties with Hydra response data
	return updateServiceAccountWithResponse(ctx, saRepo, sa, result)
}

func deleteServiceAccountOnHydra(ctx context.Context, cli client.Manager, hydraIDURL string) error {
	resp, err := cli.Invoke(ctx, http.MethodDelete, hydraIDURL, nil, nil)
	if err != nil {
		return err
	}
	util.CloseAndLogOnError(ctx, resp)
	return nil
}

func buildServiceAccountHydraPayload(sa *models.ServiceAccount) map[string]any {
	// Use SA type directly as scope — no transformation
	scope := sa.Type + " openid"

	audienceList := extractAudienceNamespaces(sa.Audiences)

	payload := map[string]any{
		"client_name":    fmt.Sprintf("sa-%s", sa.ClientID),
		"client_id":      sa.ClientID,
		"subject":        sa.ProfileID,
		"grant_types":    []string{"client_credentials"},
		"response_types": []string{"token"},
		"scope":          scope,
		"audience":       audienceList,
		"metadata": map[string]any{
			"tenant_id":    sa.TenantID,
			"partition_id": sa.PartitionID,
			"profile_id":   sa.ProfileID,
			"type":         sa.Type,
		},
	}
	if accessID := sa.Properties.GetString("access_id"); accessID != "" {
		payload["metadata"].(map[string]any)["access_id"] = accessID
	}

	applyHydraClientAuthPayload(
		payload,
		sa.Properties.GetString("token_endpoint_auth_method"),
		sa.ClientSecret,
		sa.Properties,
		sa.PublicKeys,
		true,
	)

	return payload
}

func extractAudienceNamespaces(audiences data.JSONMap) []string {
	if audiences == nil {
		return nil
	}
	return authz.AudienceNamespaces(audiences)
}

func updateServiceAccountWithResponse(
	ctx context.Context,
	saRepo repository.ServiceAccountRepository,
	sa *models.ServiceAccount,
	result []byte,
) error {
	var response map[string]any
	if err := json.Unmarshal(result, &response); err != nil {
		return err
	}

	props := sa.Properties
	if props == nil {
		props = data.JSONMap{}
	}

	for k, v := range response {
		props[k] = v
	}

	sa.Properties = props
	_, err := saRepo.Update(ctx, sa, "properties")
	return err
}
