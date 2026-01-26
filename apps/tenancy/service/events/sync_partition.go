package events

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"strings"

	"github.com/antinvestor/service-authentication/apps/tenancy/service/models"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/repository"
	"github.com/pitabwire/frame/client"
	"github.com/pitabwire/frame/config"
	"github.com/pitabwire/frame/data"
	fevents "github.com/pitabwire/frame/events"
	"github.com/pitabwire/frame/security"
	"github.com/pitabwire/util"
)

const EventKeyPartitionSynchronization = "partition.synchronization.event"

type PartitionSyncEvent struct {
	cfg                 config.ConfigurationOAUTH2
	cli                 client.Manager
	partitionRepository repository.PartitionRepository
}

func typeName(v any) string {
	t := reflect.TypeOf(v)
	if t.Kind() == reflect.Ptr {
		return "*" + t.Elem().String()
	}
	return t.String()
}

func NewPartitionSynchronizationEventHandler(_ context.Context, cfg config.ConfigurationOAUTH2, cli client.Manager, partitionRepository repository.PartitionRepository) fevents.EventI {
	return &PartitionSyncEvent{
		cfg:                 cfg,
		cli:                 cli,
		partitionRepository: partitionRepository,
	}
}

func (csq *PartitionSyncEvent) Name() string {
	return EventKeyPartitionSynchronization
}

func (csq *PartitionSyncEvent) PayloadType() any {
	var payloadT map[string]any
	return &payloadT
}

func (csq *PartitionSyncEvent) Validate(_ context.Context, payload any) error {
	_, ok := payload.(*map[string]any)
	if !ok {
		return errors.New("invalid payload type, expected : " + typeName(payload))
	}

	return nil
}

func (csq *PartitionSyncEvent) Execute(ictx context.Context, payload any) error {
	var jsonPayload data.JSONMap
	d, ok := payload.(*map[string]any)
	if !ok {
		return errors.New("invalid payload type, expected " + typeName(payload))
	}

	jsonPayload = *d

	ctx := security.SkipTenancyChecksOnClaims(ictx)

	partitionID := jsonPayload.GetString("id")

	logger := util.Log(ctx).
		WithField("payload", payload).
		WithField("type", csq.Name())

	logger.Info("initiated synchronisation of partition")

	partition, err := csq.partitionRepository.GetByID(ctx, partitionID)
	if err != nil {
		return err
	}

	err = SyncPartitionOnHydra(ctx, csq.cfg, csq.cli, csq.partitionRepository, partition)
	if err != nil {
		return err
	}

	logger.
		Info(" We have successfully synchronised partitions")

	return nil
}

func SyncPartitionOnHydra(ctx context.Context, cfg config.ConfigurationOAUTH2, cli client.Manager, partitionRepo repository.PartitionRepository, partition *models.Partition) error {

	hydraBaseURL := cfg.GetOauth2ServiceAdminURI()
	hydraURL := fmt.Sprintf("%s/admin/clients", hydraBaseURL)
	httpMethod := http.MethodPost

	clientID := partition.GetID()
	clIdProp, clientIDExists := partition.Properties["client_id"]
	if clientIDExists {
		clientID, _ = clIdProp.(string)
	}

	hydraIDURL := fmt.Sprintf("%s/%s", hydraURL, clientID)

	// Handle partition deletion
	if partition.DeletedAt.Valid {
		return deletePartitionOnHydra(ctx, cli, hydraIDURL)
	}

	// Check if client exists and update HTTP method/URL accordingly
	resp, err := cli.Invoke(ctx, http.MethodGet, hydraIDURL, nil, nil)
	if err != nil {
		return err
	}

	util.CloseAndLogOnError(ctx, resp)

	if resp.StatusCode == http.StatusOK {
		httpMethod = http.MethodPut
		hydraURL = hydraIDURL
	}
	// Prepare the payload
	payload, err := preparePayload(clientID, partition)
	if err != nil {
		return err
	}

	// Invoke the Hydra service
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

	// Update partition with response data
	return updatePartitionWithResponse(ctx, partitionRepo, partition, result)
}

func deletePartitionOnHydra(ctx context.Context, cli client.Manager, hydraIDURL string) error {
	resp, err := cli.Invoke(ctx, http.MethodDelete, hydraIDURL, nil, nil)
	if err != nil {
		return err
	}
	util.CloseAndLogOnError(ctx, resp)
	return nil
}

func preparePayload(clientID string, partition *models.Partition) (map[string]any, error) {
	logoURI := ""
	if val, ok := partition.Properties["logo_uri"].(string); ok {
		logoURI = val
	}

	audienceList := extractStringList(partition.Properties, "audience")
	scopeList := extractStringList(partition.Properties, "scope")
	postLogoutRedirectUriList := extractStringList(partition.Properties, "post_logout_redirect_uris")

	if len(scopeList) == 0 {
		scopeList = append(scopeList, "openid", "offline", "offline_access", "profile")
	}

	uriList, err := prepareRedirectURIs(partition)
	if err != nil {
		return nil, err
	}

	payload := map[string]any{
		"client_name":               partition.Name,
		"client_id":                 clientID,
		"grant_types":               []string{"authorization_code", "refresh_token"},
		"response_types":            []string{"token", "id_token", "code", "token id_token", "token code id_token"},
		"scope":                     strings.Join(scopeList, " "),
		"redirect_uris":             uriList,
		"post_logout_redirect_uris": postLogoutRedirectUriList,
		"logo_uri":                  logoURI,
		"audience":                  audienceList,
	}

	if _, ok := partition.Properties["token_endpoint_auth_method"]; ok {
		payload["token_endpoint_auth_method"] = partition.Properties["token_endpoint_auth_method"]
	} else {
		payload["token_endpoint_auth_method"] = "none"
		if partition.ClientSecret != "" {
			payload["client_secret"] = partition.ClientSecret
			payload["token_endpoint_auth_method"] = "client_secret_post"
		}
	}

	return payload, nil
}

func extractStringList(properties map[string]any, key string) []string {
	var list []string
	if val, ok := properties[key]; ok {

		if str, okStr := val.(string); okStr {
			if strings.Contains(str, " ") {
				return strings.Split(str, " ")
			}

			if strings.Contains(str, ",") {
				return strings.Split(str, ",")
			}
		}

		if arr, okArr := val.([]interface{}); okArr {
			for _, v := range arr {
				if str, okStr := v.(string); okStr {
					list = append(list, str)
				}
			}
		}
	}
	return list
}

func prepareRedirectURIs(partition *models.Partition) ([]string, error) {
	var uriList []string
	if val, ok := partition.Properties["redirect_uris"]; ok {
		switch uris := val.(type) {
		case string:
			uriList = strings.Split(uris, ",")
		case []interface{}: // Use interface{} to match JSON unmarshal type
			for _, v := range uris {
				if str, okStr := v.(string); okStr {
					uriList = append(uriList, str)
				}
			}
		default:
			return nil, fmt.Errorf("invalid redirect_uris format: %v", val)
		}
	}

	var finalURIList []string
	for _, uri := range uriList {
		parsedURI, err := url.Parse(uri)
		if err != nil {
			return nil, err
		}

		finalURIList = append(finalURIList, parsedURI.String())
	}

	return finalURIList, nil
}

func updatePartitionWithResponse(
	ctx context.Context,
	partitionRepo repository.PartitionRepository,
	partition *models.Partition,
	result []byte,
) error {
	var response map[string]any
	if err := json.Unmarshal(result, &response); err != nil {
		return err
	}

	props := partition.Properties

	if props == nil {
		props = data.JSONMap{}
	}

	for k, v := range response {
		props[k] = v
	}

	partition.Properties = props

	// Save partition

	_, err := partitionRepo.Update(ctx, partition, "properties")
	if err != nil {
		return err
	}
	return nil
}
