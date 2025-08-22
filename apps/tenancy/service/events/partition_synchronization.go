package events

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/antinvestor/service-authentication/apps/tenancy/config"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/models"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/repository"
	"github.com/pitabwire/frame"
)

const EventKeyPartitionSynchronization = "partition.synchronization.event"

type PartitionSyncEvent struct {
	svc                 *frame.Service
	partitionRepository repository.PartitionRepository
}

func NewPartitionSynchronizationEventHandler(svc *frame.Service) frame.EventI {
	return &PartitionSyncEvent{
		svc:                 svc,
		partitionRepository: repository.NewPartitionRepository(svc),
	}
}

func (csq *PartitionSyncEvent) Name() string {
	return EventKeyPartitionSynchronization
}

func (csq *PartitionSyncEvent) PayloadType() any {
	pType := ""
	return &pType
}

func (csq *PartitionSyncEvent) Validate(_ context.Context, payload any) error {
	_, ok := payload.(*string)
	if !ok {
		return errors.New("invalid payload type, expected *string")
	}

	return nil
}

func (csq *PartitionSyncEvent) Execute(ctx context.Context, payload any) error {
	idStrPtr, ok := payload.(*string)
	if !ok {
		return errors.New("invalid payload type, expected *string")
	}
	partitionID := *idStrPtr

	logger := csq.svc.Log(ctx).WithField("payload", partitionID).WithField("type", csq.Name())
	logger.Info("initiated synchronisation of partition")

	partition, err := csq.partitionRepository.GetByID(ctx, partitionID)
	if err != nil {
		return err
	}

	err = SyncPartitionOnHydra(ctx, csq.svc, partition)
	if err != nil {
		return err
	}

	logger.
		Info(" We have successfully synchronised partitions")

	return nil
}

func SyncPartitionOnHydra(ctx context.Context, service *frame.Service, partition *models.Partition) error {
	var cfg *config.PartitionConfig
	if c, ok := service.Config().(*config.PartitionConfig); ok {
		cfg = c
	} else {
		return errors.New("invalid configuration type")
	}

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
		return deletePartitionOnHydra(ctx, service, hydraIDURL)
	}

	// Check if client exists and update HTTP method/URL accordingly
	status, _, err := service.InvokeRestService(ctx, http.MethodGet, hydraIDURL, nil, nil)
	if err != nil {
		return err
	}

	if status == http.StatusOK {
		httpMethod = http.MethodPut
		hydraURL = hydraIDURL
	}
	// Prepare the payload
	payload, err := preparePayload(clientID, partition)
	if err != nil {
		return err
	}

	// Invoke the Hydra service
	status, result, err := service.InvokeRestService(ctx, httpMethod, hydraURL, payload, nil)
	if err != nil {
		return err
	}

	if status < 200 || status > 299 {
		return fmt.Errorf("invalid response status %d: %s", status, string(result))
	}

	// Update partition with response data
	return updatePartitionWithResponse(ctx, service, partition, result)
}

func deletePartitionOnHydra(ctx context.Context, service *frame.Service, hydraIDURL string) error {
	_, _, err := service.InvokeRestService(ctx, http.MethodDelete, hydraIDURL, nil, nil)
	return err
}

func preparePayload(clientID string, partition *models.Partition) (map[string]any, error) {
	logoURI := ""
	if val, ok := partition.Properties["logo_uri"].(string); ok {
		logoURI = val
	}

	audienceList := extractStringList(partition.Properties, "audience")
	scopeList := extractStringList(partition.Properties, "scope")

	if len(scopeList) == 0 {
		scopeList = append(scopeList, "openid", "offline_access", "profile")
	}

	uriList, err := prepareRedirectURIs(partition)
	if err != nil {
		return nil, err
	}

	payload := map[string]any{
		"client_name":    partition.Name,
		"client_id":      clientID,
		"grant_types":    []string{"authorization_code", "refresh_token"},
		"response_types": []string{"token", "id_token", "code", "token id_token", "token code id_token"},
		"scope":          strings.Join(scopeList, " "),
		"redirect_uris":  uriList,
		"logo_uri":       logoURI,
		"audience":       audienceList,
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
				list = strings.Split(str, " ")
				return list
			}

			if strings.Contains(str, ",") {
				list = strings.Split(str, ",")
				return list
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
		params := parsedURI.Query()
		if !params.Has("partition_id") {
			params.Add("partition_id", partition.ID)
		}
		parsedURI.RawQuery = params.Encode()
		finalURIList = append(finalURIList, parsedURI.String())
	}

	return finalURIList, nil
}

func updatePartitionWithResponse(
	ctx context.Context,
	service *frame.Service,
	partition *models.Partition,
	result []byte,
) error {
	var response map[string]any
	if err := json.Unmarshal(result, &response); err != nil {
		return err
	}

	if partition.Properties == nil {
		partition.Properties = make(frame.JSONMap)
	}

	for k, v := range response {
		partition.Properties[k] = v
	}

	// Save partition
	partitionRepository := repository.NewPartitionRepository(service)
	return partitionRepository.Save(ctx, partition)
}
