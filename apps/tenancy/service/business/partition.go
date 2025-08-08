package business

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	partitionv1 "github.com/antinvestor/apis/go/partition/v1"
	"github.com/antinvestor/service-authentication/apps/tenancy/config"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/models"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/repository"
	"github.com/pitabwire/frame"
	"github.com/pitabwire/frame/framedata"
)

type PartitionBusiness interface {
	GetPartition(ctx context.Context, request *partitionv1.GetPartitionRequest) (*partitionv1.PartitionObject, error)
	CreatePartition(
		ctx context.Context,
		request *partitionv1.CreatePartitionRequest) (*partitionv1.PartitionObject, error)
	UpdatePartition(
		ctx context.Context,
		request *partitionv1.UpdatePartitionRequest) (*partitionv1.PartitionObject, error)
	ListPartition(
		ctx context.Context,
		request *partitionv1.ListPartitionRequest,
		stream partitionv1.PartitionService_ListPartitionServer) error

	RemovePartitionRole(ctx context.Context, request *partitionv1.RemovePartitionRoleRequest) error
	ListPartitionRoles(
		ctx context.Context,
		request *partitionv1.ListPartitionRoleRequest) (*partitionv1.ListPartitionRoleResponse, error)
	CreatePartitionRole(
		ctx context.Context,
		request *partitionv1.CreatePartitionRoleRequest) (*partitionv1.PartitionRoleObject, error)
}

func NewPartitionBusiness(service *frame.Service) PartitionBusiness {
	tenantRepository := repository.NewTenantRepository(service)
	partitionRepository := repository.NewPartitionRepository(service)

	return &partitionBusiness{
		service:       service,
		partitionRepo: partitionRepository,
		tenantRepo:    tenantRepository,
	}
}

type partitionBusiness struct {
	service       *frame.Service
	tenantRepo    repository.TenantRepository
	partitionRepo repository.PartitionRepository
}

func toAPIPartitionRole(partitionModel *models.PartitionRole) *partitionv1.PartitionRoleObject {
	properties := frame.DBPropertiesToMap(partitionModel.Properties)

	return &partitionv1.PartitionRoleObject{
		PartitionId: partitionModel.PartitionID,
		Name:        partitionModel.Name,
		Properties:  properties,
	}
}

func (pb *partitionBusiness) ListPartition(
	ctx context.Context,
	request *partitionv1.ListPartitionRequest,
	stream partitionv1.PartitionService_ListPartitionServer,
) error {

	searchProperties := map[string]any{}

	for _, p := range request.GetProperties() {
		searchProperties[p] = request.GetQuery()
	}

	query := framedata.NewSearchQuery(
		request.GetQuery(), searchProperties,
		int(request.GetPage()),
		int(request.GetCount()),
	)

	jobResult, err := pb.partitionRepo.Search(ctx, query)
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

		var responseObjects []*partitionv1.PartitionObject
		for _, partition := range result.Item() {
			responseObjects = append(responseObjects, partition.ToAPI())
		}

		err = stream.Send(&partitionv1.ListPartitionResponse{Data: responseObjects})
		if err != nil {
			return err
		}

	}
}

func (pb *partitionBusiness) GetPartition(
	ctx context.Context,
	request *partitionv1.GetPartitionRequest) (*partitionv1.PartitionObject, error) {
	claims := frame.ClaimsFromContext(ctx)

	partition, err := pb.partitionRepo.GetByID(ctx, request.GetId())
	if err != nil {
		return nil, err
	}

	partitionObj := partition.ToAPI()

	var cfg *config.PartitionConfig
	if c, ok := pb.service.Config().(*config.PartitionConfig); ok {
		cfg = c
	} else {
		return nil, errors.New("invalid configuration type")
	}

	if strings.EqualFold(claims.GetServiceName(), "service_matrix") {
		props := partitionObj.GetProperties()

		props["client_secret"] = partition.ClientSecret
		props["client_discovery_uri"] = cfg.GetOauth2WellKnownOIDC()
		partitionObj.Properties = props
	}

	return partitionObj, nil
}

func (pb *partitionBusiness) CreatePartition(
	ctx context.Context,
	request *partitionv1.CreatePartitionRequest) (*partitionv1.PartitionObject, error) {
	tenant, err := pb.tenantRepo.GetByID(ctx, request.GetTenantId())
	if err != nil {
		return nil, err
	}

	partition := &models.Partition{
		ParentID:    request.GetParentId(),
		Name:        request.GetName(),
		Description: request.GetDescription(),
		Properties:  frame.DBPropertiesFromMap(request.GetProperties()),
		BaseModel: frame.BaseModel{
			TenantID: tenant.GetID(),
		},
	}

	err = pb.partitionRepo.Save(ctx, partition)
	if err != nil {
		return nil, err
	}

	var partitionConfig *config.PartitionConfig
	if c, ok := pb.service.Config().(*config.PartitionConfig); ok {
		partitionConfig = c
	} else {
		return nil, errors.New("invalid configuration type")
	}

	err = pb.service.Publish(ctx, partitionConfig.PartitionSyncName, partition)
	if err != nil {
		return nil, err
	}

	return partition.ToAPI(), nil
}

func (pb *partitionBusiness) UpdatePartition(
	ctx context.Context,
	request *partitionv1.UpdatePartitionRequest) (*partitionv1.PartitionObject, error) {
	partition, err := pb.partitionRepo.GetByID(ctx, request.GetId())
	if err != nil {
		return nil, err
	}

	jsonMap := partition.Properties
	for k, v := range request.GetProperties() {
		jsonMap[k] = v
	}

	partition.Name = request.GetName()
	partition.Description = request.GetDescription()
	partition.Properties = jsonMap

	err = pb.partitionRepo.Save(ctx, partition)
	if err != nil {
		return nil, err
	}

	return partition.ToAPI(), nil
}

func (pb *partitionBusiness) ListPartitionRoles(
	ctx context.Context,
	request *partitionv1.ListPartitionRoleRequest,
) (*partitionv1.ListPartitionRoleResponse, error) {
	partitionRoleList, err := pb.partitionRepo.GetRoles(ctx, request.GetPartitionId())
	if err != nil {
		return nil, err
	}

	response := make([]*partitionv1.PartitionRoleObject, 0)

	for _, pat := range partitionRoleList {
		response = append(response, toAPIPartitionRole(pat))
	}

	return &partitionv1.ListPartitionRoleResponse{
		Role: response,
	}, nil
}

func (pb *partitionBusiness) RemovePartitionRole(
	ctx context.Context,
	request *partitionv1.RemovePartitionRoleRequest,
) error {
	err := pb.partitionRepo.RemoveRole(ctx, request.GetId())
	if err != nil {
		return err
	}

	return nil
}

func (pb *partitionBusiness) CreatePartitionRole(
	ctx context.Context,
	request *partitionv1.CreatePartitionRoleRequest) (
	*partitionv1.PartitionRoleObject, error) {
	partition, err := pb.partitionRepo.GetByID(ctx, request.GetPartitionId())
	if err != nil {
		return nil, err
	}

	jsonMap := make(frame.JSONMap)
	for k, v := range request.GetProperties() {
		jsonMap[k] = v
	}

	partitionRole := &models.PartitionRole{
		Name:       request.GetName(),
		Properties: jsonMap,
		BaseModel: frame.BaseModel{
			PartitionID: partition.PartitionID,
			TenantID:    partition.TenantID,
		},
	}

	err = pb.partitionRepo.SaveRole(ctx, partitionRole)
	if err != nil {
		return nil, err
	}

	return toAPIPartitionRole(partitionRole), nil
}

func ReQueuePrimaryPartitionsForSync(ctx context.Context, service *frame.Service, query *framedata.SearchQuery) {
	logger := service.Log(ctx)

	partitionRepository := repository.NewPartitionRepository(service)
	var partitionConfig *config.PartitionConfig
	if c, ok := service.Config().(*config.PartitionConfig); ok {
		partitionConfig = c
	} else {
		return
	}

	jobResult, err := partitionRepository.Search(ctx, query)
	if err != nil {
		logger.WithError(err).Error(" could not create query for searching partitions")

		return
	}

	for {
		result, ok := jobResult.ReadResult(ctx)

		if !ok {
			return
		}

		if result.IsError() {
			logger.WithError(err).Panic(" could not get default system partitions to sync successfully")
			return
		}

		for _, partition := range result.Item() {
			err = service.Publish(ctx, partitionConfig.PartitionSyncName, partition)
			if err != nil {
				logger.WithError(err).Panic("could not publish because")

				return
			}
		}
	}
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

	clientID, clientIDExists := partition.Properties["client_id"].(string)

	if !clientIDExists {
		clientID = partition.GetID()
	} else {
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

func preparePayload(clientID string, partition *models.Partition) (map[string]interface{}, error) {
	logoURI := ""
	if val, ok := partition.Properties["logo_uri"].(string); ok {
		logoURI = val
	}

	audienceList := extractStringList(partition.Properties, "audience")
	uriList, err := prepareRedirectURIs(partition)
	if err != nil {
		return nil, err
	}

	payload := map[string]interface{}{
		"client_name":    partition.Name,
		"client_id":      clientID,
		"grant_types":    []string{"authorization_code", "refresh_token"},
		"response_types": []string{"token", "id_token", "code", "token id_token", "token code id_token"},
		"scope":          "openid offline offline_access profile contact",
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

func extractStringList(properties map[string]interface{}, key string) []string {
	var list []string
	if val, ok := properties[key]; ok {
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
	var response map[string]interface{}
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
