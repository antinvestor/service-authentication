// Copyright 2023-2026 Ant Investor Ltd
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package business

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"path"
	"slices"
	"strings"
	"time"

	commonv1 "buf.build/gen/go/antinvestor/common/protocolbuffers/go/common/v1"
	tenancyv2 "buf.build/gen/go/antinvestor/tenancy/protocolbuffers/go/tenancy/v2"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/authz"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/events"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/models"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/repository"
	"github.com/pitabwire/frame/v2/data"
	fevents "github.com/pitabwire/frame/v2/events"
	"github.com/pitabwire/util"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type AuthContractBusiness interface {
	CreateOAuthClient(ctx context.Context, request *tenancyv2.CreateOAuthClientRequest) (*tenancyv2.CreateOAuthClientResponse, error)
	GetOAuthClient(ctx context.Context, request *tenancyv2.GetOAuthClientRequest) (*tenancyv2.OAuthClient, error)
	ListOAuthClients(ctx context.Context, request *tenancyv2.ListOAuthClientsRequest) ([]*tenancyv2.OAuthClient, error)
	UpdateOAuthClient(ctx context.Context, request *tenancyv2.UpdateOAuthClientRequest) (*tenancyv2.OAuthClient, error)
	RemoveOAuthClient(ctx context.Context, id string) error
	CreateServiceAccount(ctx context.Context, request *tenancyv2.CreateServiceAccountRequest) (*tenancyv2.CreateServiceAccountResponse, error)
	GetServiceAccount(ctx context.Context, request *tenancyv2.GetServiceAccountRequest) (*tenancyv2.ServiceAccount, error)
	ListServiceAccounts(ctx context.Context, request *tenancyv2.ListServiceAccountsRequest) ([]*tenancyv2.ServiceAccount, error)
	UpdateServiceAccount(ctx context.Context, request *tenancyv2.UpdateServiceAccountRequest) (*tenancyv2.ServiceAccount, error)
	RemoveServiceAccount(ctx context.Context, id string) error
	ReconcileServiceAccountAuthorization(ctx context.Context, id string) (int64, error)
}

type authContractBusiness struct {
	audienceBaseURL      string
	eventsMan            fevents.Manager
	partitionRepo        repository.PartitionRepository
	clientRepo           repository.ClientRepository
	recipientRepo        repository.OAuthClientRecipientRepository
	serviceAccountRepo   repository.ServiceAccountRepository
	policyRepo           repository.ServiceAccountAuthorizationPolicyRepository
	serviceNamespaceRepo repository.ServiceNamespaceRepository
	authContractRepo     repository.AuthContractRepository
}

func NewAuthContractBusiness(
	audienceBaseURL string,
	eventsMan fevents.Manager,
	partitionRepo repository.PartitionRepository,
	clientRepo repository.ClientRepository,
	recipientRepo repository.OAuthClientRecipientRepository,
	serviceAccountRepo repository.ServiceAccountRepository,
	policyRepo repository.ServiceAccountAuthorizationPolicyRepository,
	serviceNamespaceRepo repository.ServiceNamespaceRepository,
	authContractRepo repository.AuthContractRepository,
) (AuthContractBusiness, error) {
	normalizedAudienceBaseURL, err := normalizeAudienceBaseURL(audienceBaseURL)
	if err != nil {
		return nil, err
	}
	return &authContractBusiness{
		audienceBaseURL:      normalizedAudienceBaseURL,
		eventsMan:            eventsMan,
		partitionRepo:        partitionRepo,
		clientRepo:           clientRepo,
		recipientRepo:        recipientRepo,
		serviceAccountRepo:   serviceAccountRepo,
		policyRepo:           policyRepo,
		serviceNamespaceRepo: serviceNamespaceRepo,
		authContractRepo:     authContractRepo,
	}, nil
}

func (b *authContractBusiness) CreateOAuthClient(
	ctx context.Context,
	request *tenancyv2.CreateOAuthClientRequest,
) (*tenancyv2.CreateOAuthClientResponse, error) {
	partition, err := b.partitionRepo.GetByID(ctx, request.GetPartitionId())
	if err != nil {
		return nil, fmt.Errorf("target partition not found: %w", err)
	}
	if request.GetType() != "public" && request.GetType() != "confidential" {
		return nil, fmt.Errorf("interactive OAuth client type must be public or confidential")
	}
	configuration := request.GetConfiguration()
	recipients, err := b.validateRecipients(configuration.GetResourceRecipients())
	if err != nil {
		return nil, err
	}
	grantTypes, responseTypes, redirectURIs, scopes, err := validateOAuthClientConfiguration(configuration, request.GetType())
	if err != nil {
		return nil, err
	}

	authMethod := strings.TrimSpace(configuration.GetTokenEndpointAuthMethod())
	if request.GetType() == "public" {
		authMethod = "none"
	} else {
		if authMethod == "none" {
			return nil, errors.New("confidential OAuth client cannot use token_endpoint_auth_method none")
		}
		if authMethod == "" {
			authMethod = "client_secret_post"
		}
	}
	clientSecret := ""
	if authMethod == "client_secret_basic" || authMethod == "client_secret_post" {
		clientSecret, err = generateClientSecret()
		if err != nil {
			return nil, fmt.Errorf("generate OAuth client secret: %w", err)
		}
	}

	client := &models.Client{
		Name:                    strings.TrimSpace(request.GetName()),
		ClientID:                util.IDString(),
		ClientSecret:            clientSecret,
		Type:                    request.GetType(),
		GrantTypes:              toJSONMapSlice("types", grantTypes),
		ResponseTypes:           toJSONMapSlice("types", responseTypes),
		RedirectURIs:            toJSONMapSlice("uris", redirectURIs),
		Scopes:                  scopes,
		TokenEndpointAuthMethod: authMethod,
		Properties:              protoStructToJSONMap(configuration.GetProperties()),
		BaseModel: data.BaseModel{
			TenantID:    partition.TenantID,
			PartitionID: partition.ID,
		},
	}
	if err = b.authContractRepo.CreateOAuthClient(ctx, client, recipients); err != nil {
		return nil, err
	}
	b.emitClientSync(ctx, client, "")

	object, err := b.oauthClientObject(ctx, client)
	if err != nil {
		return nil, err
	}
	return &tenancyv2.CreateOAuthClientResponse{Data: object, ClientSecret: clientSecret}, nil
}

func (b *authContractBusiness) GetOAuthClient(
	ctx context.Context,
	request *tenancyv2.GetOAuthClientRequest,
) (*tenancyv2.OAuthClient, error) {
	var client *models.Client
	var err error
	if request.GetId() != "" {
		client, err = b.clientRepo.GetByID(ctx, request.GetId())
	} else {
		client, err = b.clientRepo.GetByClientID(ctx, request.GetClientId())
	}
	if err != nil {
		return nil, err
	}
	return b.oauthClientObject(ctx, client)
}

func (b *authContractBusiness) ListOAuthClients(
	ctx context.Context,
	request *tenancyv2.ListOAuthClientsRequest,
) ([]*tenancyv2.OAuthClient, error) {
	var clients []*models.Client
	var err error
	if request.GetPartitionId() != "" {
		clients, err = b.clientRepo.ListByPartition(ctx, request.GetPartitionId())
	} else {
		clients, err = b.clientRepo.ListByServiceAccountID(ctx, request.GetServiceAccountId())
	}
	if err != nil {
		return nil, err
	}
	objects := make([]*tenancyv2.OAuthClient, 0, len(clients))
	for _, client := range clients {
		object, objectErr := b.oauthClientObject(ctx, client)
		if objectErr != nil {
			return nil, objectErr
		}
		objects = append(objects, object)
	}
	return objects, nil
}

func (b *authContractBusiness) UpdateOAuthClient(
	ctx context.Context,
	request *tenancyv2.UpdateOAuthClientRequest,
) (*tenancyv2.OAuthClient, error) {
	client, err := b.clientRepo.GetByID(ctx, request.GetId())
	if err != nil {
		return nil, err
	}
	if client.ServiceAccountID != "" {
		return nil, errors.New("service-account OAuth clients must be updated through UpdateServiceAccount")
	}
	paths := request.GetUpdateMask().GetPaths()
	if len(paths) == 0 {
		return nil, errors.New("update mask must select at least one field")
	}

	fields := []string{"synced_at"}
	recipients, err := b.recipientValues(ctx, client.ID)
	if err != nil {
		return nil, err
	}
	for _, path := range paths {
		switch path {
		case "name":
			client.Name = strings.TrimSpace(request.GetName())
			fields = append(fields, "name")
		case "configuration":
			configuration := request.GetConfiguration()
			if configuration == nil {
				return nil, errors.New("configuration is required by update mask")
			}
			recipients, err = b.validateRecipients(configuration.GetResourceRecipients())
			if err != nil {
				return nil, err
			}
			grantTypes, responseTypes, redirectURIs, scopes, configErr := validateOAuthClientConfiguration(configuration, client.Type)
			if configErr != nil {
				return nil, configErr
			}
			client.GrantTypes = toJSONMapSlice("types", grantTypes)
			client.ResponseTypes = toJSONMapSlice("types", responseTypes)
			client.RedirectURIs = toJSONMapSlice("uris", redirectURIs)
			client.Scopes = scopes
			client.Properties = protoStructToJSONMap(configuration.GetProperties())
			fields = append(fields, "grant_types", "response_types", "redirect_uris", "scopes", "properties")
		default:
			return nil, fmt.Errorf("unsupported update path %q", path)
		}
	}
	client.SyncedAt = nil
	if err = b.authContractRepo.UpdateOAuthClient(ctx, client, fields, recipients); err != nil {
		return nil, err
	}
	b.emitClientSync(ctx, client, "")
	return b.oauthClientObject(ctx, client)
}

func (b *authContractBusiness) RemoveOAuthClient(ctx context.Context, id string) error {
	client, err := b.clientRepo.GetByID(ctx, id)
	if err != nil {
		return err
	}
	if client.ServiceAccountID != "" {
		return errors.New("service-account OAuth clients must be removed through RemoveServiceAccount")
	}
	if err = b.clientRepo.Delete(ctx, id); err != nil {
		return err
	}
	b.emitClientSync(ctx, client, "")
	return nil
}

func (b *authContractBusiness) CreateServiceAccount(
	ctx context.Context,
	request *tenancyv2.CreateServiceAccountRequest,
) (*tenancyv2.CreateServiceAccountResponse, error) {
	partition, err := b.partitionRepo.GetByID(ctx, request.GetPartitionId())
	if err != nil {
		return nil, fmt.Errorf("target partition not found: %w", err)
	}
	if request.GetType() != "internal" && request.GetType() != "external" {
		return nil, errors.New("service account type must be internal or external")
	}
	recipients, err := b.validateRecipients(request.GetOauthClient().GetResourceRecipients())
	if err != nil {
		return nil, err
	}
	grants, err := b.validateAuthorizationPolicy(ctx, request.GetAuthorizationPolicy())
	if err != nil {
		return nil, err
	}
	configuration := request.GetOauthClient()
	grantTypes, _, _, scopes, err := validateOAuthClientConfiguration(configuration, request.GetType())
	if err != nil {
		return nil, err
	}
	if !slices.Equal(grantTypes, []string{"client_credentials"}) {
		return nil, errors.New("service-account OAuth client must use only client_credentials")
	}

	authMethod := strings.TrimSpace(configuration.GetTokenEndpointAuthMethod())
	if authMethod == "" {
		authMethod = "private_key_jwt"
	}
	clientSecret := ""
	if authMethod == "client_secret_basic" || authMethod == "client_secret_post" {
		clientSecret, err = generateClientSecret()
		if err != nil {
			return nil, fmt.Errorf("generate OAuth client secret: %w", err)
		}
	}
	clientID := util.IDString()
	client := &models.Client{
		Name:                    "sa-" + strings.TrimSpace(request.GetName()),
		ClientID:                clientID,
		ClientSecret:            clientSecret,
		Type:                    request.GetType(),
		GrantTypes:              toJSONMapSlice("types", grantTypes),
		ResponseTypes:           toJSONMapSlice("types", []string{"token"}),
		Scopes:                  scopes,
		TokenEndpointAuthMethod: authMethod,
		Properties:              protoStructToJSONMap(configuration.GetProperties()),
		BaseModel:               data.BaseModel{TenantID: partition.TenantID, PartitionID: partition.ID},
	}
	serviceAccount := &models.ServiceAccount{
		Name:       strings.TrimSpace(request.GetName()),
		ProfileID:  request.GetProfileId(),
		ClientID:   clientID,
		Type:       request.GetType(),
		PublicKeys: protoStructToJSONMap(request.GetPublicKeys()),
		Properties: protoStructToJSONMap(request.GetProperties()),
		BaseModel:  data.BaseModel{TenantID: partition.TenantID, PartitionID: partition.ID},
	}
	policy, err := b.authContractRepo.CreateServiceAccount(ctx, serviceAccount, client, recipients, grants)
	if err != nil {
		return nil, err
	}
	b.emitClientSync(ctx, client, serviceAccount.ProfileID)
	b.emitPolicySync(ctx, serviceAccount.ID, policy.Generation, "policy_created")

	object, err := b.serviceAccountObject(ctx, serviceAccount)
	if err != nil {
		return nil, err
	}
	return &tenancyv2.CreateServiceAccountResponse{Data: object, ClientSecret: clientSecret}, nil
}

func (b *authContractBusiness) GetServiceAccount(
	ctx context.Context,
	request *tenancyv2.GetServiceAccountRequest,
) (*tenancyv2.ServiceAccount, error) {
	var serviceAccount *models.ServiceAccount
	var err error
	if request.GetId() != "" {
		serviceAccount, err = b.serviceAccountRepo.GetByID(ctx, request.GetId())
	} else {
		serviceAccount, err = b.serviceAccountRepo.GetByClientID(ctx, request.GetClientId())
	}
	if err != nil {
		return nil, err
	}
	return b.serviceAccountObject(ctx, serviceAccount)
}

func (b *authContractBusiness) ListServiceAccounts(
	ctx context.Context,
	request *tenancyv2.ListServiceAccountsRequest,
) ([]*tenancyv2.ServiceAccount, error) {
	serviceAccounts, err := b.serviceAccountRepo.ListByPartition(ctx, request.GetPartitionId())
	if err != nil {
		return nil, err
	}
	objects := make([]*tenancyv2.ServiceAccount, 0, len(serviceAccounts))
	for _, serviceAccount := range serviceAccounts {
		object, objectErr := b.serviceAccountObject(ctx, serviceAccount)
		if objectErr != nil {
			return nil, objectErr
		}
		objects = append(objects, object)
	}
	return objects, nil
}

func (b *authContractBusiness) UpdateServiceAccount(
	ctx context.Context,
	request *tenancyv2.UpdateServiceAccountRequest,
) (*tenancyv2.ServiceAccount, error) {
	serviceAccount, err := b.serviceAccountRepo.GetByID(ctx, request.GetId())
	if err != nil {
		return nil, err
	}
	clients, err := b.clientRepo.ListByServiceAccountID(ctx, serviceAccount.ID)
	if err != nil {
		return nil, err
	}
	if len(clients) != 1 {
		return nil, fmt.Errorf("service account %q must own exactly one OAuth client, got %d", serviceAccount.ID, len(clients))
	}
	client := clients[0]
	paths := request.GetUpdateMask().GetPaths()
	if len(paths) == 0 {
		return nil, errors.New("update mask must select at least one field")
	}

	serviceAccountFields := make([]string, 0)
	clientFields := []string{"synced_at"}
	recipients := make([]string, 0)
	replaceRecipients := false
	grants := make([]repository.AuthorizationGrant, 0)
	replacePolicy := false
	clientChanged := false

	for _, path := range paths {
		switch path {
		case "name":
			name := strings.TrimSpace(request.GetName())
			if name == "" {
				return nil, errors.New("service account name is required")
			}
			serviceAccount.Name = name
			client.Name = "sa-" + name
			serviceAccountFields = append(serviceAccountFields, "name")
			clientFields = append(clientFields, "name")
			clientChanged = true
		case "type":
			if request.GetType() != "internal" && request.GetType() != "external" {
				return nil, errors.New("service account type must be internal or external")
			}
			serviceAccount.Type = request.GetType()
			client.Type = request.GetType()
			serviceAccountFields = append(serviceAccountFields, "type")
			clientFields = append(clientFields, "type")
			clientChanged = true
		case "oauth_client":
			configuration := request.GetOauthClient()
			if configuration == nil {
				return nil, errors.New("oauth_client is required by update mask")
			}
			recipients, err = b.validateRecipients(configuration.GetResourceRecipients())
			if err != nil {
				return nil, err
			}
			grantTypes, responseTypes, redirectURIs, scopes, configErr := validateOAuthClientConfiguration(configuration, serviceAccount.Type)
			if configErr != nil {
				return nil, configErr
			}
			if !slices.Equal(grantTypes, []string{"client_credentials"}) {
				return nil, errors.New("service-account OAuth client must use only client_credentials")
			}
			authMethod := strings.TrimSpace(configuration.GetTokenEndpointAuthMethod())
			if authMethod != "" && authMethod != client.TokenEndpointAuthMethod {
				return nil, errors.New("token endpoint authentication method cannot be changed without credential rotation")
			}
			client.GrantTypes = toJSONMapSlice("types", grantTypes)
			client.ResponseTypes = toJSONMapSlice("types", responseTypes)
			client.RedirectURIs = toJSONMapSlice("uris", redirectURIs)
			client.Scopes = scopes
			client.Properties = protoStructToJSONMap(configuration.GetProperties())
			clientFields = append(clientFields, "grant_types", "response_types", "redirect_uris", "scopes", "properties")
			replaceRecipients = true
			clientChanged = true
		case "authorization_policy":
			grants, err = b.validateAuthorizationPolicy(ctx, request.GetAuthorizationPolicy())
			if err != nil {
				return nil, err
			}
			replacePolicy = true
		case "public_keys":
			serviceAccount.PublicKeys = protoStructToJSONMap(request.GetPublicKeys())
			serviceAccountFields = append(serviceAccountFields, "public_keys")
		case "properties":
			serviceAccount.Properties = protoStructToJSONMap(request.GetProperties())
			serviceAccountFields = append(serviceAccountFields, "properties")
		default:
			return nil, fmt.Errorf("unsupported update path %q", path)
		}
	}
	client.SyncedAt = nil
	policy, err := b.authContractRepo.UpdateServiceAccount(
		ctx,
		serviceAccount,
		serviceAccountFields,
		client,
		clientFields,
		recipients,
		replaceRecipients,
		grants,
		replacePolicy,
	)
	if err != nil {
		return nil, err
	}
	if clientChanged {
		b.emitClientSync(ctx, client, serviceAccount.ProfileID)
	}
	if replacePolicy {
		b.emitPolicySync(ctx, serviceAccount.ID, policy.Generation, "policy_updated")
	}
	return b.serviceAccountObject(ctx, serviceAccount)
}

func (b *authContractBusiness) RemoveServiceAccount(ctx context.Context, id string) error {
	serviceAccount, err := b.serviceAccountRepo.GetByID(ctx, id)
	if err != nil {
		return err
	}
	clients, err := b.clientRepo.ListByServiceAccountID(ctx, serviceAccount.ID)
	if err != nil {
		return err
	}
	if len(clients) != 1 {
		return fmt.Errorf("service account %q must own exactly one OAuth client, got %d", serviceAccount.ID, len(clients))
	}
	serviceAccount.State = int32(commonv1.STATE_DELETED)
	policy, err := b.authContractRepo.UpdateServiceAccount(
		ctx,
		serviceAccount,
		[]string{"state"},
		clients[0],
		nil,
		nil,
		false,
		nil,
		true,
	)
	if err != nil {
		return err
	}
	b.emitPolicySync(ctx, serviceAccount.ID, policy.Generation, "service_account_deleted")
	return nil
}

func (b *authContractBusiness) ReconcileServiceAccountAuthorization(
	ctx context.Context,
	id string,
) (int64, error) {
	policy, err := b.policyRepo.GetByServiceAccountID(ctx, id)
	if err != nil {
		return 0, err
	}
	b.emitPolicySync(ctx, id, policy.Policy.Generation, "manual_reconcile")
	return policy.Policy.Generation, nil
}

func (b *authContractBusiness) validateRecipients(values []string) ([]string, error) {
	return validateResourceRecipients(b.audienceBaseURL, values)
}

func validateResourceRecipients(audienceBaseURL string, values []string) ([]string, error) {
	if len(values) == 0 {
		return nil, errors.New("at least one OAuth resource recipient is required")
	}
	base, err := url.Parse(audienceBaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse OAuth2 audience base URL: %w", err)
	}

	normalised := make([]string, 0, len(values))
	for _, value := range values {
		audience := strings.TrimSpace(value)
		if audience == "" || strings.Contains(audience, "%") {
			return nil, fmt.Errorf("resource audience %q is not a canonical platform audience", value)
		}
		parsed, parseErr := url.Parse(audience)
		if parseErr != nil || parsed.Scheme != "https" || parsed.Host == "" ||
			parsed.User != nil || parsed.Port() != "" || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
			return nil, fmt.Errorf("resource audience %q must be an absolute HTTPS URL without credentials, port, query, or fragment", value)
		}
		parsed.Host = strings.ToLower(parsed.Hostname())
		parsed.RawPath = ""
		if parsed.Host != base.Host || path.Clean(parsed.Path) != parsed.Path ||
			!isAudiencePathBelowBase(base.Path, parsed.Path) {
			return nil, fmt.Errorf("resource audience %q is outside the configured platform audience base", value)
		}
		normalised = append(normalised, parsed.String())
	}
	slices.Sort(normalised)
	if len(slices.Compact(slices.Clone(normalised))) != len(normalised) {
		return nil, errors.New("OAuth resource recipients must be unique")
	}
	return normalised, nil
}

func normalizeAudienceBaseURL(value string) (string, error) {
	value = strings.TrimSuffix(strings.TrimSpace(value), "/")
	if value == "" || strings.Contains(value, "%") {
		return "", errors.New("OAuth2 audience base URL must be a canonical absolute HTTPS URL")
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return "", fmt.Errorf("parse OAuth2 audience base URL: %w", err)
	}
	if parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Port() != "" ||
		parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" ||
		(parsed.Path != "" && path.Clean(parsed.Path) != parsed.Path) {
		return "", errors.New("OAuth2 audience base URL must be a canonical absolute HTTPS URL")
	}
	parsed.Host = strings.ToLower(parsed.Hostname())
	parsed.RawPath = ""
	return strings.TrimSuffix(parsed.String(), "/"), nil
}

func isAudiencePathBelowBase(basePath, audiencePath string) bool {
	basePath = strings.TrimSuffix(basePath, "/")
	if basePath == "" {
		return strings.HasPrefix(audiencePath, "/") && audiencePath != "/" && !strings.HasSuffix(audiencePath, "/")
	}
	return strings.HasPrefix(audiencePath, basePath+"/") && !strings.HasSuffix(audiencePath, "/")
}

func (b *authContractBusiness) validateAuthorizationPolicy(
	ctx context.Context,
	policy *tenancyv2.ServiceAuthorizationPolicyInput,
) ([]repository.AuthorizationGrant, error) {
	namespaces, err := b.serviceNamespaceRepo.ListAll(ctx)
	if err != nil {
		return nil, fmt.Errorf("load registered permission namespaces: %w", err)
	}
	return validateAuthorizationPolicy(policy, namespaces)
}

func validateAuthorizationPolicy(
	policy *tenancyv2.ServiceAuthorizationPolicyInput,
	namespaces []*models.ServiceNamespace,
) ([]repository.AuthorizationGrant, error) {
	if policy == nil {
		return nil, errors.New("authorization policy is required")
	}
	if policy.GetSchemaVersion() != models.AuthorizationPolicySchemaVersion {
		return nil, fmt.Errorf("authorization policy schema_version must be %d", models.AuthorizationPolicySchemaVersion)
	}
	if len(policy.GetGrants()) == 0 {
		return nil, errors.New("authorization policy must contain at least one grant")
	}
	result := make([]repository.AuthorizationGrant, 0, len(policy.GetGrants()))
	seen := make(map[string]struct{}, len(policy.GetGrants()))
	for _, grant := range policy.GetGrants() {
		scope := ""
		switch grant.GetScope() {
		case tenancyv2.AuthorizationScope_AUTHORIZATION_SCOPE_PARTITION_ONLY:
			scope = models.AuthorizationScopePartitionOnly
		case tenancyv2.AuthorizationScope_AUTHORIZATION_SCOPE_PARTITION_TREE:
			scope = models.AuthorizationScopePartitionTree
		default:
			return nil, fmt.Errorf("authorization grant %q has invalid scope", grant.GetNamespace())
		}
		key := grant.GetNamespace() + "\x00" + scope
		if _, exists := seen[key]; exists {
			return nil, fmt.Errorf("duplicate authorization grant %q with scope %q", grant.GetNamespace(), scope)
		}
		seen[key] = struct{}{}

		permissions := slices.Clone(grant.GetPermissions())
		if slices.Contains(permissions, authz.PermissionFullAccess) {
			return nil, fmt.Errorf("authorization grant %q must contain explicit permissions", grant.GetNamespace())
		}
		resolved, err := authz.ResolveServiceGrants(
			map[string][]string{grant.GetNamespace(): permissions},
			namespaces,
		)
		if err != nil {
			return nil, err
		}
		result = append(result, repository.AuthorizationGrant{
			Namespace:   grant.GetNamespace(),
			Scope:       scope,
			Permissions: resolved[grant.GetNamespace()],
		})
	}
	return result, nil
}

func validateOAuthClientConfiguration(
	configuration *tenancyv2.OAuthClientConfiguration,
	clientType string,
) ([]string, []string, []string, string, error) {
	if configuration == nil {
		return nil, nil, nil, "", errors.New("OAuth client configuration is required")
	}
	grantTypes := slices.Clone(configuration.GetGrantTypes())
	if len(grantTypes) == 0 {
		if clientType == "internal" || clientType == "external" {
			grantTypes = []string{"client_credentials"}
		} else {
			grantTypes = []string{"authorization_code", "refresh_token"}
		}
	}
	for _, grantType := range grantTypes {
		if !slices.Contains([]string{"authorization_code", "refresh_token", "client_credentials"}, grantType) {
			return nil, nil, nil, "", fmt.Errorf("unsupported OAuth grant type %q", grantType)
		}
	}
	responseTypes := slices.Clone(configuration.GetResponseTypes())
	if len(responseTypes) == 0 && clientType != "internal" && clientType != "external" {
		responseTypes = []string{"code"}
	}
	redirectURIs := slices.Clone(configuration.GetRedirectUris())
	for index, value := range redirectURIs {
		parsed, err := url.Parse(strings.TrimSpace(value))
		if err != nil || parsed.Scheme == "" {
			return nil, nil, nil, "", fmt.Errorf("redirect URI %d is invalid", index)
		}
		redirectURIs[index] = parsed.String()
	}
	scopes := strings.TrimSpace(configuration.GetScopes())
	if scopes == "" {
		if clientType == "internal" || clientType == "external" {
			scopes = clientType + " openid"
		} else {
			scopes = "openid offline_access profile"
		}
	}
	return grantTypes, responseTypes, redirectURIs, scopes, nil
}

func (b *authContractBusiness) oauthClientObject(
	ctx context.Context,
	client *models.Client,
) (*tenancyv2.OAuthClient, error) {
	recipients, err := b.recipientValues(ctx, client.ID)
	if err != nil {
		return nil, err
	}
	state := commonv1.STATE_ACTIVE
	if client.DeletedAt.Valid {
		state = commonv1.STATE_DELETED
	}
	object := &tenancyv2.OAuthClient{
		Id:       client.ID,
		Name:     client.Name,
		ClientId: client.ClientID,
		Type:     client.Type,
		Configuration: &tenancyv2.OAuthClientConfiguration{
			GrantTypes:              getStringSliceV2(client.GrantTypes, "types"),
			ResponseTypes:           getStringSliceV2(client.ResponseTypes, "types"),
			RedirectUris:            getStringSliceV2(client.RedirectURIs, "uris"),
			Scopes:                  client.Scopes,
			ResourceRecipients:      recipients,
			TokenEndpointAuthMethod: client.TokenEndpointAuthMethod,
			Properties:              client.Properties.ToProtoStruct(),
		},
		State:     state,
		CreatedAt: timestamppb.New(client.CreatedAt),
	}
	if client.ServiceAccountID != "" {
		object.Owner = &tenancyv2.OAuthClient_ServiceAccountId{ServiceAccountId: client.ServiceAccountID}
	} else {
		object.Owner = &tenancyv2.OAuthClient_PartitionId{PartitionId: client.PartitionID}
	}
	return object, nil
}

func (b *authContractBusiness) serviceAccountObject(
	ctx context.Context,
	serviceAccount *models.ServiceAccount,
) (*tenancyv2.ServiceAccount, error) {
	clients, err := b.clientRepo.ListByServiceAccountID(ctx, serviceAccount.ID)
	if err != nil {
		return nil, err
	}
	if len(clients) != 1 {
		return nil, fmt.Errorf("service account %q must own exactly one OAuth client, got %d", serviceAccount.ID, len(clients))
	}
	client, err := b.oauthClientObject(ctx, clients[0])
	if err != nil {
		return nil, err
	}
	policyState, err := b.policyRepo.GetByServiceAccountID(ctx, serviceAccount.ID)
	if err != nil {
		return nil, err
	}
	state := commonv1.STATE_ACTIVE
	if serviceAccount.DeletedAt.Valid || serviceAccount.State == int32(commonv1.STATE_DELETED) {
		state = commonv1.STATE_DELETED
	}
	return &tenancyv2.ServiceAccount{
		Id:                  serviceAccount.ID,
		TenantId:            serviceAccount.TenantID,
		PartitionId:         serviceAccount.PartitionID,
		ProfileId:           serviceAccount.ProfileID,
		Name:                serviceAccount.Name,
		Type:                serviceAccount.Type,
		OauthClient:         client,
		AuthorizationPolicy: policyObject(policyState),
		PublicKeys:          serviceAccount.PublicKeys.ToProtoStruct(),
		Properties:          serviceAccount.Properties.ToProtoStruct(),
		State:               state,
		CreatedAt:           timestamppb.New(serviceAccount.CreatedAt),
	}, nil
}

func policyObject(state *repository.AuthorizationPolicyState) *tenancyv2.ServiceAuthorizationPolicy {
	status := tenancyv2.AuthorizationPolicyStatus_AUTHORIZATION_POLICY_STATUS_UNSPECIFIED
	switch state.Policy.Status {
	case models.AuthorizationPolicyPending:
		status = tenancyv2.AuthorizationPolicyStatus_AUTHORIZATION_POLICY_STATUS_PENDING
	case models.AuthorizationPolicyApplied:
		status = tenancyv2.AuthorizationPolicyStatus_AUTHORIZATION_POLICY_STATUS_APPLIED
	case models.AuthorizationPolicyFailed:
		status = tenancyv2.AuthorizationPolicyStatus_AUTHORIZATION_POLICY_STATUS_FAILED
	}
	grants := make([]*tenancyv2.ServiceAuthorizationGrant, 0, len(state.Grants))
	for _, grant := range state.Grants {
		scope := tenancyv2.AuthorizationScope_AUTHORIZATION_SCOPE_UNSPECIFIED
		switch grant.Scope {
		case models.AuthorizationScopePartitionOnly:
			scope = tenancyv2.AuthorizationScope_AUTHORIZATION_SCOPE_PARTITION_ONLY
		case models.AuthorizationScopePartitionTree:
			scope = tenancyv2.AuthorizationScope_AUTHORIZATION_SCOPE_PARTITION_TREE
		}
		grants = append(grants, &tenancyv2.ServiceAuthorizationGrant{
			Namespace: grant.Namespace, Permissions: slices.Clone(grant.Permissions), Scope: scope,
		})
	}
	return &tenancyv2.ServiceAuthorizationPolicy{
		Id:                state.Policy.ID,
		SchemaVersion:     state.Policy.SchemaVersion,
		Generation:        state.Policy.Generation,
		AppliedGeneration: state.Policy.AppliedGeneration,
		Status:            status,
		Grants:            grants,
		LastErrorCode:     state.Policy.LastErrorCode,
		NextAttemptAt:     timestamppbOrNil(state.Policy.NextAttemptAt),
		SyncedAt:          timestamppbOrNil(state.Policy.SyncedAt),
	}
}

func (b *authContractBusiness) recipientValues(ctx context.Context, clientID string) ([]string, error) {
	recipients, err := b.recipientRepo.ListByClientRef(ctx, clientID)
	if err != nil {
		return nil, err
	}
	values := make([]string, 0, len(recipients))
	for _, recipient := range recipients {
		values = append(values, recipient.ResourceAudience)
	}
	return values, nil
}

func (b *authContractBusiness) emitClientSync(ctx context.Context, client *models.Client, profileID string) {
	payload := data.JSONMap{"id": client.ID}
	if profileID != "" {
		payload["profile_id"] = profileID
	}
	if err := b.eventsMan.Emit(ctx, events.EventKeyClientSynchronization, payload); err != nil {
		util.Log(ctx).WithError(err).WithField("client_id", client.ID).Error("enqueue Hydra client reconciliation")
	}
}

func (b *authContractBusiness) emitPolicySync(ctx context.Context, id string, generation int64, reason string) {
	if err := b.eventsMan.Emit(ctx, events.EventKeyAuthzServiceAccountSync, data.JSONMap{
		"id": id, "generation": generation, "reason": reason,
	}); err != nil {
		util.Log(ctx).WithError(err).WithField("service_account_id", id).
			Error("enqueue service-account authorization reconciliation")
	}
}

func protoStructToJSONMap(value *structpb.Struct) data.JSONMap {
	if value == nil {
		return nil
	}
	return data.JSONMap(value.AsMap())
}

func getStringSliceV2(values data.JSONMap, key string) []string {
	if values == nil {
		return nil
	}
	raw, ok := values[key]
	if !ok {
		return nil
	}
	result := make([]string, 0)
	switch typed := raw.(type) {
	case []string:
		result = append(result, typed...)
	case []any:
		for _, value := range typed {
			if item, ok := value.(string); ok {
				result = append(result, item)
			}
		}
	}
	return result
}

func timestamppbOrNil(value *time.Time) *timestamppb.Timestamp {
	if value == nil {
		return nil
	}
	return timestamppb.New(*value)
}
