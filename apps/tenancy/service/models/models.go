package models

import (
	"errors"
	"maps"
	"time"

	commonv1 "buf.build/gen/go/antinvestor/common/protocolbuffers/go/common/v1"
	partitionv1 "buf.build/gen/go/antinvestor/partition/protocolbuffers/go/partition/v1"
	"github.com/pitabwire/frame/data"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type Tenant struct {
	data.BaseModel
	Name        string `gorm:"type:varchar(100);"`
	Description string `gorm:"type:text;"`
	Properties  data.JSONMap
}

func (t *Tenant) ToAPI() *partitionv1.TenantObject {
	return &partitionv1.TenantObject{
		Id:          t.ID,
		Name:        t.Name,
		Description: t.Description,
		Properties:  t.Properties.ToProtoStruct(),
		CreatedAt:   timestamppb.New(t.CreatedAt),
	}
}

type Partition struct {
	data.BaseModel
	Name        string       `gorm:"type:varchar(100);" json:"name"`
	Description string       `gorm:"type:text;"         json:"description"`
	Domain      string       `gorm:"type:varchar(255);index:idx_partitions_domain,unique,where:domain != ''" json:"domain"`
	ParentID    string       `gorm:"type:varchar(50);"  json:"parent_id"`
	Properties  data.JSONMap `                          json:"properties"`
	State       int32        `                          json:"state"`
}

func (p *Partition) ToAPI() *partitionv1.PartitionObject {
	return &partitionv1.PartitionObject{
		Id:          p.ID,
		TenantId:    p.TenantID,
		ParentId:    p.ParentID,
		Name:        p.Name,
		Description: p.Description,
		Properties:  p.Properties.ToProtoStruct(),
		State:       commonv1.STATE(p.State),
		CreatedAt:   timestamppb.New(p.CreatedAt),
		Domain:      p.Domain,
	}
}

type PartitionRole struct {
	data.BaseModel
	Name       string `gorm:"type:varchar(100);"`
	IsDefault  bool   `gorm:"default:false"`
	Properties data.JSONMap
}

func (pr *PartitionRole) ToAPI() *partitionv1.PartitionRoleObject {
	state := commonv1.STATE_ACTIVE
	if pr.DeletedAt.Valid {
		state = commonv1.STATE_DELETED
	}

	props := make(data.JSONMap, len(pr.Properties)+1)
	maps.Copy(props, pr.Properties)
	props["is_default"] = pr.IsDefault

	return &partitionv1.PartitionRoleObject{
		Id:          pr.ID,
		PartitionId: pr.PartitionID,
		Name:        pr.Name,
		Properties:  props.ToProtoStruct(),
		CreatedAt:   timestamppb.New(pr.CreatedAt),
		State:       state,
	}
}

type Page struct {
	data.BaseModel
	Name       string `gorm:"type:varchar(50);"`
	HTML       string `gorm:"type:text;"`
	State      int32
	Properties data.JSONMap
}

func (p *Page) ToAPI() *partitionv1.PageObject {
	return &partitionv1.PageObject{
		Id:         p.GetID(),
		Name:       p.Name,
		Html:       p.HTML,
		State:      commonv1.STATE(p.State),
		CreatedAt:  timestamppb.New(p.CreatedAt),
		Properties: p.Properties.ToProtoStruct(),
	}
}

type Access struct {
	data.BaseModel
	ProfileID string `gorm:"type:varchar(50);"`
	State     int32
}

func (a *Access) ToAPI(partitionObject *partitionv1.PartitionObject) (*partitionv1.AccessObject, error) {

	if partitionObject == nil {
		return nil, errors.New("no partition exists for this access")
	}

	return &partitionv1.AccessObject{
		Id:        a.GetID(),
		ProfileId: a.ProfileID,
		Partition: partitionObject,
		State:     commonv1.STATE(a.State),
		CreatedAt: timestamppb.New(a.CreatedAt),
	}, nil
}

// Client represents an OAuth2 client configuration attached to a partition.
// It defines HOW authentication happens (grant types, redirect URIs, scopes).
// For PKCE flows (public/confidential), users authenticate through the client.
// For client_credentials flows (internal/external), a ServiceAccount references
// a Client to provide the identity (profile).
//
// ServiceAccountID is set when this client belongs to a service account.
// If empty, the client belongs directly to the partition (user-facing).
type Client struct {
	data.BaseModel
	Name                    string       `gorm:"type:varchar(100);"                                                        json:"name"`
	ClientID                string       `gorm:"type:varchar(100);uniqueIndex"                                             json:"client_id"`
	ClientSecret            string       `gorm:"type:varchar(250);"                                                        json:"client_secret"`
	Type                    string       `gorm:"type:varchar(20);not null;default:'public'"                                 json:"type"`                       // "public", "confidential", "internal", "external"
	GrantTypes              data.JSONMap `                                                                                  json:"grant_types"`                // ["authorization_code","refresh_token"] or ["client_credentials"]
	ResponseTypes           data.JSONMap `                                                                                  json:"response_types"`             // ["code","token"]
	RedirectURIs            data.JSONMap `                                                                                  json:"redirect_uris"`              // ["https://app.example.com/callback"]
	Scopes                  string       `gorm:"type:text;"                                                                 json:"scopes"`                     // "openid offline_access profile"
	Audiences               data.JSONMap `                                                                                  json:"audiences"`                  // {"namespaces": ["service_profile",...]}
	Roles                   data.JSONMap `                                                                                  json:"roles"`                      // ["admin","member"] — permission template for SA tokens
	LogoURI                 string       `gorm:"type:text;"                                                                 json:"logo_uri"`                   // Logo URL for OIDC clients
	PostLogoutRedirectURIs  data.JSONMap `                                                                                  json:"post_logout_redirect_uris"`  // {"uris": ["https://app.example.com/"]}
	TokenEndpointAuthMethod string       `gorm:"type:varchar(50);"                                                          json:"token_endpoint_auth_method"` // "none", "client_secret_post", "client_secret_basic", "private_key_jwt"
	ServiceAccountID        string       `gorm:"type:varchar(50);index:idx_clients_service_account_id"                      json:"service_account_id"`         // FK → ServiceAccount.ID; empty = partition client
	Properties              data.JSONMap `                                                                                  json:"properties"`
	State                   int32        `                                                                                  json:"state"`
	SyncedAt                *time.Time   `gorm:"index"                                                                      json:"synced_at"`
}

func (c *Client) ToAPI() *partitionv1.ClientObject {
	state := commonv1.STATE_ACTIVE
	if c.DeletedAt.Valid {
		state = commonv1.STATE_DELETED
	}

	obj := &partitionv1.ClientObject{
		Id:            c.ID,
		Name:          c.Name,
		ClientId:      c.ClientID,
		Type:          c.Type,
		GrantTypes:    jsonMapToStringSlice(c.GrantTypes, "grant_types"),
		ResponseTypes: jsonMapToStringSlice(c.ResponseTypes, "response_types"),
		RedirectUris:  jsonMapToStringSlice(c.RedirectURIs, "uris"),
		Scopes:        c.Scopes,
		Audiences:     jsonMapToStringSlice(c.Audiences, "namespaces"),
		Roles:         c.GetRoleNames(),
		State:         state,
		CreatedAt:     timestamppb.New(c.CreatedAt),
	}

	props := make(data.JSONMap)
	if c.Properties != nil {
		maps.Copy(props, c.Properties)
	}
	if c.LogoURI != "" {
		props["logo_uri"] = c.LogoURI
	}
	if plru := jsonMapToStringSlice(c.PostLogoutRedirectURIs, "uris"); len(plru) > 0 {
		props["post_logout_redirect_uris"] = plru
	}
	if c.TokenEndpointAuthMethod != "" {
		props["token_endpoint_auth_method"] = c.TokenEndpointAuthMethod
	}
	if c.ServiceAccountID != "" {
		props["service_account_id"] = c.ServiceAccountID
	}
	if len(props) > 0 {
		obj.Properties = props.ToProtoStruct()
	}

	return obj
}

// ToServiceAccountAPI returns a ServiceAccountObject view of this client for backward compatibility.
func (c *Client) ToServiceAccountAPI() *partitionv1.ServiceAccountObject {
	state := commonv1.STATE_ACTIVE
	if c.DeletedAt.Valid {
		state = commonv1.STATE_DELETED
	}

	props := make(data.JSONMap, len(c.Properties)+3)
	maps.Copy(props, c.Properties)
	props["type"] = c.Type
	if c.GrantTypes != nil {
		props["grant_types"] = c.GrantTypes
	}
	if c.RedirectURIs != nil {
		props["redirect_uris"] = c.RedirectURIs
	}
	if c.Roles != nil {
		props["roles"] = c.Roles
	}

	obj := &partitionv1.ServiceAccountObject{
		Id:          c.ID,
		TenantId:    c.TenantID,
		PartitionId: c.PartitionID,
		ClientId:    c.ClientID,
		State:       state,
		CreatedAt:   timestamppb.New(c.CreatedAt),
		Properties:  props.ToProtoStruct(),
		Type:        c.Type,
		Audiences:   jsonMapToStringSlice(c.Audiences, "namespaces"),
	}

	return obj
}

// GetRoleNames extracts the list of role name strings from the Roles JSONMap.
func (c *Client) GetRoleNames() []string {
	if c.Roles == nil {
		return nil
	}
	raw, ok := c.Roles["roles"]
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
	}
	return nil
}

type ServiceAccount struct {
	data.BaseModel
	ProfileID    string `gorm:"type:varchar(50);not null;index:idx_sa_profile"`
	ClientID     string `gorm:"type:varchar(100);uniqueIndex"`                // OAuth2 client_id (denormalized from Client for lookup)
	ClientSecret string `gorm:"type:varchar(250);"`                           // DEPRECATED: kept for backward compat, new SAs use Client.ClientSecret
	ClientRef    string `gorm:"type:varchar(50);index:idx_sa_client_ref"`     // FK → Client.ID
	Type         string `gorm:"type:varchar(20);not null;default:'internal'"` // "internal" or "external"
	State        int32
	Audiences    data.JSONMap // {"namespaces": ["service_tenancy", "service_profile", ...]}
	PublicKeys   data.JSONMap // {"keys": [{"kid":"k1","kty":"EC","crv":"P-256","x":"...","y":"..."}]}
	Properties   data.JSONMap
}

func (sa *ServiceAccount) ToAPI() *partitionv1.ServiceAccountObject {
	state := commonv1.STATE_ACTIVE
	if sa.DeletedAt.Valid {
		state = commonv1.STATE_DELETED
	}

	obj := &partitionv1.ServiceAccountObject{
		Id:          sa.ID,
		TenantId:    sa.TenantID,
		PartitionId: sa.PartitionID,
		ProfileId:   sa.ProfileID,
		ClientId:    sa.ClientID,
		State:       state,
		CreatedAt:   timestamppb.New(sa.CreatedAt),
		Type:        sa.Type,
	}

	if sa.Audiences != nil {
		obj.Audiences = jsonMapToStringSlice(sa.Audiences, "namespaces")
	}

	if sa.Properties != nil {
		obj.Properties = sa.Properties.ToProtoStruct()
	}

	return obj
}

type AccessRole struct {
	data.BaseModel
	AccessID        string `gorm:"type:varchar(50);"`
	PartitionRoleID string `gorm:"type:varchar(50);"`
}

func (ar *AccessRole) ToAPI(partitionRoleObj *partitionv1.PartitionRoleObject) *partitionv1.AccessRoleObject {
	return &partitionv1.AccessRoleObject{
		Id:       ar.GetID(),
		AccessId: ar.AccessID,
		Role:     partitionRoleObj,
	}
}

// jsonMapToStringSlice extracts a []string from a JSONMap entry keyed by key.
func jsonMapToStringSlice(m data.JSONMap, key string) []string {
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
	}
	return nil
}
