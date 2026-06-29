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

package models

import (
	"errors"
	"maps"
	"time"

	commonv1 "buf.build/gen/go/antinvestor/common/protocolbuffers/go/common/v1"
	tenancyv1 "buf.build/gen/go/antinvestor/tenancy/protocolbuffers/go/tenancy/v1"
	"github.com/antinvestor/service-authentication/pkg/partitionpolicy"
	"github.com/antinvestor/service-authentication/pkg/tenantenv"
	"github.com/pitabwire/frame/v2/data"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type Tenant struct {
	data.BaseModel
	Name        string `gorm:"type:varchar(100);"`
	Description string `gorm:"type:text;"`
	Environment string `gorm:"type:varchar(20);not null;default:'production';index"`
	Properties  data.JSONMap
}

func (t *Tenant) ToAPI() *tenancyv1.TenantObject {
	return &tenancyv1.TenantObject{
		Id:          t.ID,
		Name:        t.Name,
		Description: t.Description,
		Properties:  t.Properties.ToProtoStruct(),
		CreatedAt:   timestamppb.New(t.CreatedAt),
		Environment: tenantenv.ToProto(t.Environment),
	}
}

type Partition struct {
	data.BaseModel
	Name            string       `gorm:"type:varchar(100);" json:"name"`
	Description     string       `gorm:"type:text;"         json:"description"`
	Domain          string       `gorm:"type:varchar(255);index:idx_partitions_domain,unique,where:domain != ''" json:"domain"`
	ParentID        string       `gorm:"type:varchar(50);"  json:"parent_id"`
	AllowAutoAccess *bool        `gorm:"column:allow_auto_access;not null;default:true" json:"allow_auto_access"`
	Properties      data.JSONMap `                          json:"properties"`
	State           int32        `                          json:"state"`
}

func (p *Partition) AutoAccessAllowed() bool {
	if p == nil || p.AllowAutoAccess == nil {
		return true
	}

	return *p.AllowAutoAccess
}

func (p *Partition) SetAllowAutoAccess(allow bool) {
	if p == nil {
		return
	}

	p.AllowAutoAccess = &allow
}

func (p *Partition) ToAPI() *tenancyv1.PartitionObject {
	props := make(data.JSONMap)
	if p.Properties != nil {
		maps.Copy(props, p.Properties)
	}
	delete(props, partitionpolicy.PropertyAllowAutoAccessSetup)
	props[partitionpolicy.PropertyAllowAutoAccess] = p.AutoAccessAllowed()

	return &tenancyv1.PartitionObject{
		Id:          p.ID,
		TenantId:    p.TenantID,
		ParentId:    p.ParentID,
		Name:        p.Name,
		Description: p.Description,
		Properties:  props.ToProtoStruct(),
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

func (pr *PartitionRole) ToAPI() *tenancyv1.PartitionRoleObject {
	state := commonv1.STATE_ACTIVE
	if pr.DeletedAt.Valid {
		state = commonv1.STATE_DELETED
	}

	props := make(data.JSONMap, len(pr.Properties)+1)
	maps.Copy(props, pr.Properties)
	props["is_default"] = pr.IsDefault

	return &tenancyv1.PartitionRoleObject{
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

func (p *Page) ToAPI() *tenancyv1.PageObject {
	return &tenancyv1.PageObject{
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

func (a *Access) ToAPI(partitionObject *tenancyv1.PartitionObject) (*tenancyv1.AccessObject, error) {

	if partitionObject == nil {
		return nil, errors.New("no partition exists for this access")
	}

	return &tenancyv1.AccessObject{
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
	LogoURI                 string       `gorm:"type:text;"                                                                 json:"logo_uri"`                   // Logo URL for OIDC clients
	PostLogoutRedirectURIs  data.JSONMap `                                                                                  json:"post_logout_redirect_uris"`  // {"uris": ["https://app.example.com/"]}
	TokenEndpointAuthMethod string       `gorm:"type:varchar(50);"                                                          json:"token_endpoint_auth_method"` // "none", "client_secret_post", "client_secret_basic", "private_key_jwt"
	ServiceAccountID        string       `gorm:"type:varchar(50);index:idx_clients_service_account_id"                      json:"service_account_id"`         // FK → ServiceAccount.ID; empty = partition client
	Properties              data.JSONMap `                                                                                  json:"properties"`
	State                   int32        `                                                                                  json:"state"`
	SyncedAt                *time.Time   `gorm:"index"                                                                      json:"synced_at"`
}

type ServiceAccount struct {
	data.BaseModel
	Name       string `gorm:"type:varchar(100);not null;default:''"`
	ProfileID  string `gorm:"type:varchar(50);not null;index:idx_sa_profile"`
	ClientID   string `gorm:"type:varchar(100);uniqueIndex"`            // OAuth2 client_id (denormalized from Client for lookup)
	ClientRef  string `gorm:"type:varchar(50);index:idx_sa_client_ref"` // FK → Client.ID
	Type       string `gorm:"type:varchar(20);not null;default:'internal'"`
	State      int32
	PublicKeys data.JSONMap
	Properties data.JSONMap
}

type AccessRole struct {
	data.BaseModel
	AccessID        string `gorm:"type:varchar(50);"`
	PartitionRoleID string `gorm:"type:varchar(50);"`
}

func (ar *AccessRole) ToAPI(partitionRoleObj *tenancyv1.PartitionRoleObject) *tenancyv1.AccessRoleObject {
	return &tenancyv1.AccessRoleObject{
		Id:       ar.GetID(),
		AccessId: ar.AccessID,
		Role:     partitionRoleObj,
	}
}
