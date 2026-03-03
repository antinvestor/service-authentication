package models

import (
	"errors"

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
	Name         string       `gorm:"type:varchar(100);" json:"name"`
	Description  string       `gorm:"type:text;"         json:"description"`
	ParentID     string       `gorm:"type:varchar(50);"  json:"parent_id"`
	ClientSecret string       `gorm:"type:varchar(250);" json:"client_secret"`
	Properties   data.JSONMap `                          json:"properties"`
	State        int32        `                          json:"state"`
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
	for k, v := range pr.Properties {
		props[k] = v
	}
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

type ServiceAccount struct {
	data.BaseModel
	ProfileID    string `gorm:"type:varchar(50);not null;index:idx_sa_profile"`
	ClientID     string `gorm:"type:varchar(100);uniqueIndex"`
	ClientSecret string `gorm:"type:varchar(250);"`
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
	}

	if sa.Audiences != nil {
		obj.Audiences = sa.Audiences.ToProtoStruct()
	}

	props := sa.Properties
	if props == nil {
		props = make(data.JSONMap)
	}
	props["type"] = sa.Type
	obj.Properties = props.ToProtoStruct()

	return obj
}

type AccessRole struct {
	data.BaseModel
	AccessID        string `gorm:"type:varchar(50);"`
	PartitionRoleID string `gorm:"type:varchar(50);"`
}

func (ar *AccessRole) ToAPI(partitionRoleObj *partitionv1.PartitionRoleObject) *partitionv1.AccessRoleObject {
	return &partitionv1.AccessRoleObject{
		AccessRoleId: ar.GetID(),
		AccessId:     ar.AccessID,
		Role:         partitionRoleObj,
	}
}
