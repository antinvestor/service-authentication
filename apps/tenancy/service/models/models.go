package models

import (
	commonv1 "github.com/antinvestor/apis/go/common/v1"
	partitionv1 "github.com/antinvestor/apis/go/partition/v1"
	"github.com/pitabwire/frame"
)

type Tenant struct {
	frame.BaseModel
	Name        string `gorm:"type:varchar(100);"`
	Description string `gorm:"type:text;"`
	Properties  frame.JSONMap
}

func (t *Tenant) ToAPI() *partitionv1.TenantObject {

	return &partitionv1.TenantObject{
		Id:          t.ID,
		Description: t.Description,
		Properties:  t.Properties.ToProtoStruct(),
	}
}

type Partition struct {
	frame.BaseModel
	Name         string        `gorm:"type:varchar(100);" json:"name"`
	Description  string        `gorm:"type:text;"         json:"description"`
	ParentID     string        `gorm:"type:varchar(50);"  json:"parent_id"`
	ClientSecret string        `gorm:"type:varchar(250);" json:"client_secret"`
	Properties   frame.JSONMap `                          json:"properties"`
	State        int32         `                          json:"state"`
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
	}
}

type PartitionRole struct {
	frame.BaseModel
	Name       string `gorm:"type:varchar(100);"`
	Properties frame.JSONMap
}

func (pr *PartitionRole) ToAPI() *partitionv1.PartitionRoleObject {

	return &partitionv1.PartitionRoleObject{
		PartitionId: pr.PartitionID,
		Name:        pr.Name,
		Properties:  pr.Properties.ToProtoStruct(),
	}
}

type Page struct {
	frame.BaseModel
	Name  string `gorm:"type:varchar(50);"`
	HTML  string `gorm:"type:text;"`
	State int32
}

type Access struct {
	frame.BaseModel
	ProfileID string `gorm:"type:varchar(50);"`
	State     int32
}

type AccessRole struct {
	frame.BaseModel
	AccessID        string `gorm:"type:varchar(50);"`
	PartitionRoleID string `gorm:"type:varchar(50);"`
}
