package repository

import (
	"context"

	"github.com/antinvestor/service-authentication/apps/tenancy/service/models"
	"github.com/pitabwire/frame"
	"github.com/pitabwire/frame/framedata"
)

type TenantRepository interface {
	GetByID(ctx context.Context, id string) (*models.Tenant, error)
	Search(ctx context.Context, query *framedata.SearchQuery) (frame.JobResultPipe[[]*models.Tenant], error)
	Save(ctx context.Context, tenant *models.Tenant) error
	Delete(ctx context.Context, id string) error
}

type PartitionRepository interface {
	GetByID(ctx context.Context, id string) (*models.Partition, error)
	Search(ctx context.Context, query *framedata.SearchQuery) (frame.JobResultPipe[[]*models.Partition], error)
	GetChildren(ctx context.Context, id string) ([]*models.Partition, error)
	GetParents(ctx context.Context, id string) ([]*models.Partition, error)
	Save(ctx context.Context, partition *models.Partition) error
	Delete(ctx context.Context, id string) error

	GetRoles(ctx context.Context, partitionID string) ([]*models.PartitionRole, error)
	GetRolesByID(ctx context.Context, id ...string) ([]*models.PartitionRole, error)
	SaveRole(ctx context.Context, role *models.PartitionRole) error
	RemoveRole(ctx context.Context, partitionRoleID string) error
}

type PageRepository interface {
	GetByID(ctx context.Context, id string) (*models.Page, error)
	GetByPartitionAndName(ctx context.Context, partitionID string, name string) (*models.Page, error)
	Save(ctx context.Context, partition *models.Page) error
	Delete(ctx context.Context, id string) error
}

type AccessRepository interface {
	GetByID(ctx context.Context, id string) (*models.Access, error)
	GetByPartitionAndProfile(ctx context.Context, partitionID string, profile string) (*models.Access, error)
	Save(ctx context.Context, access *models.Access) error
	Delete(ctx context.Context, id string) error

	GetRoles(ctx context.Context, accessID string) ([]*models.AccessRole, error)
	SaveRole(ctx context.Context, role *models.AccessRole) error
	RemoveRole(ctx context.Context, accessRoleID string) error
}
