package repository

import (
	"context"

	"github.com/antinvestor/service-authentication/apps/tenancy/service/models"
	"github.com/pitabwire/frame/datastore"
)

type TenantRepository interface {
	datastore.BaseRepository[*models.Tenant]
}

type PartitionRepository interface {
	datastore.BaseRepository[*models.Partition]
	GetByDomain(ctx context.Context, domain string) (*models.Partition, error)
	GetChildren(ctx context.Context, id string) ([]*models.Partition, error)
	GetParents(ctx context.Context, id string) ([]*models.Partition, error)
}
type PartitionRoleRepository interface {
	datastore.BaseRepository[*models.PartitionRole]
	GetByPartitionID(ctx context.Context, partitionID string) ([]*models.PartitionRole, error)
	GetDefaultByPartitionID(ctx context.Context, partitionID string) ([]*models.PartitionRole, error)
	GetRolesByID(ctx context.Context, id ...string) ([]*models.PartitionRole, error)
	GetByPartitionAndNames(ctx context.Context, partitionID string, names []string) ([]*models.PartitionRole, error)
}

type PageRepository interface {
	datastore.BaseRepository[*models.Page]
	GetByPartitionAndName(ctx context.Context, partitionID string, name string) (*models.Page, error)
}

type AccessRepository interface {
	datastore.BaseRepository[*models.Access]
	GetByPartitionAndProfile(ctx context.Context, partitionID string, profile string) (*models.Access, error)
}
type AccessRoleRepository interface {
	datastore.BaseRepository[*models.AccessRole]
	GetByAccessID(ctx context.Context, accessID string) ([]*models.AccessRole, error)
}

type ClientRepository interface {
	datastore.BaseRepository[*models.Client]
	GetByClientID(ctx context.Context, clientID string) (*models.Client, error)
	ListByPartition(ctx context.Context, partitionID string) ([]*models.Client, error)
}

type ServiceAccountRepository interface {
	datastore.BaseRepository[*models.ServiceAccount]
	GetByPartitionAndProfile(ctx context.Context, partitionID, profileID string) (*models.ServiceAccount, error)
	GetByClientAndProfile(ctx context.Context, clientID, profileID string) (*models.ServiceAccount, error)
	GetByClientID(ctx context.Context, clientID string) (*models.ServiceAccount, error)
	GetByClientRef(ctx context.Context, clientRef string) (*models.ServiceAccount, error)
	ListByPartition(ctx context.Context, partitionID string) ([]*models.ServiceAccount, error)
}
