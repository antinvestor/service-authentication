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

package repository

import (
	"context"
	"time"

	"github.com/antinvestor/service-authentication/apps/tenancy/service/models"
	"github.com/pitabwire/frame/v2/datastore"
)

type TenantRepository interface {
	datastore.BaseRepository[*models.Tenant]
}

type PartitionRepository interface {
	datastore.BaseRepository[*models.Partition]
	GetByDomain(ctx context.Context, domain string) (*models.Partition, error)
	GetChildren(ctx context.Context, id string) ([]*models.Partition, error)
	GetParents(ctx context.Context, id string) ([]*models.Partition, error)
	CountByTenantID(ctx context.Context, tenantID string) (int64, error)
	// ListAll returns every partition (used by authz bootstrap).
	ListAll(ctx context.Context) ([]*models.Partition, error)
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
	ListByPartition(ctx context.Context, partitionID string) ([]*models.Page, error)
}

type AccessRepository interface {
	datastore.BaseRepository[*models.Access]
	GetByPartitionAndProfile(ctx context.Context, partitionID string, profile string) (*models.Access, error)
	ListByPartition(ctx context.Context, partitionID string) ([]*models.Access, error)
	ListByProfileID(ctx context.Context, profileID string) ([]*models.Access, error)
	CountByPartitionID(ctx context.Context, partitionID string) (int64, error)
}
type AccessRoleRepository interface {
	datastore.BaseRepository[*models.AccessRole]
	GetByAccessID(ctx context.Context, accessID string) ([]*models.AccessRole, error)
}

type ClientRepository interface {
	datastore.BaseRepository[*models.Client]
	GetByClientID(ctx context.Context, clientID string) (*models.Client, error)
	GetByIDIncludingDeleted(ctx context.Context, id string) (*models.Client, error)
	ListByPartition(ctx context.Context, partitionID string) ([]*models.Client, error)
	ListByServiceAccountID(ctx context.Context, serviceAccountID string) ([]*models.Client, error)
	CountByPartitionID(ctx context.Context, partitionID string) (int64, error)
}

type OAuthClientRecipientRepository interface {
	datastore.BaseRepository[*models.OAuthClientRecipient]
	ListByClientRef(ctx context.Context, clientRef string) ([]*models.OAuthClientRecipient, error)
	ReplaceForClient(ctx context.Context, client *models.Client, audiences []string) error
}

type ServiceAccountRepository interface {
	datastore.BaseRepository[*models.ServiceAccount]
	GetByIDPrimary(ctx context.Context, id string) (*models.ServiceAccount, error)
	GetByPartitionAndProfile(ctx context.Context, partitionID, profileID string) (*models.ServiceAccount, error)
	GetByClientAndProfile(ctx context.Context, clientID, profileID string) (*models.ServiceAccount, error)
	GetByClientID(ctx context.Context, clientID string) (*models.ServiceAccount, error)
	GetByClientRef(ctx context.Context, clientRef string) (*models.ServiceAccount, error)
	ListByPartition(ctx context.Context, partitionID string) ([]*models.ServiceAccount, error)
	// ListAll returns every service account (used by authz bootstrap).
	ListAll(ctx context.Context) ([]*models.ServiceAccount, error)
	CountByPartitionID(ctx context.Context, partitionID string) (int64, error)
}

type AuthorizationGrant struct {
	Namespace   string
	Scope       string
	Permissions []string
}

type AuthorizationPolicyState struct {
	Policy *models.ServiceAccountAuthorizationPolicy
	Grants []AuthorizationGrant
}

type ServiceAccountAuthorizationPolicyRepository interface {
	datastore.BaseRepository[*models.ServiceAccountAuthorizationPolicy]
	GetByServiceAccountID(ctx context.Context, serviceAccountID string) (*AuthorizationPolicyState, error)
	ListPending(ctx context.Context) ([]*models.ServiceAccountAuthorizationPolicy, error)
	ListByNamespace(ctx context.Context, namespace string) ([]*models.ServiceAccountAuthorizationPolicy, error)
	Replace(ctx context.Context, serviceAccount *models.ServiceAccount, grants []AuthorizationGrant) (*models.ServiceAccountAuthorizationPolicy, error)
	RecordFailure(ctx context.Context, policyID string, generation int64, code, message string, nextAttempt time.Time) error
	ListAppliedTuples(ctx context.Context, policyID string) ([]*models.ServiceAccountAppliedTuple, error)
	ReplaceAppliedState(
		ctx context.Context,
		policy *models.ServiceAccountAuthorizationPolicy,
		tuples []*models.ServiceAccountAppliedTuple,
	) error
}

type AuthContractRepository interface {
	CreateOAuthClient(ctx context.Context, client *models.Client, recipients []string) error
	CreateServiceAccount(
		ctx context.Context,
		serviceAccount *models.ServiceAccount,
		client *models.Client,
		recipients []string,
		grants []AuthorizationGrant,
	) (*models.ServiceAccountAuthorizationPolicy, error)
	UpdateOAuthClient(ctx context.Context, client *models.Client, fields []string, recipients []string) error
	UpdateServiceAccount(
		ctx context.Context,
		serviceAccount *models.ServiceAccount,
		serviceAccountFields []string,
		client *models.Client,
		clientFields []string,
		recipients []string,
		replaceRecipients bool,
		grants []AuthorizationGrant,
		replacePolicy bool,
	) (*models.ServiceAccountAuthorizationPolicy, error)
	FinalizeServiceAccountRemoval(ctx context.Context, serviceAccountID string) (string, error)
}
