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

package repository_test

import (
	"testing"

	"github.com/antinvestor/service-authentication/apps/tenancy/service/models"
	"github.com/antinvestor/service-authentication/apps/tenancy/tests"
	"github.com/pitabwire/frame/v3/data"
	"github.com/pitabwire/frame/v3/datastore"
	"github.com/pitabwire/frame/v3/frametests/definition"
	"github.com/pitabwire/util"
	"github.com/stretchr/testify/suite"
)

type ClientRepositoryTestSuite struct {
	tests.BaseTestSuite
}

func (s *ClientRepositoryTestSuite) TestGreenfieldSeedUsesOnlyNormalizedAuthContract() {
	s.WithTestDependancies(s.T(), func(t *testing.T, dep *definition.DependencyOption) {
		ctx, svc, _ := s.CreateService(t, dep)
		db := svc.DatastoreManager().GetPool(ctx, datastore.DefaultPoolName).DB(ctx, true)

		for table, expected := range map[string]int64{
			"clients":                                   69,  // #856 (60) + stawi-imports-web prod/dev + service_commerce + service_procurement + service_notification_whatsapp + service_manufacturing + service_payment_flutterwave + finance + settlement
			"oauth_client_recipients":                   343, // + service_imports files/notification, service_commerce (9), service_procurement (4), trustage /commerce (1), service_notification_whatsapp (4), service_manufacturing (2), service_payment_flutterwave (4), service_finance (8), service_settlement (5), trustage stawi (2), chat drone /stawi-settlement (1), chat app prod/dev /stawi-settlement + /stawi-finance (4), settlement /authentication (1), fintech peer audiences for the limits rollout (12)
			"service_accounts":                          56,  // + service_commerce + service_procurement + service_notification_whatsapp + service_manufacturing + service_payment_flutterwave + service_finance + service_settlement
			"service_account_authorization_policies":    56,
			"service_account_authorization_grants":      237,  // + service_imports files/notification grants, service_commerce (8), service_procurement (2), trustage service_commerce (1), service_notification_whatsapp (4), service_manufacturing (1), service_payment_flutterwave (4), service_finance (7), service_settlement (4), trustage stawi (2), chat drone service_settlement (1), settlement service_authentication (1), finance service_chat (1), settlement service_finance (1), fintech limits rollout (13)
			"service_account_authorization_permissions": 2163, // + service_imports content/notification permits, service_commerce (24), service_procurement (9), trustage ledger_post/shops_list (2), service_notification_whatsapp (33), service_manufacturing (39), service_payment_flutterwave (40), service_finance (61), service_settlement (13), trustage (2), chat drone (3), settlement auth_genesis_verify (1), finance service_chat (2), settlement genesis_policy_view (1), loan book finance service_chat (4) + service_settlement (1), chat profile_account_view (1), fintech limits rollout (20), operations loan_view (1)
		} {
			var count int64
			s.Require().NoError(db.Table(table).Count(&count).Error)
			s.Equal(expected, count, table)
		}

		s.False(db.Migrator().HasColumn("clients", "audiences"))
		s.False(db.Migrator().HasColumn("clients", "roles"))
		s.False(db.Migrator().HasColumn("service_accounts", "audiences"))
		s.False(db.Migrator().HasColumn("service_accounts", "client_secret"))

		var invalidRecipients int64
		s.Require().NoError(db.Table("oauth_client_recipients").
			Where("resource_audience NOT LIKE ?", "https://%").
			Count(&invalidRecipients).Error)
		s.Zero(invalidRecipients)

		var wildcardPermissions int64
		s.Require().NoError(db.Table("service_account_authorization_permissions").
			Where("permission = ?", "*").
			Count(&wildcardPermissions).Error)
		s.Zero(wildcardPermissions)

		// Every permission namespace a Frame service registers must have exactly
		// one internal service account able to own it (name or client_id).
		for namespace, clientID := range map[string]string{
			"service_chat":       "service-chat-drone",
			"service_finance":    "finance",
			"service_settlement": "settlement",
		} {
			var owners []string
			s.Require().NoError(db.Table("service_accounts").
				Where("name = ? OR replace(client_id, '-', '_') = ?", namespace, namespace).
				Pluck("client_id", &owners).Error)
			s.Equal([]string{clientID}, owners, namespace)
		}
	})
}

func (s *ClientRepositoryTestSuite) TestCreateAndGetByID() {
	s.WithTestDependancies(s.T(), func(t *testing.T, dep *definition.DependencyOption) {
		ctx, _, deps := s.CreateService(t, dep)
		repo := deps.Server.ClientRepo

		tenant := &models.Tenant{Name: "T"}
		err := deps.TenantRepo.Create(ctx, tenant)
		s.Require().NoError(err)

		partitionID := util.IDString()
		partition := &models.Partition{
			Name: "P",
			BaseModel: data.BaseModel{
				ID: partitionID, TenantID: tenant.ID, PartitionID: partitionID,
			},
		}
		err = deps.PartitionRepo.Create(ctx, partition)
		s.Require().NoError(err)

		clientID := "oauth-" + util.IDString()
		client := &models.Client{
			BaseModel: data.BaseModel{
				TenantID:    tenant.ID,
				PartitionID: partitionID,
			},
			Name:     "Test Client",
			ClientID: clientID,
			Type:     "public",
			Scopes:   "openid offline_access",
		}
		err = repo.Create(ctx, client)
		s.Require().NoError(err)
		s.NotEmpty(client.ID)

		found, err := repo.GetByID(ctx, client.ID)
		s.Require().NoError(err)
		s.Equal("Test Client", found.Name)
		s.Equal(clientID, found.ClientID)
	})
}

func (s *ClientRepositoryTestSuite) TestGetByClientID() {
	s.WithTestDependancies(s.T(), func(t *testing.T, dep *definition.DependencyOption) {
		ctx, _, deps := s.CreateService(t, dep)
		repo := deps.Server.ClientRepo

		clientID := "unique-" + util.IDString()
		client := &models.Client{
			Name:     "By ClientID",
			ClientID: clientID,
			Type:     "internal",
		}
		err := repo.Create(ctx, client)
		s.Require().NoError(err)

		found, err := repo.GetByClientID(ctx, clientID)
		s.Require().NoError(err)
		s.Equal(client.ID, found.ID)
	})
}

func (s *ClientRepositoryTestSuite) TestGetByClientID_NotFound() {
	s.WithTestDependancies(s.T(), func(t *testing.T, dep *definition.DependencyOption) {
		ctx, _, deps := s.CreateService(t, dep)
		repo := deps.Server.ClientRepo

		_, err := repo.GetByClientID(ctx, "nonexistent")
		s.Error(err)
	})
}

func (s *ClientRepositoryTestSuite) TestListByPartition() {
	s.WithTestDependancies(s.T(), func(t *testing.T, dep *definition.DependencyOption) {
		ctx, _, deps := s.CreateService(t, dep)
		repo := deps.Server.ClientRepo

		partitionID := util.IDString()
		for i := range 3 {
			client := &models.Client{
				BaseModel: data.BaseModel{PartitionID: partitionID},
				Name:      "Client",
				ClientID:  util.IDString(),
				Type:      "public",
			}
			err := repo.Create(ctx, client)
			s.Require().NoError(err, "failed creating client %d", i)
		}

		clients, err := repo.ListByPartition(ctx, partitionID)
		s.Require().NoError(err)
		s.GreaterOrEqual(len(clients), 3)
	})
}

func (s *ClientRepositoryTestSuite) TestListByPartition_Empty() {
	s.WithTestDependancies(s.T(), func(t *testing.T, dep *definition.DependencyOption) {
		ctx, _, deps := s.CreateService(t, dep)
		repo := deps.Server.ClientRepo

		clients, err := repo.ListByPartition(ctx, "empty-partition")
		s.Require().NoError(err)
		s.Empty(clients)
	})
}

func TestClientRepository(t *testing.T) {
	suite.Run(t, new(ClientRepositoryTestSuite))
}
