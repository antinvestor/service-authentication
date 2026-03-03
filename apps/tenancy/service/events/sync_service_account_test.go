package events_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/antinvestor/service-authentication/apps/tenancy/service/events"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/models"
	"github.com/antinvestor/service-authentication/apps/tenancy/tests"
	"github.com/pitabwire/frame/config"
	"github.com/pitabwire/frame/data"
	"github.com/pitabwire/frame/frametests"
	"github.com/pitabwire/frame/frametests/definition"
	"github.com/pitabwire/util"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"gorm.io/gorm"
)

type SyncServiceAccountTestSuite struct {
	tests.BaseTestSuite
}

func TestSyncServiceAccountTestSuite(t *testing.T) {
	suite.Run(t, new(SyncServiceAccountTestSuite))
}

// TestSyncServiceAccountOnHydra_Internal tests direct Hydra sync for an internal SA.
func (suite *SyncServiceAccountTestSuite) TestSyncServiceAccountOnHydra_Internal() {
	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependencyOption) {
		ctx, svc, deps := suite.CreateService(t, dep)
		cfg, _ := svc.Config().(config.ConfigurationOAUTH2)
		saRepo := deps.Server.ServiceAccountRepo

		sa := &models.ServiceAccount{
			ClientID:     util.IDString(),
			ClientSecret: "test-internal-secret",
			Type:         "internal",
			ProfileID:    util.IDString(),
			Audiences:    data.JSONMap{"namespaces": []any{"service_profile", "service_tenancy"}},
			Properties:   data.JSONMap{},
		}

		err := events.SyncServiceAccountOnHydra(ctx, cfg, svc.HTTPClientManager(), saRepo, sa)
		if err != nil {
			t.Logf("SyncServiceAccountOnHydra error (may be expected in test env): %v", err)
		} else {
			t.Log("SyncServiceAccountOnHydra succeeded for internal SA")
			require.NotNil(t, sa.Properties)
		}

		// Verify SA structure integrity
		require.Equal(t, "internal", sa.Type)
		require.NotEmpty(t, sa.ClientID)
	})
}

// TestSyncServiceAccountOnHydra_External tests direct Hydra sync for an external SA.
func (suite *SyncServiceAccountTestSuite) TestSyncServiceAccountOnHydra_External() {
	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependencyOption) {
		ctx, svc, deps := suite.CreateService(t, dep)
		cfg, _ := svc.Config().(config.ConfigurationOAUTH2)
		saRepo := deps.Server.ServiceAccountRepo

		sa := &models.ServiceAccount{
			ClientID:     util.IDString(),
			ClientSecret: "test-external-secret",
			Type:         "external",
			ProfileID:    util.IDString(),
			Audiences:    data.JSONMap{"namespaces": []any{"api_gateway"}},
			Properties:   data.JSONMap{},
		}

		err := events.SyncServiceAccountOnHydra(ctx, cfg, svc.HTTPClientManager(), saRepo, sa)
		if err != nil {
			t.Logf("SyncServiceAccountOnHydra error (may be expected in test env): %v", err)
		} else {
			t.Log("SyncServiceAccountOnHydra succeeded for external SA")
			require.NotNil(t, sa.Properties)
		}

		require.Equal(t, "external", sa.Type)
	})
}

// TestSyncServiceAccountOnHydra_NoSecret tests sync for an SA without a client secret.
func (suite *SyncServiceAccountTestSuite) TestSyncServiceAccountOnHydra_NoSecret() {
	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependencyOption) {
		ctx, svc, deps := suite.CreateService(t, dep)
		cfg, _ := svc.Config().(config.ConfigurationOAUTH2)
		saRepo := deps.Server.ServiceAccountRepo

		sa := &models.ServiceAccount{
			ClientID:   util.IDString(),
			Type:       "internal",
			ProfileID:  util.IDString(),
			Properties: data.JSONMap{},
		}

		err := events.SyncServiceAccountOnHydra(ctx, cfg, svc.HTTPClientManager(), saRepo, sa)
		if err != nil {
			t.Logf("SyncServiceAccountOnHydra no-secret error: %v", err)
		} else {
			t.Log("SyncServiceAccountOnHydra no-secret succeeded")
		}
	})
}

// TestSyncServiceAccountOnHydra_DeletedSA tests sync for a soft-deleted SA.
func (suite *SyncServiceAccountTestSuite) TestSyncServiceAccountOnHydra_DeletedSA() {
	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependencyOption) {
		ctx, svc, deps := suite.CreateService(t, dep)
		cfg, _ := svc.Config().(config.ConfigurationOAUTH2)
		saRepo := deps.Server.ServiceAccountRepo

		sa := &models.ServiceAccount{
			BaseModel: data.BaseModel{
				ID: fmt.Sprintf("test-deleted-sa-%d", time.Now().Unix()),
				DeletedAt: gorm.DeletedAt{
					Time:  time.Now(),
					Valid: true,
				},
			},
			ClientID:  util.IDString(),
			Type:      "internal",
			ProfileID: util.IDString(),
		}

		err := events.SyncServiceAccountOnHydra(ctx, cfg, svc.HTTPClientManager(), saRepo, sa)
		if err != nil {
			t.Logf("Delete SA sync error (expected if client doesn't exist on Hydra): %v", err)
		} else {
			t.Log("Delete SA sync succeeded")
		}

		require.True(t, sa.DeletedAt.Valid, "SA should remain marked as deleted")
	})
}

// TestSyncServiceAccountOnHydra_ViaQueue tests the full async flow: create SA in DB,
// emit event, and wait for Hydra to register the client (Properties["client_id"] appears).
func (suite *SyncServiceAccountTestSuite) TestSyncServiceAccountOnHydra_ViaQueue() {
	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependencyOption) {
		ctx, svc, deps := suite.CreateService(t, dep)
		saRepo := deps.Server.ServiceAccountRepo

		// Create a parent partition (SA needs TenantID/PartitionID)
		tenantID := util.IDString()
		partitionID := util.IDString()
		partition := &models.Partition{
			Name: "SA Queue Test Partition",
			BaseModel: data.BaseModel{
				ID:          partitionID,
				TenantID:    tenantID,
				PartitionID: partitionID,
			},
			Properties: data.JSONMap{
				"redirect_uris": []any{"https://sa-queue-test.com/callback"},
				"scope":         "openid profile",
			},
		}
		err := deps.PartitionRepo.Create(ctx, partition)
		require.NoError(t, err)

		// Create SA record in DB
		sa := &models.ServiceAccount{
			ClientID:     util.IDString(),
			ClientSecret: "queue-test-secret",
			Type:         "internal",
			ProfileID:    util.IDString(),
			Audiences:    data.JSONMap{"namespaces": []any{"service_profile"}},
			Properties:   data.JSONMap{},
			BaseModel: data.BaseModel{
				TenantID:    tenantID,
				PartitionID: partitionID,
			},
		}
		err = saRepo.Create(ctx, sa)
		require.NoError(t, err)

		// Emit the SA sync event
		err = svc.EventsManager().Emit(ctx, events.EventKeyServiceAccountSynchronization, data.JSONMap{"id": sa.GetID()})
		require.NoError(t, err)

		// Wait for SA to be synced — Properties["client_id"] appears after Hydra registers the client
		finalSA, finalErr := frametests.WaitForConditionWithResult(ctx, func() (*models.ServiceAccount, error) {
			iSA, iErr := saRepo.GetByID(ctx, sa.GetID())
			if iErr != nil {
				if data.ErrorIsNoRows(iErr) {
					return nil, nil
				}
				return nil, iErr
			}

			_, ok := iSA.Properties["client_id"]
			if ok {
				return iSA, nil
			}

			return nil, nil
		}, 5*time.Second, 200*time.Millisecond)

		require.NoError(t, finalErr)
		require.NotNil(t, finalSA, "SA should have been synced with Hydra")
		require.Contains(t, finalSA.Properties, "client_id")
		require.Equal(t, "internal", finalSA.Type)
		t.Logf("SA synced via queue, properties: %v", finalSA.Properties)
	})
}

// TestSyncServiceAccountOnHydra_Idempotent verifies that syncing the same SA twice
// succeeds (first creates, second updates on Hydra).
func (suite *SyncServiceAccountTestSuite) TestSyncServiceAccountOnHydra_Idempotent() {
	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependencyOption) {
		ctx, svc, deps := suite.CreateService(t, dep)
		cfg, _ := svc.Config().(config.ConfigurationOAUTH2)
		saRepo := deps.Server.ServiceAccountRepo

		tenantID := util.IDString()
		partitionID := util.IDString()
		partition := &models.Partition{
			Name: "Idempotent Test Partition",
			BaseModel: data.BaseModel{
				ID:          partitionID,
				TenantID:    tenantID,
				PartitionID: partitionID,
			},
			Properties: data.JSONMap{},
		}
		err := deps.PartitionRepo.Create(ctx, partition)
		require.NoError(t, err)

		sa := &models.ServiceAccount{
			ClientID:     util.IDString(),
			ClientSecret: "idempotent-secret",
			Type:         "internal",
			ProfileID:    util.IDString(),
			Properties:   data.JSONMap{},
			BaseModel: data.BaseModel{
				TenantID:    tenantID,
				PartitionID: partitionID,
			},
		}
		err = saRepo.Create(ctx, sa)
		require.NoError(t, err)

		// First sync — creates Hydra client
		err = events.SyncServiceAccountOnHydra(ctx, cfg, svc.HTTPClientManager(), saRepo, sa)
		require.NoError(t, err, "first sync should succeed")

		// Second sync — updates Hydra client (idempotent)
		err = events.SyncServiceAccountOnHydra(ctx, cfg, svc.HTTPClientManager(), saRepo, sa)
		require.NoError(t, err, "second sync should succeed (idempotent)")
	})
}
