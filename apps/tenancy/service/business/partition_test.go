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

package business_test

import (
	"testing"

	"github.com/antinvestor/service-authentication/apps/tenancy/config"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/events"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/models"
	"github.com/antinvestor/service-authentication/apps/tenancy/tests"
	"github.com/pitabwire/frame/data"
	"github.com/pitabwire/frame/frametests/definition"
	"github.com/pitabwire/frame/frametests/deps/testoryhydra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type PartitionBusinessTestSuite struct {
	tests.BaseTestSuite

	hydraContainer definition.TestResource
}

func (p *PartitionBusinessTestSuite) SetupSuite() {
	p.BaseTestSuite.SetupSuite()

	t := p.T()
	ctx := t.Context()

	for _, res := range p.Resources() {
		if res.GetInternalDS(ctx).IsPostgres() {
			p.hydraContainer = testoryhydra.NewWithOpts(
				testoryhydra.HydraConfiguration, definition.WithDependancies(res),
			)

			err := p.hydraContainer.Setup(ctx, p.Network)
			require.NoError(t, err)
		}
	}
}

func (p *PartitionBusinessTestSuite) TearDownSuite() {
	if p.hydraContainer != nil {
		t := p.T()
		ctx := t.Context()
		p.hydraContainer.Cleanup(ctx)
	}

	p.BaseTestSuite.TearDownSuite()
}

func (p *PartitionBusinessTestSuite) TestSyncPartitionOnHydra() {
	// Test cases
	t := p.T()
	dep := definition.NewDependancyOption("partition_test", "partition_sync", nil)
	ctx, svc, deps := p.CreateService(t, dep)

	cfg, ok := svc.Config().(*config.TenancyConfig)
	if ok {
		cfg.Oauth2ServiceAdminURI = p.hydraContainer.GetInternalDS(ctx).String()
	}

	tenantRepo := deps.TenantRepo
	partitionRepo := deps.PartitionRepo

	// Setup
	tenant := models.Tenant{
		Name:        "default",
		Description: "Test",
	}

	err := tenantRepo.Create(ctx, &tenant)
	require.NoError(t, err)

	partition := &models.Partition{
		Name:        "test partition",
		Description: "",
		BaseModel: data.BaseModel{
			TenantID: tenant.GetID(),
		},
	}

	err = partitionRepo.Create(ctx, partition)
	require.NoError(t, err)

	// Execute
	err = events.SyncPartitionOnHydra(ctx, cfg, svc.HTTPClientManager(), partitionRepo, partition)

	// Verify
	assert.NoError(t, err, "Could not sync this partition")
}

// TestPartitionBusiness runs the partition business test suite.
func TestPartitionBusiness(t *testing.T) {
	suite.Run(t, new(PartitionBusinessTestSuite))
}
