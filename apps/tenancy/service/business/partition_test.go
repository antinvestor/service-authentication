package business_test

import (
	"github.com/antinvestor/service-authentication/apps/tenancy/config"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/business"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/models"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/repository"
	"github.com/antinvestor/service-authentication/apps/tenancy/tests"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/pitabwire/frame"
	"github.com/pitabwire/frame/tests/deps/testoryhydra"
	"github.com/pitabwire/frame/tests/testdef"
)

type PartitionBusinessTestSuite struct {
	tests.BaseTestSuite

	hydraContainer testdef.TestResource
}

func (p *PartitionBusinessTestSuite) SetupSuite() {
	p.BaseTestSuite.SetupSuite()

	for _, res := range p.Resources() {
		if res.GetInternalDS().IsPostgres() {
			p.hydraContainer = testoryhydra.NewWithCred(
				testoryhydra.OryHydraImage,
				testoryhydra.HydraConfiguration,
				res.GetInternalDS().String(),
			)

			t := p.T()
			ctx := t.Context()
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
	testCases := []struct {
		name        string
		shouldError bool
	}{
		{
			name:        "Sync partition on Hydra",
			shouldError: false,
		},
	}

	p.WithTestDependancies(p.T(), func(t *testing.T, dep *testdef.DependancyOption) {
		svc, ctx := p.CreateService(t, dep)

		cfg, ok := svc.Config().(*config.PartitionConfig)
		if ok {
			cfg.Oauth2ServiceAdminURI = p.hydraContainer.GetInternalDS().String()
		}

		tenantRepo := repository.NewTenantRepository(svc)
		partitionRepo := repository.NewPartitionRepository(svc)

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				// Setup
				tenant := models.Tenant{
					Name:        "default",
					Description: "Test",
				}

				err := tenantRepo.Save(ctx, &tenant)
				require.NoError(t, err)

				partition := &models.Partition{
					Name:        "test partition",
					Description: "",
					BaseModel: frame.BaseModel{
						TenantID: tenant.GetID(),
					},
				}

				err = partitionRepo.Save(ctx, partition)
				require.NoError(t, err)

				// Execute
				err = business.SyncPartitionOnHydra(ctx, svc, partition)

				// Verify
				if tc.shouldError {
					assert.Error(t, err)
				} else {
					assert.NoError(t, err, "Could not sync this partition")
				}
			})
		}
	})
}

// TestPartitionBusiness runs the partition business test suite.
func TestPartitionBusiness(t *testing.T) {
	suite.Run(t, new(PartitionBusinessTestSuite))
}
