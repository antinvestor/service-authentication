package business_test

import (
	"testing"

	"github.com/antinvestor/service-authentication/apps/tenancy/config"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/events"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/models"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/repository"
	"github.com/antinvestor/service-authentication/apps/tenancy/tests"
	"github.com/pitabwire/frame"
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
	testCases := []struct {
		name        string
		shouldError bool
	}{
		{
			name:        "Sync partition on Hydra",
			shouldError: false,
		},
	}

	p.WithTestDependancies(p.T(), func(t *testing.T, dep *definition.DependancyOption) {
		svc, ctx := p.CreateService(t, dep)

		cfg, ok := svc.Config().(*config.PartitionConfig)
		if ok {
			cfg.Oauth2ServiceAdminURI = p.hydraContainer.GetInternalDS(ctx).String()
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
				err = events.SyncPartitionOnHydra(ctx, svc, partition)

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
