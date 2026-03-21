package main

import (
	"context"
	"testing"

	partitionv1 "buf.build/gen/go/antinvestor/partition/protocolbuffers/go/partition/v1"
	"github.com/stretchr/testify/require"
)

func TestRootPartitionIDForEnvironment(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		environment partitionv1.TenantEnvironment
		expectedID  string
	}{
		{
			name:        "production",
			environment: partitionv1.TenantEnvironment_TENANT_ENVIRONMENT_PRODUCTION,
			expectedID:  rootPartitionProductionID,
		},
		{
			name:        "staging",
			environment: partitionv1.TenantEnvironment_TENANT_ENVIRONMENT_STAGING,
			expectedID:  rootPartitionStagingID,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			partitionID, err := rootPartitionIDForEnvironment(tc.environment)
			require.NoError(t, err)
			require.Equal(t, tc.expectedID, partitionID)
		})
	}
}

func TestRootPartitionIDForEnvironmentRejectsUnsupportedValue(t *testing.T) {
	t.Parallel()

	_, err := rootPartitionIDForEnvironment(partitionv1.TenantEnvironment_TENANT_ENVIRONMENT_UNSPECIFIED)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported environment")
}

func TestSeedSuperUserRejectsInvalidArguments(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		email       string
		environment string
		errContains string
	}{
		{
			name:        "invalid_email",
			email:       "not-an-email",
			environment: rootEnvironmentProduction,
			errContains: "invalid email",
		},
		{
			name:        "unsupported_environment",
			email:       "admin@example.com",
			environment: "development",
			errContains: "unsupported environment",
		},
	}

	seeder := &superUserSeeder{}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := seeder.SeedSuperUser(context.Background(), tc.email, tc.environment)
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.errContains)
		})
	}
}
