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

package main

import (
	"context"
	"testing"

	tenancyv1 "buf.build/gen/go/antinvestor/tenancy/protocolbuffers/go/tenancy/v1"
	"github.com/stretchr/testify/require"
)

func TestRootPartitionIDForEnvironment(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		environment tenancyv1.TenantEnvironment
		expectedID  string
	}{
		{
			name:        "production",
			environment: tenancyv1.TenantEnvironment_TENANT_ENVIRONMENT_PRODUCTION,
			expectedID:  rootPartitionProductionID,
		},
		{
			name:        "staging",
			environment: tenancyv1.TenantEnvironment_TENANT_ENVIRONMENT_STAGING,
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

	_, err := rootPartitionIDForEnvironment(tenancyv1.TenantEnvironment_TENANT_ENVIRONMENT_UNSPECIFIED)
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
