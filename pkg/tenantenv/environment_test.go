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

package tenantenv_test

import (
	"testing"

	tenancyv1 "buf.build/gen/go/antinvestor/tenancy/protocolbuffers/go/tenancy/v1"
	"github.com/antinvestor/service-authentication/pkg/tenantenv"
	"github.com/stretchr/testify/require"
)

func TestNormaliseAndIsValid(t *testing.T) {
	t.Parallel()

	require.Equal(t, tenantenv.Production, tenantenv.Normalise(" Production "))
	require.True(t, tenantenv.IsValid("staging"))
	require.True(t, tenantenv.IsValid("PRODUCTION"))
	require.False(t, tenantenv.IsValid("dev"))
	require.False(t, tenantenv.IsValid(""))
}

func TestProtoRoundTrip(t *testing.T) {
	t.Parallel()

	require.Equal(t, tenantenv.Production, tenantenv.FromProto(tenancyv1.TenantEnvironment_TENANT_ENVIRONMENT_PRODUCTION))
	require.Equal(t, tenantenv.Staging, tenantenv.FromProto(tenancyv1.TenantEnvironment_TENANT_ENVIRONMENT_STAGING))
	require.Empty(t, tenantenv.FromProto(tenancyv1.TenantEnvironment_TENANT_ENVIRONMENT_UNSPECIFIED))

	require.Equal(t, tenancyv1.TenantEnvironment_TENANT_ENVIRONMENT_PRODUCTION, tenantenv.ToProto("production"))
	require.Equal(t, tenancyv1.TenantEnvironment_TENANT_ENVIRONMENT_STAGING, tenantenv.ToProto("staging"))
	require.Equal(t, tenancyv1.TenantEnvironment_TENANT_ENVIRONMENT_UNSPECIFIED, tenantenv.ToProto("other"))
}

func TestParseToProto(t *testing.T) {
	t.Parallel()

	got, err := tenantenv.ParseToProto("production")
	require.NoError(t, err)
	require.Equal(t, tenancyv1.TenantEnvironment_TENANT_ENVIRONMENT_PRODUCTION, got)

	_, err = tenantenv.ParseToProto("qa")
	require.Error(t, err)
}
