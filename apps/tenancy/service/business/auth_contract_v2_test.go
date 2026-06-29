package business

import (
	"testing"

	tenancyv2 "buf.build/gen/go/antinvestor/tenancy/protocolbuffers/go/tenancy/v2"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/models"
	"github.com/stretchr/testify/require"
)

func TestValidateAuthorizationPolicyRequiresExplicitCataloguedPermissions(t *testing.T) {
	t.Parallel()

	_, err := validateAuthorizationPolicy(nil)
	require.EqualError(t, err, "authorization policy is required")

	grants, err := validateAuthorizationPolicy(&tenancyv2.ServiceAuthorizationPolicyInput{
		SchemaVersion: models.AuthorizationPolicySchemaVersion,
		Grants: []*tenancyv2.ServiceAuthorizationGrant{{
			Namespace:   "service_profile",
			Permissions: []string{"profile_view", "profile_update"},
			Scope:       tenancyv2.AuthorizationScope_AUTHORIZATION_SCOPE_PARTITION_ONLY,
		}},
	})
	require.NoError(t, err)
	require.Len(t, grants, 1)
	require.Equal(t, models.AuthorizationScopePartitionOnly, grants[0].Scope)
	require.Equal(t, []string{"profile_update", "profile_view"}, grants[0].Permissions)

	_, err = validateAuthorizationPolicy(&tenancyv2.ServiceAuthorizationPolicyInput{
		SchemaVersion: 1,
		Grants: []*tenancyv2.ServiceAuthorizationGrant{{
			Namespace:   "service_profile",
			Permissions: []string{"*"},
			Scope:       tenancyv2.AuthorizationScope_AUTHORIZATION_SCOPE_PARTITION_ONLY,
		}},
	})
	require.ErrorContains(t, err, "explicit permissions")

	_, err = validateAuthorizationPolicy(&tenancyv2.ServiceAuthorizationPolicyInput{
		SchemaVersion: 1,
		Grants: []*tenancyv2.ServiceAuthorizationGrant{{
			Namespace:   "opportunities_api",
			Permissions: []string{"job_view"},
			Scope:       tenancyv2.AuthorizationScope_AUTHORIZATION_SCOPE_PARTITION_ONLY,
		}},
	})
	require.ErrorContains(t, err, "not registered")
}

func TestValidateOAuthClientConfigurationRejectsUnsupportedGrant(t *testing.T) {
	t.Parallel()

	_, _, _, _, err := validateOAuthClientConfiguration(&tenancyv2.OAuthClientConfiguration{
		GrantTypes: []string{"password"},
	}, "confidential")
	require.ErrorContains(t, err, "unsupported OAuth grant type")

	grantTypes, responseTypes, _, scopes, err := validateOAuthClientConfiguration(
		&tenancyv2.OAuthClientConfiguration{},
		"internal",
	)
	require.NoError(t, err)
	require.Equal(t, []string{"client_credentials"}, grantTypes)
	require.Empty(t, responseTypes)
	require.Equal(t, "internal openid", scopes)
}
