package business

import (
	"testing"

	tenancyv2 "buf.build/gen/go/antinvestor/tenancy/protocolbuffers/go/tenancy/v2"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/models"
	"github.com/pitabwire/frame/v2/data"
	"github.com/stretchr/testify/require"
)

func TestValidateAuthorizationPolicyRequiresExplicitRegisteredPermissions(t *testing.T) {
	t.Parallel()

	namespaces := []*models.ServiceNamespace{{
		Namespace:   "service_profile",
		Permissions: data.JSONMap{"values": []string{"profile_update", "profile_view"}},
	}}

	_, err := validateAuthorizationPolicy(nil, namespaces)
	require.EqualError(t, err, "authorization policy is required")

	grants, err := validateAuthorizationPolicy(&tenancyv2.ServiceAuthorizationPolicyInput{
		SchemaVersion: models.AuthorizationPolicySchemaVersion,
		Grants: []*tenancyv2.ServiceAuthorizationGrant{{
			Namespace:   "service_profile",
			Permissions: []string{"profile_view", "profile_update"},
			Scope:       tenancyv2.AuthorizationScope_AUTHORIZATION_SCOPE_PARTITION_ONLY,
		}},
	}, namespaces)
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
	}, namespaces)
	require.ErrorContains(t, err, "explicit permissions")

	_, err = validateAuthorizationPolicy(&tenancyv2.ServiceAuthorizationPolicyInput{
		SchemaVersion: 1,
		Grants: []*tenancyv2.ServiceAuthorizationGrant{{
			Namespace:   "opportunities_api",
			Permissions: []string{"job_view"},
			Scope:       tenancyv2.AuthorizationScope_AUTHORIZATION_SCOPE_PARTITION_ONLY,
		}},
	}, namespaces)
	require.ErrorContains(t, err, "not registered")
}

func TestValidateResourceRecipientsAllowsUncataloguedPlatformServices(t *testing.T) {
	t.Parallel()

	baseURL, err := normalizeAudienceBaseURL("https://API.example.test/platform/")
	require.NoError(t, err)
	require.Equal(t, "https://api.example.test/platform", baseURL)

	recipients, err := validateResourceRecipients(baseURL, []string{
		" https://api.example.test/platform/new-service ",
		"https://api.example.test/platform/profile",
	})
	require.NoError(t, err)
	require.Equal(t, []string{
		"https://api.example.test/platform/new-service",
		"https://api.example.test/platform/profile",
	}, recipients)
}

func TestValidateResourceRecipientsRejectsUnsafeAudiences(t *testing.T) {
	t.Parallel()

	baseURL, err := normalizeAudienceBaseURL("https://api.example.test/platform")
	require.NoError(t, err)

	tests := []struct {
		name      string
		audiences []string
	}{
		{name: "foreign origin", audiences: []string{"https://other.example.test/platform/profile"}},
		{name: "base itself", audiences: []string{"https://api.example.test/platform"}},
		{name: "sibling prefix", audiences: []string{"https://api.example.test/platform-other/profile"}},
		{name: "path traversal", audiences: []string{"https://api.example.test/platform/../admin"}},
		{name: "encoded path", audiences: []string{"https://api.example.test/platform/new%2Dservice"}},
		{name: "query", audiences: []string{"https://api.example.test/platform/profile?tenant=1"}},
		{name: "duplicate after normalisation", audiences: []string{
			"https://api.example.test/platform/profile",
			" https://api.example.test/platform/profile ",
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, validationErr := validateResourceRecipients(baseURL, test.audiences)
			require.Error(t, validationErr)
		})
	}
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
