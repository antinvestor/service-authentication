import 'package:antinvestor_api_tenancy/antinvestor_api_tenancy.dart';
import 'package:test/test.dart';

void main() {
  test('exports the normalized v2 authentication contract', () {
    final request = CreateServiceAccountRequest(
      partitionId: 'partition-1',
      profileId: 'profile-1',
      name: 'service-account',
      type: 'internal',
      oauthClient: OAuthClientConfiguration(
        grantTypes: ['client_credentials'],
        scopes: 'system_int openid',
        resourceRecipients: ['https://api.stawi.org/profile'],
        tokenEndpointAuthMethod: 'private_key_jwt',
      ),
      authorizationPolicy: ServiceAuthorizationPolicyInput(
        schemaVersion: 1,
        grants: [
          ServiceAuthorizationGrant(
            namespace: 'service_profile',
            permissions: ['profile_view'],
            scope: AuthorizationScope.AUTHORIZATION_SCOPE_PARTITION_ONLY,
          ),
        ],
      ),
    );

    expect(request.oauthClient.resourceRecipients, [
      'https://api.stawi.org/profile',
    ]);
    expect(
        request.authorizationPolicy.grants.single.namespace, 'service_profile');
  });
}
