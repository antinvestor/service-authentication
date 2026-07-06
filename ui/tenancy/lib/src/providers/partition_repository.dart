import 'package:antinvestor_api_tenancy/antinvestor_api_tenancy.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import 'tenancy_transport_provider.dart';

/// Repository wrapping [TenancyServiceClient] with error handling
/// and stream-to-list conversion for all partition service entities,
/// including permission namespace management via Connect RPC.
class PartitionRepository {
  PartitionRepository({
    required TenancyServiceClient client,
    required AuthContractServiceClient authContractClient,
  }) : _client = client,
       _authContractClient = authContractClient;

  final TenancyServiceClient _client;
  final AuthContractServiceClient _authContractClient;

  /// Collect items from a streaming list RPC where each chunk has a repeated field.
  Future<List<T>> _collectStream<T>(
    Stream<dynamic> stream,
    List<T> Function(dynamic response) getData,
  ) async {
    final items = <T>[];
    await for (final response in stream) {
      items.addAll(getData(response));
    }
    return items;
  }

  // -- Tenants --

  Future<List<TenantObject>> listTenants({String query = ''}) => _collectStream(
    _client.listTenant(ListTenantRequest(query: query)),
    (r) => (r as ListTenantResponse).data,
  );

  Future<TenantObject> getTenant(String id) async =>
      (await _client.getTenant(GetTenantRequest(id: id))).data;

  Future<TenantObject> createTenant({
    required String name,
    String description = '',
    TenantEnvironment? environment,
    Struct? properties,
  }) async => (await _client.createTenant(
    CreateTenantRequest(
      name: name,
      description: description,
      environment: environment,
      properties: properties,
    ),
  )).data;

  Future<TenantObject> updateTenant({
    required String id,
    String? name,
    String? description,
    STATE? state,
    TenantEnvironment? environment,
    Struct? properties,
  }) async => (await _client.updateTenant(
    UpdateTenantRequest(
      id: id,
      name: name,
      description: description,
      state: state,
      environment: environment,
      properties: properties,
    ),
  )).data;

  // -- Partitions --

  Future<List<PartitionObject>> listPartitions({String query = ''}) =>
      _collectStream(
        _client.listPartition(ListPartitionRequest(query: query)),
        (r) => (r as ListPartitionResponse).data,
      );

  Future<PartitionObject> getPartition(String id) async =>
      (await _client.getPartition(GetPartitionRequest(id: id))).data;

  Future<GetPartitionParentsResponse> getPartitionParents(String id) async =>
      _client.getPartitionParents(GetPartitionParentsRequest(id: id));

  Future<PartitionObject> createPartition({
    required String tenantId,
    required String name,
    String? parentId,
    String description = '',
    String? domain,
    Struct? properties,
  }) async => (await _client.createPartition(
    CreatePartitionRequest(
      tenantId: tenantId,
      name: name,
      parentId: parentId,
      description: description,
      domain: domain,
      properties: properties,
    ),
  )).data;

  Future<PartitionObject> updatePartition({
    required String id,
    String? name,
    String? description,
    String? domain,
    STATE? state,
    Struct? properties,
  }) async => (await _client.updatePartition(
    UpdatePartitionRequest(
      id: id,
      name: name,
      description: description,
      domain: domain,
      state: state,
      properties: properties,
    ),
  )).data;

  // -- Partition Roles --

  Future<List<PartitionRoleObject>> listPartitionRoles({String? partitionId}) =>
      _collectStream(
        _client.listPartitionRole(
          ListPartitionRoleRequest(partitionId: partitionId),
        ),
        (r) => (r as ListPartitionRoleResponse).data,
      );

  Future<PartitionRoleObject> createPartitionRole({
    required String partitionId,
    required String name,
    Struct? properties,
  }) async => (await _client.createPartitionRole(
    CreatePartitionRoleRequest(
      partitionId: partitionId,
      name: name,
      properties: properties,
    ),
  )).data;

  Future<void> removePartitionRole(String id) async =>
      _client.removePartitionRole(RemovePartitionRoleRequest(id: id));

  // -- Pages --

  Future<List<PageObject>> listPages({String? partitionId}) => _collectStream(
    _client.listPage(ListPageRequest(partitionId: partitionId)),
    (r) => (r as ListPageResponse).data,
  );

  Future<PageObject> getPage(String pageId) async =>
      (await _client.getPage(GetPageRequest(pageId: pageId))).data;

  Future<PageObject> createPage({
    required String partitionId,
    required String name,
    String html = '',
  }) async => (await _client.createPage(
    CreatePageRequest(partitionId: partitionId, name: name, html: html),
  )).data;

  Future<void> removePage(String id) async =>
      _client.removePage(RemovePageRequest(id: id));

  // -- Access --

  Future<List<AccessObject>> listAccess({
    String? partitionId,
    String? profileId,
  }) => _collectStream(
    _client.listAccess(
      ListAccessRequest(partitionId: partitionId, profileId: profileId),
    ),
    (r) => (r as ListAccessResponse).data,
  );

  Future<AccessObject> getAccess({
    required String accessId,
    String? profileId,
  }) async => (await _client.getAccess(
    GetAccessRequest(accessId: accessId, profileId: profileId),
  )).data;

  Future<AccessObject> createAccess({
    required String partitionId,
    required String profileId,
  }) async => (await _client.createAccess(
    CreateAccessRequest(partitionId: partitionId, profileId: profileId),
  )).data;

  Future<void> removeAccess(String id) async =>
      _client.removeAccess(RemoveAccessRequest(id: id));

  // -- Access Roles --

  Future<List<AccessRoleObject>> listAccessRoles({String? accessId}) =>
      _collectStream(
        _client.listAccessRole(ListAccessRoleRequest(accessId: accessId)),
        (r) => (r as ListAccessRoleResponse).data,
      );

  Future<AccessRoleObject> createAccessRole({
    required String accessId,
    required String partitionRoleId,
  }) async => (await _client.createAccessRole(
    CreateAccessRoleRequest(
      accessId: accessId,
      partitionRoleId: partitionRoleId,
    ),
  )).data;

  Future<void> removeAccessRole(String id) async =>
      _client.removeAccessRole(RemoveAccessRoleRequest(id: id));

  // -- Service Accounts --

  Future<List<ServiceAccount>> listServiceAccounts({
    String? partitionId,
  }) async => (await _authContractClient.listServiceAccounts(
    ListServiceAccountsRequest(partitionId: partitionId),
  )).data;

  Future<ServiceAccount> createServiceAccount({
    required String partitionId,
    required String profileId,
    required String name,
    required List<String> resourceRecipients,
    required String authorizationNamespace,
    required List<String> permissions,
    required AuthorizationScope scope,
    String type = 'internal',
  }) async => (await _authContractClient.createServiceAccount(
    CreateServiceAccountRequest(
      partitionId: partitionId,
      profileId: profileId,
      name: name,
      type: type,
      oauthClient: OAuthClientConfiguration(
        grantTypes: const ['client_credentials'],
        scopes: 'system_int openid',
        resourceRecipients: resourceRecipients,
        tokenEndpointAuthMethod: 'private_key_jwt',
      ),
      authorizationPolicy: ServiceAuthorizationPolicyInput(
        schemaVersion: 1,
        grants: [
          ServiceAuthorizationGrant(
            namespace: authorizationNamespace,
            permissions: permissions,
            scope: scope,
          ),
        ],
      ),
    ),
  )).data;

  Future<void> removeServiceAccount(String id) async => _authContractClient
      .removeServiceAccount(RemoveServiceAccountRequest(id: id));

  // -- Clients --

  Future<List<OAuthClient>> listClients({String? partitionId}) async =>
      (await _authContractClient.listOAuthClients(
        ListOAuthClientsRequest(partitionId: partitionId),
      )).data;

  Future<OAuthClient> createClient({
    required String name,
    required String partitionId,
    String type = 'public',
    String scopes = 'openid',
    List<String> grantTypes = const [],
    List<String> responseTypes = const [],
    List<String> redirectUris = const [],
    List<String> resourceRecipients = const [],
  }) async => (await _authContractClient.createOAuthClient(
    CreateOAuthClientRequest(
      name: name,
      partitionId: partitionId,
      type: type,
      configuration: OAuthClientConfiguration(
        scopes: scopes,
        grantTypes: grantTypes,
        responseTypes: responseTypes,
        redirectUris: redirectUris,
        resourceRecipients: resourceRecipients,
        tokenEndpointAuthMethod: type == 'public'
            ? 'none'
            : 'client_secret_post',
      ),
    ),
  )).data;

  Future<void> removeClient(String id) async =>
      _authContractClient.removeOAuthClient(RemoveOAuthClientRequest(id: id));

  // -- Permissions --

  /// List all registered service namespaces with their permissions and role bindings.
  Future<List<ServiceNamespaceObject>> listServiceNamespaces() async =>
      (await _client.listServiceNamespaces(
        ListServiceNamespacesRequest(),
      )).data;

  /// Grant a specific permission to a profile within a service namespace.
  Future<void> grantPermission({
    required String namespace,
    required String permission,
    required String profileId,
  }) async => _client.grantPermission(
    GrantPermissionRequest(
      namespace: namespace,
      permission: permission,
      profileId: profileId,
    ),
  );

  /// Revoke a specific permission from a profile within a service namespace.
  Future<void> revokePermission({
    required String namespace,
    required String permission,
    required String profileId,
  }) async => _client.revokePermission(
    RevokePermissionRequest(
      namespace: namespace,
      permission: permission,
      profileId: profileId,
    ),
  );
}

// --- Riverpod Provider ---

final partitionRepositoryProvider = Provider<PartitionRepository>((ref) {
  final client = ref.watch(tenancyServiceClientProvider);
  final authContractClient = ref.watch(authContractServiceClientProvider);
  return PartitionRepository(
    client: client,
    authContractClient: authContractClient,
  );
});
