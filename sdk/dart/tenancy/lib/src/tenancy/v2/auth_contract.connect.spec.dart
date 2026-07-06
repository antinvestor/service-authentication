//
//  Generated code. Do not modify.
//  source: tenancy/v2/auth_contract.proto
//

import "package:connectrpc/connect.dart" as connect;
import "auth_contract.pb.dart" as tenancyv2auth_contract;

abstract final class AuthContractService {
  /// Fully-qualified name of the AuthContractService service.
  static const name = 'tenancy.v2.AuthContractService';

  static const createOAuthClient = connect.Spec(
    '/$name/CreateOAuthClient',
    connect.StreamType.unary,
    tenancyv2auth_contract.CreateOAuthClientRequest.new,
    tenancyv2auth_contract.CreateOAuthClientResponse.new,
  );

  static const getOAuthClient = connect.Spec(
    '/$name/GetOAuthClient',
    connect.StreamType.unary,
    tenancyv2auth_contract.GetOAuthClientRequest.new,
    tenancyv2auth_contract.GetOAuthClientResponse.new,
    idempotency: connect.Idempotency.noSideEffects,
  );

  static const listOAuthClients = connect.Spec(
    '/$name/ListOAuthClients',
    connect.StreamType.unary,
    tenancyv2auth_contract.ListOAuthClientsRequest.new,
    tenancyv2auth_contract.ListOAuthClientsResponse.new,
    idempotency: connect.Idempotency.noSideEffects,
  );

  static const updateOAuthClient = connect.Spec(
    '/$name/UpdateOAuthClient',
    connect.StreamType.unary,
    tenancyv2auth_contract.UpdateOAuthClientRequest.new,
    tenancyv2auth_contract.UpdateOAuthClientResponse.new,
  );

  static const removeOAuthClient = connect.Spec(
    '/$name/RemoveOAuthClient',
    connect.StreamType.unary,
    tenancyv2auth_contract.RemoveOAuthClientRequest.new,
    tenancyv2auth_contract.RemoveOAuthClientResponse.new,
  );

  static const createServiceAccount = connect.Spec(
    '/$name/CreateServiceAccount',
    connect.StreamType.unary,
    tenancyv2auth_contract.CreateServiceAccountRequest.new,
    tenancyv2auth_contract.CreateServiceAccountResponse.new,
  );

  static const getServiceAccount = connect.Spec(
    '/$name/GetServiceAccount',
    connect.StreamType.unary,
    tenancyv2auth_contract.GetServiceAccountRequest.new,
    tenancyv2auth_contract.GetServiceAccountResponse.new,
    idempotency: connect.Idempotency.noSideEffects,
  );

  static const listServiceAccounts = connect.Spec(
    '/$name/ListServiceAccounts',
    connect.StreamType.unary,
    tenancyv2auth_contract.ListServiceAccountsRequest.new,
    tenancyv2auth_contract.ListServiceAccountsResponse.new,
    idempotency: connect.Idempotency.noSideEffects,
  );

  static const updateServiceAccount = connect.Spec(
    '/$name/UpdateServiceAccount',
    connect.StreamType.unary,
    tenancyv2auth_contract.UpdateServiceAccountRequest.new,
    tenancyv2auth_contract.UpdateServiceAccountResponse.new,
  );

  static const removeServiceAccount = connect.Spec(
    '/$name/RemoveServiceAccount',
    connect.StreamType.unary,
    tenancyv2auth_contract.RemoveServiceAccountRequest.new,
    tenancyv2auth_contract.RemoveServiceAccountResponse.new,
  );

  static const reconcileServiceAccountAuthorization = connect.Spec(
    '/$name/ReconcileServiceAccountAuthorization',
    connect.StreamType.unary,
    tenancyv2auth_contract.ReconcileServiceAccountAuthorizationRequest.new,
    tenancyv2auth_contract.ReconcileServiceAccountAuthorizationResponse.new,
  );
}
