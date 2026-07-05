//
//  Generated code. Do not modify.
//  source: tenancy/v2/auth_contract.proto
//

import "package:connectrpc/connect.dart" as connect;
import "auth_contract.pb.dart" as tenancyv2auth_contract;
import "auth_contract.connect.spec.dart" as specs;

extension type AuthContractServiceClient(connect.Transport _transport) {
  Future<tenancyv2auth_contract.CreateOAuthClientResponse> createOAuthClient(
    tenancyv2auth_contract.CreateOAuthClientRequest input, {
    connect.Headers? headers,
    connect.AbortSignal? signal,
    Function(connect.Headers)? onHeader,
    Function(connect.Headers)? onTrailer,
  }) {
    return connect.Client(_transport).unary(
      specs.AuthContractService.createOAuthClient,
      input,
      signal: signal,
      headers: headers,
      onHeader: onHeader,
      onTrailer: onTrailer,
    );
  }

  Future<tenancyv2auth_contract.GetOAuthClientResponse> getOAuthClient(
    tenancyv2auth_contract.GetOAuthClientRequest input, {
    connect.Headers? headers,
    connect.AbortSignal? signal,
    Function(connect.Headers)? onHeader,
    Function(connect.Headers)? onTrailer,
  }) {
    return connect.Client(_transport).unary(
      specs.AuthContractService.getOAuthClient,
      input,
      signal: signal,
      headers: headers,
      onHeader: onHeader,
      onTrailer: onTrailer,
    );
  }

  Future<tenancyv2auth_contract.ListOAuthClientsResponse> listOAuthClients(
    tenancyv2auth_contract.ListOAuthClientsRequest input, {
    connect.Headers? headers,
    connect.AbortSignal? signal,
    Function(connect.Headers)? onHeader,
    Function(connect.Headers)? onTrailer,
  }) {
    return connect.Client(_transport).unary(
      specs.AuthContractService.listOAuthClients,
      input,
      signal: signal,
      headers: headers,
      onHeader: onHeader,
      onTrailer: onTrailer,
    );
  }

  Future<tenancyv2auth_contract.UpdateOAuthClientResponse> updateOAuthClient(
    tenancyv2auth_contract.UpdateOAuthClientRequest input, {
    connect.Headers? headers,
    connect.AbortSignal? signal,
    Function(connect.Headers)? onHeader,
    Function(connect.Headers)? onTrailer,
  }) {
    return connect.Client(_transport).unary(
      specs.AuthContractService.updateOAuthClient,
      input,
      signal: signal,
      headers: headers,
      onHeader: onHeader,
      onTrailer: onTrailer,
    );
  }

  Future<tenancyv2auth_contract.RemoveOAuthClientResponse> removeOAuthClient(
    tenancyv2auth_contract.RemoveOAuthClientRequest input, {
    connect.Headers? headers,
    connect.AbortSignal? signal,
    Function(connect.Headers)? onHeader,
    Function(connect.Headers)? onTrailer,
  }) {
    return connect.Client(_transport).unary(
      specs.AuthContractService.removeOAuthClient,
      input,
      signal: signal,
      headers: headers,
      onHeader: onHeader,
      onTrailer: onTrailer,
    );
  }

  Future<tenancyv2auth_contract.CreateServiceAccountResponse>
      createServiceAccount(
    tenancyv2auth_contract.CreateServiceAccountRequest input, {
    connect.Headers? headers,
    connect.AbortSignal? signal,
    Function(connect.Headers)? onHeader,
    Function(connect.Headers)? onTrailer,
  }) {
    return connect.Client(_transport).unary(
      specs.AuthContractService.createServiceAccount,
      input,
      signal: signal,
      headers: headers,
      onHeader: onHeader,
      onTrailer: onTrailer,
    );
  }

  Future<tenancyv2auth_contract.GetServiceAccountResponse> getServiceAccount(
    tenancyv2auth_contract.GetServiceAccountRequest input, {
    connect.Headers? headers,
    connect.AbortSignal? signal,
    Function(connect.Headers)? onHeader,
    Function(connect.Headers)? onTrailer,
  }) {
    return connect.Client(_transport).unary(
      specs.AuthContractService.getServiceAccount,
      input,
      signal: signal,
      headers: headers,
      onHeader: onHeader,
      onTrailer: onTrailer,
    );
  }

  Future<tenancyv2auth_contract.ListServiceAccountsResponse>
      listServiceAccounts(
    tenancyv2auth_contract.ListServiceAccountsRequest input, {
    connect.Headers? headers,
    connect.AbortSignal? signal,
    Function(connect.Headers)? onHeader,
    Function(connect.Headers)? onTrailer,
  }) {
    return connect.Client(_transport).unary(
      specs.AuthContractService.listServiceAccounts,
      input,
      signal: signal,
      headers: headers,
      onHeader: onHeader,
      onTrailer: onTrailer,
    );
  }

  Future<tenancyv2auth_contract.UpdateServiceAccountResponse>
      updateServiceAccount(
    tenancyv2auth_contract.UpdateServiceAccountRequest input, {
    connect.Headers? headers,
    connect.AbortSignal? signal,
    Function(connect.Headers)? onHeader,
    Function(connect.Headers)? onTrailer,
  }) {
    return connect.Client(_transport).unary(
      specs.AuthContractService.updateServiceAccount,
      input,
      signal: signal,
      headers: headers,
      onHeader: onHeader,
      onTrailer: onTrailer,
    );
  }

  Future<tenancyv2auth_contract.RemoveServiceAccountResponse>
      removeServiceAccount(
    tenancyv2auth_contract.RemoveServiceAccountRequest input, {
    connect.Headers? headers,
    connect.AbortSignal? signal,
    Function(connect.Headers)? onHeader,
    Function(connect.Headers)? onTrailer,
  }) {
    return connect.Client(_transport).unary(
      specs.AuthContractService.removeServiceAccount,
      input,
      signal: signal,
      headers: headers,
      onHeader: onHeader,
      onTrailer: onTrailer,
    );
  }

  Future<tenancyv2auth_contract.ReconcileServiceAccountAuthorizationResponse>
      reconcileServiceAccountAuthorization(
    tenancyv2auth_contract.ReconcileServiceAccountAuthorizationRequest input, {
    connect.Headers? headers,
    connect.AbortSignal? signal,
    Function(connect.Headers)? onHeader,
    Function(connect.Headers)? onTrailer,
  }) {
    return connect.Client(_transport).unary(
      specs.AuthContractService.reconcileServiceAccountAuthorization,
      input,
      signal: signal,
      headers: headers,
      onHeader: onHeader,
      onTrailer: onTrailer,
    );
  }
}
