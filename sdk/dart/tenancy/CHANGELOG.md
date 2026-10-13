## 3.0.0

- Regenerated with protoc_plugin 25.1 / connect-dart 2.0; requires protobuf ^6.1.0, connectrpc ^2.0.0, Dart ^3.7. WKTs now come from package:protobuf.
- Depends on `antinvestor_api_common` ^2.0.0.
- Breaking: the vendored `google.protobuf` well-known types (`Any`, `Duration`, `FieldMask`, `Struct`, `Timestamp`) are gone. The barrel re-exports `Struct` and `Timestamp` from `package:protobuf/well_known_types/`, so every SDK shares one type.
- Version 3.0.0 skips the unpublished `dart/tenancy/v2.0.0` tag; it contains the 2.0.0 changes below.

## 2.0.0

- Add the `tenancy.v2.AuthContractService` client and normalized OAuth/resource authorization models.
- Remove the retired v1 OAuth client and service-account messages and RPC methods.

## 1.54.0

- Add ListServiceNamespaces, GrantPermission, RevokePermission Connect RPCs
- Add ServiceNamespaceObject and RolePermissionList message types

## 1.53.0

- Renamed package from antinvestor_api_partition to antinvestor_api_tenancy
