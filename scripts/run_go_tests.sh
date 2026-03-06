#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

GO_TEST_ARGS=("$@")
HANDLERS_PKG="./apps/tenancy/service/handlers"

mapfile -t PACKAGES < <(
  go list ./... | grep -v '^github.com/antinvestor/service-authentication/apps/tenancy/service/handlers$'
)

for pkg in "${PACKAGES[@]}"; do
  go test "${GO_TEST_ARGS[@]}" "$pkg"
done

go test "${GO_TEST_ARGS[@]}" "$HANDLERS_PKG" -run '^TestSyncPartitionsTestSuite$'
sleep 2

HANDLER_BATCHES=(
  '^(TestGetTenant_Success|TestGetTenant_NotFound|TestGetTenant_NoAuthz|TestCreateTenant_Success|TestCreateTenant_NoAuthz|TestUpdateTenant_Success|TestUpdateTenant_NotFound|TestListTenant_Success|TestCreatePartition_Success|TestCreatePartition_NoAuthz)$'
  '^(TestGetPartition_Success|TestGetPartition_NotFound|TestListPartition_Success|TestUpdatePartition_Success|TestGetPartitionParents_Success|TestCreatePartitionRole_Success|TestCreatePartitionRole_NoAuthz|TestListPartitionRoles_Success|TestRemovePartitionRole_Success|TestRemovePartitionRole_NotFound)$'
  '^(TestCreateAccess_Success|TestCreateAccess_Idempotent|TestCreateAccess_NoAuthz|TestGetAccess_ByAccessId|TestGetAccess_ByPartitionAndProfile|TestGetAccess_NotFound|TestRemoveAccess_Success|TestCreateAccessRole_Success|TestListAccessRoles_Success|TestRemoveAccessRole_Success|TestRemoveAccessRole_NotFound)$'
  '^(TestCreatePage_Success|TestCreatePage_NoAuthz|TestGetPage_Success|TestGetPage_NotFound|TestRemovePage_Success|TestRemovePage_NotFound)$'
  '^(TestCreateServiceAccount_Success|TestCreateServiceAccount_InvalidPartition|TestCreateServiceAccount_NoAuthz|TestGetServiceAccount_ByID|TestGetServiceAccount_ByClientAndProfile|TestGetServiceAccount_NotFound|TestGetServiceAccount_NoAuthz|TestRemoveServiceAccount_Success|TestRemoveServiceAccount_NotFound|TestRemoveServiceAccount_NoAuthz)$'
  '^(TestCreateClient_NoAuthz|TestGetClient_NoAuthz|TestUpdateClient_NoAuthz|TestRemoveClient_NoAuthz)$'
)

for batch in "${HANDLER_BATCHES[@]}"; do
  go test "${GO_TEST_ARGS[@]}" "$HANDLERS_PKG" -run '^TestHandlerTestSuite$' -testify.m "$batch"
  sleep 2
done
