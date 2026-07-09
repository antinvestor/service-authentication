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

package handlers

import (
	"errors"
	"strings"
)

// ErrIncompleteTenancyPair is returned when tenant_id and partition_id are not
// both present. Token issuance and enrichment treat them as a single unit of
// tenancy context — never emit or accept one without the other.
var ErrIncompleteTenancyPair = errors.New("tenant_id and partition_id must both be set")

// NormalizeTenancyPair trims tenant and partition identifiers.
func NormalizeTenancyPair(tenantID, partitionID string) (string, string) {
	return strings.TrimSpace(tenantID), strings.TrimSpace(partitionID)
}

// ValidTenancyPair reports whether both tenant_id and partition_id are non-empty.
func ValidTenancyPair(tenantID, partitionID string) bool {
	tenantID, partitionID = NormalizeTenancyPair(tenantID, partitionID)
	return tenantID != "" && partitionID != ""
}

// TenancyPairFromClaims extracts tenant_id and partition_id from a claims map.
func TenancyPairFromClaims(claims map[string]any) (tenantID, partitionID string) {
	return claimString(claims, "tenant_id"), claimString(claims, "partition_id")
}

// ClaimsHaveTenancyPair reports whether claims carry a complete tenancy pair.
func ClaimsHaveTenancyPair(claims map[string]any) bool {
	return ValidTenancyPair(TenancyPairFromClaims(claims))
}
