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
	"context"
	"encoding/json"
	"net/http"

	"github.com/antinvestor/service-authentication/apps/default/service/fedcm"
)

// BuildClientMetadataResponse renders the JSON object returned by
// GET /fedcm/client_metadata for a resolved Branding.
func BuildClientMetadataResponse(b fedcm.Branding) map[string]any {
	return map[string]any{
		"privacy_policy_url":   b.PrivacyPolicyURL,
		"terms_of_service_url": b.TermsOfServiceURL,
		"icon_url":             b.IconURL,
		"background_colour":    b.BackgroundColor,
	}
}

// FedCMClientMetadataEndpoint serves GET /fedcm/client_metadata?client_id=...
func (h *AuthServer) FedCMClientMetadataEndpoint(w http.ResponseWriter, r *http.Request) error {
	if r.Header.Get("Sec-Fetch-Dest") != "webidentity" {
		w.WriteHeader(http.StatusBadRequest)
		return nil
	}

	clientID := r.URL.Query().Get("client_id")
	if clientID == "" {
		return writeFedCMError(w, http.StatusBadRequest, "invalid_request")
	}

	partitionProps, err := h.loadClientProperties(r.Context(), clientID)
	if err != nil {
		return writeFedCMError(w, http.StatusNotFound, "invalid_request")
	}

	b := fedcm.ResolveBranding(partitionProps, nil, fedcm.BrandingDefaults{
		PrivacyPolicyURL:  h.config.FedCMDefaultPrivacyURL,
		TermsOfServiceURL: h.config.FedCMDefaultToSURL,
		IconURL:           h.config.FedCMDefaultIconURL,
		BackgroundColor:   h.config.FedCMDefaultBgColor,
	})

	w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	return json.NewEncoder(w).Encode(BuildClientMetadataResponse(b))
}

// loadClientProperties returns the partition Properties map for clientID.
// Tenant properties are not fetched (would require an additional gRPC call); the
// branding resolver falls through to defaults for any missing values.
func (h *AuthServer) loadClientProperties(ctx context.Context, clientID string) (map[string]string, error) {
	partition, err := h.resolvePartitionByClientID(ctx, clientID)
	if err != nil {
		return nil, err
	}
	if partition.GetProperties() == nil {
		return map[string]string{}, nil
	}
	return anyMapToStringMap(partition.GetProperties().AsMap()), nil
}

// anyMapToStringMap converts a map[string]any to map[string]string by
// taking only the string-typed values and discarding the rest.
func anyMapToStringMap(m map[string]any) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		if s, ok := v.(string); ok {
			out[k] = s
		}
	}
	return out
}

// writeFedCMError writes a FedCM-conformant JSON error body.
func writeFedCMError(w http.ResponseWriter, status int, code string) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(map[string]string{"error": code})
}
