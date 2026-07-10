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
	"errors"
	"fmt"
	"strings"

	tenancyv2 "buf.build/gen/go/antinvestor/tenancy/protocolbuffers/go/tenancy/v2"
	"connectrpc.com/connect"
	"github.com/pitabwire/util"
)

func (h *AuthServer) getOAuthClient(ctx context.Context, clientID string) (*tenancyv2.OAuthClient, error) {
	clientID = strings.TrimSpace(clientID)
	if clientID == "" {
		return nil, errors.New("client_id is required")
	}
	if h.authContractCli == nil {
		return nil, errors.New("tenancy auth contract client is unavailable")
	}

	response, err := h.authContractCli.GetOAuthClient(ctx, connect.NewRequest(&tenancyv2.GetOAuthClientRequest{
		Selector: &tenancyv2.GetOAuthClientRequest_ClientId{ClientId: clientID},
	}))
	if err == nil {
		if response.Msg.GetData() == nil {
			return nil, fmt.Errorf("get OAuth client %q: response data is missing", clientID)
		}
		return response.Msg.GetData(), nil
	}

	// When tenancy ReBAC denies service-authentication (common after greenfield
	// keto drift), fall back to a minimal client synthesised from Hydra admin
	// metadata so user OAuth consent can still complete for public SPA clients.
	util.Log(ctx).WithError(err).WithField("client_id", clientID).
		Warn("tenancy GetOAuthClient failed; trying Hydra metadata fallback")
	fallback, fallbackErr := h.oauthClientFromHydraMetadata(ctx, clientID)
	if fallbackErr != nil {
		return nil, fmt.Errorf("get OAuth client %q: %w (hydra fallback: %v)", clientID, err, fallbackErr)
	}
	return fallback, nil
}

// oauthClientFromHydraMetadata builds a partition-owned OAuthClient from Hydra
// client metadata keys tenant_id / partition_id (written by tenancy partition sync).
func (h *AuthServer) oauthClientFromHydraMetadata(ctx context.Context, clientID string) (*tenancyv2.OAuthClient, error) {
	tenantID, partitionID, err := h.tenancyIDsFromHydraClient(ctx, clientID)
	if err != nil {
		return nil, err
	}
	return &tenancyv2.OAuthClient{
		ClientId: clientID,
		Type:     "public",
		Owner:    &tenancyv2.OAuthClient_PartitionId{PartitionId: partitionID},
		// Name is informational only; tenant is carried via login event after enrichment.
		Name: tenantID,
	}, nil
}

// tenancyIDsFromHydraClient reads tenant_id and partition_id from the Hydra
// OAuth2 client's metadata map. Both must be non-empty.
func (h *AuthServer) tenancyIDsFromHydraClient(ctx context.Context, clientID string) (tenantID, partitionID string, err error) {
	clientID = strings.TrimSpace(clientID)
	if clientID == "" {
		return "", "", errors.New("client_id is required")
	}
	if h.defaultHydraCli == nil {
		return "", "", errors.New("hydra admin client is unavailable")
	}
	hydraClient, err := h.defaultHydraCli.GetOAuth2Client(ctx, clientID)
	if err != nil {
		return "", "", err
	}
	metaMap := metadataAsMap(hydraClient.GetMetadata())
	if metaMap == nil {
		return "", "", fmt.Errorf("hydra client %q has no metadata", clientID)
	}
	tenantID = strings.TrimSpace(metaString(metaMap, "tenant_id"))
	partitionID = strings.TrimSpace(metaString(metaMap, "partition_id"))
	if !ValidTenancyPair(tenantID, partitionID) {
		return "", "", fmt.Errorf("hydra client %q metadata missing tenant_id/partition_id", clientID)
	}
	return tenantID, partitionID, nil
}

// metadataAsMap normalises Hydra client metadata (typed as interface{}) into a
// string-keyed map.
func metadataAsMap(meta any) map[string]any {
	if meta == nil {
		return nil
	}
	if m, ok := meta.(map[string]any); ok {
		return m
	}
	return nil
}

func metaString(meta map[string]any, key string) string {
	if meta == nil {
		return ""
	}
	v, ok := meta[key]
	if !ok || v == nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return t
	default:
		return fmt.Sprint(t)
	}
}

func (h *AuthServer) getServiceAccount(ctx context.Context, serviceAccountID string) (*tenancyv2.ServiceAccount, error) {
	serviceAccountID = strings.TrimSpace(serviceAccountID)
	if serviceAccountID == "" {
		return nil, errors.New("service account id is required")
	}
	if h.authContractCli == nil {
		return nil, errors.New("tenancy auth contract client is unavailable")
	}

	response, err := h.authContractCli.GetServiceAccount(ctx, connect.NewRequest(&tenancyv2.GetServiceAccountRequest{
		Selector: &tenancyv2.GetServiceAccountRequest_Id{Id: serviceAccountID},
	}))
	if err != nil {
		return nil, fmt.Errorf("get service account %q: %w", serviceAccountID, err)
	}
	if response.Msg.GetData() == nil {
		return nil, fmt.Errorf("get service account %q: response data is missing", serviceAccountID)
	}
	return response.Msg.GetData(), nil
}
