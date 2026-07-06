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
	if err != nil {
		return nil, fmt.Errorf("get OAuth client %q: %w", clientID, err)
	}
	if response.Msg.GetData() == nil {
		return nil, fmt.Errorf("get OAuth client %q: response data is missing", clientID)
	}
	return response.Msg.GetData(), nil
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
