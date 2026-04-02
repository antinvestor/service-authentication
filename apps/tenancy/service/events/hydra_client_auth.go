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

package events

import (
	"strings"

	"github.com/antinvestor/common"
	"github.com/pitabwire/frame/data"
)

// DefaultHydraPublicJWKSURI is the internal JWKS endpoint for Hydra's public keys.
// Internal service accounts use this for private_key_jwt authentication —
// they sign assertions with a shared key from Hydra's JWK set and Hydra
// verifies against its own published JWKS.
const DefaultHydraPublicJWKSURI = "http://service-authentication-oauth2-hydra-public.auth.svc.cluster.local:4444/.well-known/jwks.json"

func applyHydraClientAuthPayload(
	payload map[string]any,
	explicitMethod string,
	clientSecret string,
	properties data.JSONMap,
	publicKeys data.JSONMap,
	isInternalSA bool,
) {
	method := strings.TrimSpace(explicitMethod)
	if method == "" {
		method = defaultHydraClientAuthMethod(clientSecret, properties, publicKeys, isInternalSA)
	}

	if method == "" {
		return
	}

	payload["token_endpoint_auth_method"] = method

	switch method {
	case common.TokenEndpointAuthMethodPrivateKeyJWT:
		applyHydraPrivateKeyJWTPayload(payload, properties, publicKeys, isInternalSA)
	case common.TokenEndpointAuthMethodClientSecretPost, common.TokenEndpointAuthMethodClientSecretBasic:
		if strings.TrimSpace(clientSecret) != "" {
			payload["client_secret"] = clientSecret
		}
	}
}

func defaultHydraClientAuthMethod(
	clientSecret string,
	properties data.JSONMap,
	publicKeys data.JSONMap,
	isInternalSA bool,
) string {
	// Explicit JWKS config in properties takes priority
	if hasHydraPrivateJWTConfig(properties, publicKeys) {
		return common.TokenEndpointAuthMethodPrivateKeyJWT
	}
	if strings.TrimSpace(clientSecret) != "" {
		return common.TokenEndpointAuthMethodClientSecretPost
	}
	// Internal SAs always use private_key_jwt with the default Hydra JWKS
	if isInternalSA {
		return common.TokenEndpointAuthMethodPrivateKeyJWT
	}

	return "none"
}

func hasHydraPrivateJWTConfig(properties data.JSONMap, publicKeys data.JSONMap) bool {
	if properties != nil {
		if jwksURI := strings.TrimSpace(properties.GetString("jwks_uri")); jwksURI != "" {
			return true
		}
		if raw, ok := properties["jwks"]; ok && raw != nil {
			return true
		}
	}

	return len(publicKeys) > 0
}

func applyHydraPrivateKeyJWTPayload(payload map[string]any, properties data.JSONMap, publicKeys data.JSONMap, isInternalSA bool) {
	if payload == nil {
		return
	}

	// Check for explicit jwks_uri in properties
	if jwksURI := strings.TrimSpace(properties.GetString("jwks_uri")); jwksURI != "" {
		payload["jwks_uri"] = jwksURI
	} else if isInternalSA {
		// Internal SAs default to Hydra's public JWKS endpoint
		payload["jwks_uri"] = DefaultHydraPublicJWKSURI
	}

	if signingAlg := strings.TrimSpace(properties.GetString("token_endpoint_auth_signing_alg")); signingAlg != "" {
		payload["token_endpoint_auth_signing_alg"] = signingAlg
	}
	if raw, ok := properties["jwks"]; ok && raw != nil {
		payload["jwks"] = raw
		return
	}
	if len(publicKeys) > 0 {
		payload["jwks"] = publicKeys
	}
}
