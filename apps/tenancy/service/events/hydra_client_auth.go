package events

import (
	"strings"

	"github.com/antinvestor/apis/go/common"
	"github.com/pitabwire/frame/data"
)

func applyHydraClientAuthPayload(
	payload map[string]any,
	explicitMethod string,
	clientSecret string,
	properties data.JSONMap,
	publicKeys data.JSONMap,
	defaultToNone bool,
) {
	method := strings.TrimSpace(explicitMethod)
	if method == "" {
		method = defaultHydraClientAuthMethod(clientSecret, properties, publicKeys, defaultToNone)
	}

	if method == "" {
		return
	}

	payload["token_endpoint_auth_method"] = method

	switch method {
	case common.TokenEndpointAuthMethodPrivateKeyJWT:
		applyHydraPrivateKeyJWTPayload(payload, properties, publicKeys)
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
	defaultToNone bool,
) string {
	if hasHydraPrivateJWTConfig(properties, publicKeys) {
		return common.TokenEndpointAuthMethodPrivateKeyJWT
	}
	if strings.TrimSpace(clientSecret) != "" {
		return common.TokenEndpointAuthMethodClientSecretPost
	}
	if defaultToNone {
		return "none"
	}

	return ""
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

func applyHydraPrivateKeyJWTPayload(payload map[string]any, properties data.JSONMap, publicKeys data.JSONMap) {
	if payload == nil {
		return
	}

	if jwksURI := strings.TrimSpace(properties.GetString("jwks_uri")); jwksURI != "" {
		payload["jwks_uri"] = jwksURI
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
