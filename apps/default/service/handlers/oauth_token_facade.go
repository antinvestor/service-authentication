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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	profilev1 "buf.build/gen/go/antinvestor/profile/protocolbuffers/go/profile/v1"
	"connectrpc.com/connect"
	"github.com/antinvestor/service-authentication/apps/default/service/fedcm"
	"github.com/antinvestor/service-authentication/apps/default/service/models"
	"github.com/antinvestor/service-authentication/apps/default/service/nativecredentials"
	"github.com/pitabwire/frame/v2"
	"github.com/pitabwire/frame/v2/client"
	"github.com/pitabwire/frame/v2/data"
	"github.com/pitabwire/util"
	"google.golang.org/protobuf/types/known/structpb"
)

const nativeTokenExchangeGrant = "urn:ietf:params:oauth:grant-type:token-exchange"
const idTokenSubjectTokenType = "urn:ietf:params:oauth:token-type:id_token"

// facadeUpstreamTimeout bounds every facade call to Hydra (discovery + token).
// The native exchange is a session-bootstrap path, not a hot path, so a slow
// Hydra must not hold the request open indefinitely.
const facadeUpstreamTimeout = 15 * time.Second

// facadeUpstreamClient returns the bounded-timeout client used to reach Hydra.
// It is always set by NewAuthServer in production; the fallback only matters
// for unit tests that construct AuthServer directly.
func (h *AuthServer) facadeUpstreamClient() *http.Client {
	if h.tokenFacadeClient != nil {
		return h.tokenFacadeClient
	}
	return client.NewHTTPClient(context.Background(), client.WithHTTPTimeout(facadeUpstreamTimeout))
}

// hydraUpstreamBase resolves the Hydra public base URL the facade proxies to.
// It fails closed when the URL is unset or points back at this facade's own
// origin, which would otherwise cause unbounded request recursion (the issuer
// origin routes /oauth2/token to the facade, the facade proxies to the same
// origin, and so on).
func (h *AuthServer) hydraUpstreamBase(r *http.Request) (string, error) {
	base := strings.TrimRight(hydraPublicURL(h.config), "/")
	if base == "" {
		return "", fmt.Errorf("hydra public URL is not configured")
	}
	if sameHTTPHost(base, h.externalTokenEndpoint(r)) {
		return "", fmt.Errorf("hydra public URL points back at the token facade")
	}
	return base, nil
}

// sameHTTPHost reports whether two URLs share a host (case-insensitive),
// ignoring scheme and path. Used to detect the self-referential proxy loop.
func sameHTTPHost(a, b string) bool {
	ua, err1 := url.Parse(a)
	ub, err2 := url.Parse(b)
	if err1 != nil || err2 != nil || ua.Host == "" || ub.Host == "" {
		return false
	}
	return strings.EqualFold(ua.Host, ub.Host)
}

type nativeClientConfig struct {
	ClientID       string
	Enabled        bool
	GoogleAudience string
	AppleAudience  string
}

type nativeExchangeError struct {
	status      int
	code        string
	description string
}

func (e *nativeExchangeError) Error() string {
	if e.description != "" {
		return e.description
	}
	return e.code
}

// OpenIDConfigurationFacadeEndpoint proxies Hydra's discovery document and
// rewrites token_endpoint to this authentication-service facade.
func (h *AuthServer) OpenIDConfigurationFacadeEndpoint(w http.ResponseWriter, r *http.Request) error {
	base, err := h.hydraUpstreamBase(r)
	if err != nil {
		util.Log(r.Context()).WithError(err).Error("hydra discovery facade misconfigured")
		return h.writeOAuthError(w, http.StatusInternalServerError, "server_error", "token endpoint is misconfigured")
	}
	discoveryURL := base + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, discoveryURL, nil)
	if err != nil {
		return h.writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not construct discovery request")
	}
	req.Header.Set("Accept", "application/json")

	resp, err := h.facadeUpstreamClient().Do(req)
	if err != nil {
		util.Log(r.Context()).WithError(err).Error("hydra discovery proxy transport failed")
		return h.writeOAuthError(w, http.StatusBadGateway, "server_error", "hydra discovery endpoint is unavailable")
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return h.writeOAuthError(w, http.StatusBadGateway, "server_error", "could not read hydra discovery response")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
		w.WriteHeader(resp.StatusCode)
		_, err = w.Write(raw)
		return err
	}

	var doc map[string]any
	if err = json.Unmarshal(raw, &doc); err != nil {
		return h.writeOAuthError(w, http.StatusBadGateway, "server_error", "hydra discovery response is invalid")
	}
	doc["token_endpoint"] = h.externalTokenEndpoint(r)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	return json.NewEncoder(w).Encode(doc)
}

// OAuthTokenFacadeEndpoint serves the public /oauth2/token facade. It handles
// native provider ID-token exchange and proxies all ordinary grants to Hydra.
func (h *AuthServer) OAuthTokenFacadeEndpoint(w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		return h.writeOAuthError(w, http.StatusMethodNotAllowed, "invalid_request", "method not allowed")
	}
	if r.Body == nil {
		return h.writeOAuthError(w, http.StatusBadRequest, "invalid_request", "request body is required")
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 2*1024*1024))
	if err != nil {
		return h.writeOAuthError(w, http.StatusBadRequest, "invalid_request", "could not read request body")
	}
	form, err := url.ParseQuery(string(body))
	if err != nil {
		return h.writeOAuthError(w, http.StatusBadRequest, "invalid_request", "invalid form body")
	}

	if form.Get("grant_type") != nativeTokenExchangeGrant {
		return h.proxyTokenRequestToHydra(w, r, body)
	}

	tokenResponse, exchangeErr := h.handleNativeTokenExchange(r.Context(), r, form)
	if exchangeErr != nil {
		return h.writeOAuthError(w, exchangeErr.status, exchangeErr.code, exchangeErr.description)
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusOK)
	_, err = w.Write(tokenResponse)
	return err
}

func (h *AuthServer) proxyTokenRequestToHydra(w http.ResponseWriter, r *http.Request, body []byte) error {
	base, err := h.hydraUpstreamBase(r)
	if err != nil {
		util.Log(r.Context()).WithError(err).Error("hydra token facade misconfigured")
		return h.writeOAuthError(w, http.StatusInternalServerError, "server_error", "token endpoint is misconfigured")
	}
	tokenURL := base + "/oauth2/token"
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, tokenURL, bytes.NewReader(body))
	if err != nil {
		return h.writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not construct upstream token request")
	}
	copyTokenProxyHeaders(req.Header, r.Header)

	resp, err := h.facadeUpstreamClient().Do(req)
	if err != nil {
		util.Log(r.Context()).WithError(err).Error("hydra token proxy transport failed")
		return h.writeOAuthError(w, http.StatusBadGateway, "server_error", "hydra token endpoint is unavailable")
	}
	defer func() { _ = resp.Body.Close() }()

	for key, values := range resp.Header {
		if shouldProxyResponseHeader(key) {
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}
	}
	if w.Header().Get("Cache-Control") == "" {
		w.Header().Set("Cache-Control", "no-store")
	}
	if w.Header().Get("Pragma") == "" {
		w.Header().Set("Pragma", "no-cache")
	}
	w.WriteHeader(resp.StatusCode)
	_, err = io.Copy(w, resp.Body)
	return err
}

func copyTokenProxyHeaders(dst, src http.Header) {
	for _, key := range []string{"Content-Type", "Accept", "Authorization", "DPoP", "DPoP-Nonce", "User-Agent"} {
		if value := src.Get(key); value != "" {
			dst.Set(key, value)
		}
	}
}

func shouldProxyResponseHeader(key string) bool {
	switch strings.ToLower(key) {
	case "content-type", "cache-control", "pragma", "www-authenticate", "dpop-nonce":
		return true
	default:
		return false
	}
}

// handleNativeTokenExchange validates a provider ID token and mints a Hydra
// session for the resolved profile. The deployment-wide
// NativeCredentialExchangeEnabled flag is a kill switch; normal authorization
// is constrained by a known local OAuth client and that client's
// native_auth_enabled property. Provider audience verification uses the
// authentication service's server-side provider configuration.
//
// NOTE: this path does not enforce a step-up MFA challenge — possession of a
// fresh, verified Google/Apple ID token is treated as the authentication
// factor. Tenancies that require MFA must not enable native auth on their
// clients until an MFA gate is wired in.
func (h *AuthServer) handleNativeTokenExchange(ctx context.Context, r *http.Request, form url.Values) ([]byte, *nativeExchangeError) {
	if !h.config.NativeCredentialExchangeEnabled {
		return nil, oauthErr(http.StatusBadRequest, "invalid_grant", "native credential exchange is disabled")
	}
	if form.Get("subject_token_type") != idTokenSubjectTokenType {
		return nil, oauthErr(http.StatusBadRequest, "invalid_request", "subject_token_type must be id_token")
	}
	clientID := strings.TrimSpace(form.Get("client_id"))
	if clientID == "" {
		return nil, oauthErr(http.StatusBadRequest, "invalid_request", "client_id is required")
	}

	clientCfg, hydraClient, err := h.resolveNativeClientConfig(ctx, clientID)
	if err != nil {
		return nil, oauthErr(http.StatusBadRequest, "invalid_client", err.Error())
	}
	clientID = clientCfg.ClientID
	if !clientCfg.Enabled {
		return nil, oauthErr(http.StatusBadRequest, "invalid_grant", "native auth is not enabled for this client")
	}

	issuer := strings.TrimSpace(form.Get("subject_issuer"))
	audience := clientCfg.audienceForIssuer(issuer)
	if audience == "" {
		return nil, oauthErr(http.StatusBadRequest, "invalid_grant", "subject issuer is not enabled for this client")
	}

	rate := h.CheckLoginRateLimit(ctx, nativeRateLimitKey(clientID, issuer, clientIP(r)))
	if !rate.Allowed {
		util.Log(ctx).WithField("client_id", clientID).WithField("subject_issuer", issuer).
			Warn("native credential exchange rate limited")
		return nil, oauthErr(http.StatusTooManyRequests, "rate_limited", "too many native credential exchange attempts")
	}

	identity, err := h.nativeVerifier.VerifyIDToken(ctx, issuer, audience, form.Get("subject_token"))
	if err != nil {
		return nil, oauthErr(http.StatusBadRequest, "invalid_grant", err.Error())
	}
	replayed, replayErr := h.rejectNativeReplay(ctx, identity)
	if replayErr != nil {
		return nil, oauthErr(http.StatusInternalServerError, "server_error", "replay cache unavailable")
	}
	if replayed {
		return nil, oauthErr(http.StatusBadRequest, "invalid_grant", "subject token has already been used")
	}

	profileID, contactID, err := h.resolveNativeProfile(ctx, identity)
	if err != nil {
		return nil, oauthErr(http.StatusBadRequest, "invalid_grant", err.Error())
	}

	ownerPartition, err := h.resolvePartitionByClientID(ctx, clientID)
	if err != nil {
		return nil, oauthErr(http.StatusForbidden, "access_denied", "OAuth client has no partition owner")
	}
	accessObj, err := h.getOrCreateTenancyAccessByPartitionID(ctx, ownerPartition, profileID)
	if err != nil {
		return nil, oauthErr(http.StatusForbidden, "access_denied", "profile is not allowed for this client")
	}
	partition := accessObj.GetPartition()
	if partition == nil {
		return nil, oauthErr(http.StatusInternalServerError, "server_error", "access partition is missing")
	}
	if err = h.linkExternalIdentity(ctx, identity, profileID, accessObj.GetId(), partition.GetTenantId(), partition.GetId()); err != nil {
		return nil, oauthErr(http.StatusInternalServerError, "server_error", "could not link external identity")
	}

	loginEvent, err := h.createNativeLoginEvent(
		ctx, r, form, clientID, profileID, contactID, accessObj.GetId(), partition.GetTenantId(), partition.GetId(), identity,
	)
	if err != nil {
		return nil, oauthErr(http.StatusInternalServerError, "server_error", err.Error())
	}

	deviceObj, err := h.processDeviceSession(ctx, profileID, r.UserAgent())
	if err != nil && deviceObj == nil {
		return nil, oauthErr(http.StatusInternalServerError, "server_error", "could not resolve device session")
	}
	deviceID := ""
	if deviceObj != nil {
		deviceID = deviceObj.GetId()
		loginEvent.DeviceID = deviceID
	}
	if _, err = h.loginEventRepo.Update(ctx, loginEvent, "device_id"); err != nil {
		return nil, oauthErr(http.StatusInternalServerError, "server_error", "could not persist login event context")
	}

	defaultRole := partitionDefaultRole(partition)
	roles := h.fetchAccessRoleNames(ctx, loginEvent.AccessID, defaultRole)
	if len(roles) == 0 {
		roles = []string{"user"}
	}
	claims := BuildUserTokenClaims(loginEvent, profileID, deviceID, roles)
	scopes := tokenScopes(hydraClient.GetScope())
	nonce := strings.TrimSpace(form.Get("nonce"))

	result, err := h.fedcmDriver.Run(ctx, fedcm.HeadlessRequest{
		ClientID:     clientID,
		ClientSecret: hydraClient.GetClientSecret(),
		SubjectID:    profileID,
		Nonce:        nonce,
		Scopes:       scopes,
		Claims:       claims,
		ACR:          "native",
		AMR:          []string{identity.Provider},
		DeviceID:     deviceID,
	})
	if err != nil {
		util.Log(ctx).WithError(err).WithField("client_id", clientID).Error("native headless hydra flow failed")
		return nil, oauthErr(http.StatusBadGateway, "server_error", "hydra token issuance failed")
	}

	h.ResetLoginRateLimit(ctx, nativeRateLimitKey(clientID, issuer, clientIP(r)))
	util.Log(ctx).
		WithField("client_id", clientID).
		WithField("provider", identity.Provider).
		WithField("profile_id", profileID).
		WithField("login_event_id", loginEvent.GetID()).
		Info("native credential exchange succeeded")
	payload, err := json.Marshal(map[string]any{
		"access_token":  result.AccessToken,
		"refresh_token": result.RefreshToken,
		"id_token":      result.IDToken,
		"token_type":    "Bearer",
		"expires_in":    result.ExpiresIn,
	})
	if err != nil {
		return nil, oauthErr(http.StatusInternalServerError, "server_error", "could not encode token response")
	}
	return payload, nil
}

func (c nativeClientConfig) audienceForIssuer(issuer string) string {
	switch strings.TrimRight(strings.TrimSpace(issuer), "/") {
	case nativecredentials.GoogleIssuer, nativecredentials.GoogleIssuerShort:
		return c.GoogleAudience
	case nativecredentials.AppleIssuer:
		return c.AppleAudience
	default:
		return ""
	}
}

func (h *AuthServer) resolveNativeClientConfig(ctx context.Context, clientID string) (*nativeClientConfig, anyHydraClient, error) {
	if h.authContractCli == nil {
		return nil, nil, fmt.Errorf("tenancy client lookup is unavailable")
	}

	clientObj, err := h.getOAuthClient(ctx, clientID)
	if err != nil {
		return nil, nil, fmt.Errorf("client lookup failed: %w", err)
	}
	resolvedClientID := strings.TrimSpace(clientObj.GetClientId())
	if resolvedClientID == "" {
		return nil, nil, fmt.Errorf("client lookup returned no client_id")
	}

	if h.defaultHydraCli == nil {
		return nil, nil, fmt.Errorf("hydra client lookup is unavailable")
	}
	hydraClient, err := h.defaultHydraCli.GetOAuth2Client(ctx, resolvedClientID)
	if err != nil {
		return nil, nil, fmt.Errorf("hydra client lookup failed: %w", err)
	}

	props := map[string]any{}
	if clientObj.GetConfiguration().GetProperties() != nil {
		props = clientObj.GetConfiguration().GetProperties().AsMap()
	}

	return h.nativeClientConfigFromProperties(resolvedClientID, props), hydraClient, nil
}

func (h *AuthServer) nativeClientConfigFromProperties(clientID string, props map[string]any) *nativeClientConfig {
	googleAudience := ""
	appleAudience := ""
	if h != nil && h.config != nil {
		googleAudience = h.config.AuthProviderGoogleClientID
		appleAudience = h.config.AuthProviderAppleClientID
	}

	return &nativeClientConfig{
		ClientID:       strings.TrimSpace(clientID),
		Enabled:        boolProperty(props, "native_auth_enabled"),
		GoogleAudience: strings.TrimSpace(googleAudience),
		AppleAudience:  strings.TrimSpace(appleAudience),
	}
}

type anyHydraClient interface {
	GetClientSecret() string
	GetScope() string
}

func boolProperty(props map[string]any, key string) bool {
	v, ok := props[key]
	if !ok {
		return false
	}
	switch typed := v.(type) {
	case bool:
		return typed
	case string:
		return strings.EqualFold(typed, "true") || typed == "1"
	default:
		return false
	}
}

func tokenScopes(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return []string{"openid", "profile", "email", "offline_access"}
	}
	return strings.Fields(raw)
}

func (h *AuthServer) rejectNativeReplay(ctx context.Context, identity *nativecredentials.Identity) (bool, error) {
	if identity == nil {
		return false, fmt.Errorf("identity is required")
	}
	if identity.TokenHash == "" {
		return false, fmt.Errorf("token hash is required")
	}
	if h.cacheMan == nil {
		return false, fmt.Errorf("cache manager is unavailable")
	}
	rawCache, ok := h.cacheMan.GetRawCache(h.config.CacheName)
	if !ok {
		return false, fmt.Errorf("cache %q is unavailable", h.config.CacheName)
	}
	key := "native:replay:" + identity.Provider + ":" + identity.TokenHash
	count, err := rawCache.Increment(ctx, key, 1)
	if err != nil {
		return false, err
	}
	if count > 1 {
		return true, nil
	}
	if err = rawCache.Expire(ctx, key, 6*time.Minute); err != nil {
		_ = rawCache.Delete(ctx, key)
		return false, err
	}
	return false, nil
}

func (h *AuthServer) resolveNativeProfile(ctx context.Context, identity *nativecredentials.Identity) (profileID, contactID string, err error) {
	if identity == nil {
		return "", "", fmt.Errorf("identity is required")
	}
	existingIdentity, err := h.externalIdentityRepo.GetByProviderSubject(ctx, identity.Provider, identity.Subject)
	if err != nil {
		return "", "", fmt.Errorf("external identity lookup failed: %w", err)
	}
	if existingIdentity != nil && existingIdentity.ProfileID != "" {
		profileID = existingIdentity.ProfileID
		contactID, err = h.findContactIDForProfile(ctx, profileID, identity.Email)
		if err != nil {
			return "", "", err
		}
		return profileID, contactID, nil
	}
	if identity.Email == "" {
		return "", "", fmt.Errorf("%s did not provide an email and is not linked", identity.Provider)
	}
	if !identity.EmailVerified {
		return "", "", fmt.Errorf("%s email is not verified", identity.Provider)
	}

	result, lookupErr := h.profileCli.GetByContact(ctx, connect.NewRequest(&profilev1.GetByContactRequest{Contact: identity.Email}))
	if lookupErr != nil && !frame.ErrorIsNotFound(lookupErr) {
		return "", "", fmt.Errorf("profile lookup failed: %w", lookupErr)
	}
	if lookupErr == nil && result != nil && result.Msg.GetData() != nil {
		profile := result.Msg.GetData()
		if profile.GetType() == profilev1.ProfileType_BOT {
			return "", "", fmt.Errorf("bot accounts cannot log in through native credentials")
		}
		return profile.GetId(), contactIDFromProfile(profile, identity.Email), nil
	}

	displayName := identity.Name
	if displayName == "" {
		displayName = strings.TrimSpace(strings.Join([]string{identity.GivenName, identity.FamilyName}, " "))
	}
	properties, _ := structpb.NewStruct(map[string]any{
		KeyProfileName: displayName,
		"src":          identity.Provider,
	})
	createResult, createErr := h.profileCli.Create(ctx, connect.NewRequest(&profilev1.CreateRequest{
		Type:       profilev1.ProfileType_PERSON,
		Contact:    identity.Email,
		Properties: properties,
	}))
	if createErr != nil {
		return "", "", fmt.Errorf("profile creation failed: %w", createErr)
	}
	profile := createResult.Msg.GetData()
	if profile == nil || profile.GetId() == "" {
		return "", "", fmt.Errorf("profile creation returned invalid response")
	}
	return profile.GetId(), contactIDFromProfile(profile, identity.Email), nil
}

func (h *AuthServer) findContactIDForProfile(ctx context.Context, profileID, contact string) (string, error) {
	req := &profilev1.GetByIdRequest{}
	req.SetId(profileID)
	resp, err := h.profileCli.GetById(ctx, connect.NewRequest(req))
	if err != nil {
		return "", err
	}
	profile := resp.Msg.GetData()
	if profile == nil {
		return "", fmt.Errorf("linked profile is missing")
	}
	if profile.GetType() == profilev1.ProfileType_BOT {
		return "", fmt.Errorf("bot accounts cannot log in through native credentials")
	}
	return contactIDFromProfile(profile, contact), nil
}

func contactIDFromProfile(profile *profilev1.ProfileObject, contact string) string {
	if profile == nil {
		return ""
	}
	for _, c := range profile.GetContacts() {
		if strings.EqualFold(strings.TrimSpace(c.GetDetail()), strings.TrimSpace(contact)) {
			return c.GetId()
		}
	}
	return ""
}

func (h *AuthServer) linkExternalIdentity(ctx context.Context, identity *nativecredentials.Identity, profileID, accessID, tenantID, partitionID string) error {
	existing, err := h.externalIdentityRepo.GetByProviderSubject(ctx, identity.Provider, identity.Subject)
	if err != nil {
		return err
	}
	if existing != nil {
		if existing.ProfileID != profileID {
			return fmt.Errorf("external identity is already linked to another profile")
		}
		return h.touchExternalIdentity(ctx, existing, identity, accessID, tenantID, partitionID)
	}

	record := &models.ExternalIdentity{
		ProfileID:       profileID,
		Provider:        identity.Provider,
		ProviderSubject: identity.Subject,
		EmailAtLink:     identity.Email,
		EmailVerified:   identity.EmailVerified,
		LastSeenAt:      time.Now(),
		Properties: data.JSONMap{
			"issuer":                identity.Issuer,
			"provider_subject_hash": identity.SubjectHash,
		},
	}
	record.AccessID = accessID
	record.TenantID = tenantID
	record.PartitionID = partitionID
	record.GenID(ctx)
	if err = h.externalIdentityRepo.Create(ctx, record); err != nil {
		if !data.ErrorIsDuplicateKey(err) {
			return err
		}
		existing, lookupErr := h.externalIdentityRepo.GetByProviderSubject(ctx, identity.Provider, identity.Subject)
		if lookupErr != nil {
			return lookupErr
		}
		if existing == nil || existing.ProfileID != profileID {
			return err
		}
		return h.touchExternalIdentity(ctx, existing, identity, accessID, tenantID, partitionID)
	}
	return err
}

// touchExternalIdentity refreshes the mutable columns of an already-linked
// identity on each successful native login, including the tenant/partition of
// the access used this time so the record reflects the latest workspace.
func (h *AuthServer) touchExternalIdentity(
	ctx context.Context, existing *models.ExternalIdentity,
	identity *nativecredentials.Identity, accessID, tenantID, partitionID string,
) error {
	existing.LastSeenAt = time.Now()
	existing.EmailAtLink = identity.Email
	existing.EmailVerified = identity.EmailVerified
	existing.AccessID = accessID
	existing.TenantID = tenantID
	existing.PartitionID = partitionID
	_, err := h.externalIdentityRepo.Update(ctx, existing,
		"last_seen_at", "email_at_link", "email_verified", "access_id", "tenant_id", "partition_id")
	return err
}

func (h *AuthServer) createNativeLoginEvent(
	ctx context.Context, r *http.Request, form url.Values,
	clientID, profileID, contactID, accessID, tenantID, partitionID string,
	identity *nativecredentials.Identity,
) (*models.LoginEvent, error) {
	loginRecord, err := h.getOrCreateLoginRecord(ctx, profileID, clientID, identity.Provider)
	if err != nil {
		return nil, fmt.Errorf("resolve login record: %w", err)
	}
	loginEvent := &models.LoginEvent{
		ClientID:  clientID,
		LoginID:   loginRecord.GetID(),
		ProfileID: profileID,
		ContactID: contactID,
		Client:    r.UserAgent(),
		IP:        clientIP(r),
		AccessID:  accessID,
		Properties: data.JSONMap{
			loginEventPropertyLoginSource: string(models.LoginSource(identity.Provider)),
			"native_provider":             identity.Provider,
			"native_issuer":               identity.Issuer,
			"native_subject_hash":         identity.SubjectHash,
			"native_email":                identity.Email,
			"native_email_verified":       identity.EmailVerified,
			"platform":                    strings.TrimSpace(form.Get("platform")),
			"installation_id":             strings.TrimSpace(form.Get("installation_id")),
			"device_name":                 strings.TrimSpace(form.Get("device_name")),
		},
	}
	loginEvent.TenantID = tenantID
	loginEvent.PartitionID = partitionID
	loginEvent.GenID(ctx)
	if err = h.loginEventRepo.Create(ctx, loginEvent); err != nil {
		return nil, fmt.Errorf("create login event: %w", err)
	}
	return loginEvent, nil
}

func oauthErr(status int, code, description string) *nativeExchangeError {
	return &nativeExchangeError{status: status, code: code, description: description}
}

func (h *AuthServer) writeOAuthError(w http.ResponseWriter, status int, code, description string) error {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(map[string]string{
		"error":             code,
		"error_description": description,
	})
}

func clientIP(r *http.Request) string {
	for _, header := range []string{"X-Forwarded-For", "X-Real-IP"} {
		if value := strings.TrimSpace(r.Header.Get(header)); value != "" {
			first := strings.TrimSpace(strings.Split(value, ",")[0])
			if first != "" {
				return first
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

func nativeRateLimitKey(clientID, issuer, ip string) string {
	return clientID + ":" + issuer + ":" + ip
}

func (h *AuthServer) externalTokenEndpoint(r *http.Request) string {
	if h != nil && h.config != nil {
		if origin := strings.TrimRight(strings.TrimSpace(h.config.FedCMPublicOrigin), "/"); origin != "" {
			if parsed, err := url.Parse(origin); err == nil && parsed.Scheme != "" && parsed.Host != "" {
				return origin + "/oauth2/token"
			}
		}
	}
	scheme := "https"
	if r.Header.Get("X-Forwarded-Proto") != "" {
		scheme = strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Proto"), ",")[0])
	} else if r.TLS == nil {
		scheme = "http"
	}
	host := r.Host
	if forwardedHost := strings.TrimSpace(r.Header.Get("X-Forwarded-Host")); forwardedHost != "" {
		host = strings.TrimSpace(strings.Split(forwardedHost, ",")[0])
	}
	return scheme + "://" + host + "/oauth2/token"
}
