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

// FedCM cold-start popup flow.
//
// Design decision: parallel /s/fedcm/verify route (NOT branching existing verification).
//
// The existing VerificationEndpointSubmit calls h.defaultHydraCli.AcceptLoginRequest
// as its final step — an operation that requires a Hydra login_challenge.  The FedCM
// cold-start popup has no Hydra challenge (it is standalone sign-in to populate the
// idp_session cookie), so branching the existing handler would require threading an
// optional-challenge concept through critical production code.  Instead we introduce
// a narrow parallel verify route /s/fedcm/verify/{loginEventId} that:
//   - Shows a code-entry form backed by the SAME profile service verification API.
//   - On success writes the idp_session cookie and renders fedcm_close.html.
//   - Does NOT touch Hydra at all.
//
// The LoginEvent created by FedCMLoginSubmit is tagged with
// Properties["fedcm_coldstart"] = "1" and ClientID = "" (sentinel) so downstream
// code (webhook, consent) can identify and ignore it safely.

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	profilev1 "buf.build/gen/go/antinvestor/profile/protocolbuffers/go/profile/v1"
	"connectrpc.com/connect"
	"github.com/antinvestor/service-authentication/apps/default/service/models"
	"github.com/antinvestor/service-authentication/apps/default/utils"
	"github.com/pitabwire/frame/v2"
	"github.com/pitabwire/util"
)

const fedcmColdStartProperty = "fedcm_coldstart"

// FedCMLoginShow renders the contact-entry form for the FedCM cold-start popup.
//
// GET /s/fedcm/login
func (h *AuthServer) FedCMLoginShow(rw http.ResponseWriter, req *http.Request) error {
	payload := h.initTemplatePayloadWithI18n(req.Context(), req)
	payload["error"] = ""
	return fedcmLoginTmpl.Execute(rw, payload)
}

// FedCMLoginSubmit receives a contact, creates a standalone LoginEvent tagged with
// fedcm_coldstart=1, sends a verification code via the profile service, and
// redirects the browser to the FedCM-specific code-entry page.
//
// POST /s/fedcm/login
func (h *AuthServer) FedCMLoginSubmit(rw http.ResponseWriter, req *http.Request) error {
	ctx := req.Context()
	log := util.Log(ctx)

	if err := req.ParseForm(); err != nil {
		return fmt.Errorf("fedcm login: failed to parse form: %w", err)
	}

	contact := strings.TrimSpace(req.FormValue("contact"))

	renderError := func(msg string) error {
		payload := h.initTemplatePayloadWithI18n(ctx, req)
		payload["error"] = msg
		return fedcmLoginTmpl.Execute(rw, payload)
	}

	if contact == "" {
		return renderError("Please enter your email or phone number.")
	}

	contactType, valid := utils.ValidateContact(contact)
	if !valid {
		return renderError("Please enter a valid email address or phone number.")
	}

	// Rate-limit by IP (reuse existing limiter).
	ipAddr := util.GetIP(req)
	if result := h.CheckLoginRateLimit(ctx, ipAddr); !result.Allowed {
		return renderError("Too many login attempts. Please try again later.")
	}

	contactID, profileID, profileName, err := h.fedcmResolveContact(ctx, contact)
	if err != nil {
		log.WithError(err).Error("fedcm login: contact resolution failed")
		return renderError("Something went wrong. Please try again.")
	}

	// Send verification code.
	verResp, verErr := h.profileCli.CreateContactVerification(ctx, connect.NewRequest(&profilev1.CreateContactVerificationRequest{
		Id:               util.IDString(),
		ContactId:        contactID,
		DurationToExpire: "15m",
	}))
	if verErr != nil {
		log.WithError(verErr).Error("fedcm login: failed to create verification")
		return renderError("Something went wrong. Please try again.")
	}

	// Create a standalone LoginEvent (no Hydra challenge, ClientID="").
	loginEvt := &models.LoginEvent{
		ClientID:       "", // FedCM cold-start sentinel — no OAuth2 client
		VerificationID: verResp.Msg.GetId(),
		ContactID:      contactID,
		ProfileID:      profileID,
		IP:             util.GetIP(req),
		Client:         req.UserAgent(),
		Properties: map[string]any{
			fedcmColdStartProperty:        "1",
			loginEventPropertyLoginSource: string(models.LoginSourceDirect),
		},
	}
	loginEvt.ID = util.IDString()

	if err = h.loginEventRepo.Create(ctx, loginEvt); err != nil {
		log.WithError(err).Error("fedcm login: failed to persist login event")
		return renderError("Something went wrong. Please try again.")
	}

	if cacheErr := h.setLoginEventToCache(ctx, loginEvt); cacheErr != nil {
		log.WithError(cacheErr).Debug("fedcm login: failed to cache login event")
	}

	log.WithFields(map[string]any{
		"login_event_id":  loginEvt.GetID(),
		"contact_type":    contactType.String(),
		"verification_id": verResp.Msg.GetId(),
	}).Info("fedcm cold-start: verification code sent")

	// Redirect to FedCM-specific verify page.
	http.Redirect(rw, req,
		fmt.Sprintf("/s/fedcm/verify/%s?contact_type=%s&profile_name=%s",
			loginEvt.GetID(), contactType.String(), profileName),
		http.StatusSeeOther)
	return nil
}

// FedCMVerifyShow renders the code-entry form for the FedCM cold-start popup.
//
// GET /s/fedcm/verify/{loginEventId}
func (h *AuthServer) FedCMVerifyShow(rw http.ResponseWriter, req *http.Request) error {
	ctx := req.Context()
	loginEventID := req.PathValue(pathValueLoginEventID)

	payload := h.initTemplatePayloadWithI18n(ctx, req)
	payload["login_event_id"] = loginEventID
	payload["contact_type"] = req.URL.Query().Get("contact_type")
	payload["profile_name"] = req.URL.Query().Get("profile_name")
	payload["error"] = ""

	return fedcmVerifyTmpl.Execute(rw, payload)
}

// FedCMVerifySubmit validates the code, upserts the idp_session cookie, and
// renders fedcm_close.html so the browser popup can call IdentityProvider.close().
//
// POST /s/fedcm/verify/{loginEventId}
func (h *AuthServer) FedCMVerifySubmit(rw http.ResponseWriter, req *http.Request) error {
	ctx := req.Context()
	log := util.Log(ctx)

	loginEventID, contactType, profileName, code, parseErr := h.parseFedCMVerifyForm(req)
	if parseErr != nil {
		return parseErr
	}

	showVerifyError := func(msg string) error {
		payload := h.initTemplatePayloadWithI18n(ctx, req)
		payload["login_event_id"] = loginEventID
		payload["contact_type"] = contactType
		payload["profile_name"] = profileName
		payload["error"] = msg
		return fedcmVerifyTmpl.Execute(rw, payload)
	}

	if loginEventID == "" {
		return showVerifyError("Session expired. Please start again.")
	}

	loginEvent, err := h.loginEventRepo.GetByID(ctx, loginEventID)
	if err != nil {
		log.WithError(err).Warn("fedcm verify: login event not found")
		return showVerifyError("Session expired. Please start again.")
	}

	if loginEvent.Properties == nil || loginEvent.Properties[fedcmColdStartProperty] != "1" {
		log.Warn("fedcm verify: login event is not a fedcm cold-start event")
		http.Redirect(rw, req, "/s/fedcm/login", http.StatusSeeOther)
		return nil
	}

	if code == "" {
		return showVerifyError("Please enter the verification code.")
	}

	profileID, verErr := h.fedcmCheckCode(ctx, loginEvent, code)
	if verErr != nil {
		log.WithError(verErr).Warn("fedcm verify: code check failed")
		return showVerifyError(verErr.Error())
	}

	contactDetail, contactTypeStr, name := h.fedcmEnrichFromProfile(ctx, loginEvent, profileID, contactType, profileName)

	h.fedcmWriteIdPSession(ctx, rw, req, profileID, contactDetail, contactTypeStr, name, loginEventID, "contact")

	log.WithFields(map[string]any{
		"profile_id":     profileID,
		"login_event_id": loginEventID,
	}).Info("fedcm cold-start: login complete, rendering close page")

	setLoginStatusLoggedIn(rw)
	return fedcmCloseTmpl.Execute(rw, nil)
}

// FedCMLoginComplete is the programmatic entry point for other handlers that have
// already authenticated the user (e.g. social callback) and need to upsert the
// idp_session and close the FedCM popup. It is exported so it can be called from
// provider callback handlers in future tasks.
func (h *AuthServer) FedCMLoginComplete(
	rw http.ResponseWriter,
	req *http.Request,
	profileID string,
	contact string,
	contactType string,
	name string,
	loginEventID string,
	authMethod string,
) error {
	ctx := req.Context()
	h.fedcmWriteIdPSession(ctx, rw, req, profileID, contact, contactType, name, loginEventID, authMethod)
	setLoginStatusLoggedIn(rw)
	return fedcmCloseTmpl.Execute(rw, nil)
}

// fedcmResolveContact looks up or creates the profile contact for the given
// contact detail string. Returns contactID, profileID, profileName, error.
func (h *AuthServer) fedcmResolveContact(ctx context.Context, contact string) (contactID, profileID, profileName string, err error) {
	result, lookupErr := h.profileCli.GetByContact(ctx, connect.NewRequest(&profilev1.GetByContactRequest{
		Contact: contact,
	}))
	if lookupErr != nil && !frame.ErrorIsNotFound(lookupErr) {
		return "", "", "", lookupErr
	}

	if result != nil && result.Msg.GetData() != nil {
		existing := result.Msg.GetData()
		profileID = existing.GetId()
		for _, c := range existing.GetContacts() {
			if strings.EqualFold(contact, c.GetDetail()) {
				contactID = c.GetId()
				break
			}
		}
		if pn := existing.GetProperties(); pn != nil {
			if m := pn.AsMap(); m != nil {
				if n, ok := m[KeyProfileName].(string); ok {
					profileName = n
				}
			}
		}
	}

	if contactID == "" {
		resp, createErr := h.profileCli.CreateContact(ctx, connect.NewRequest(&profilev1.CreateContactRequest{
			Contact: contact,
		}))
		if createErr != nil {
			return "", "", "", createErr
		}
		contactID = resp.Msg.GetData().GetId()
	}

	return contactID, profileID, profileName, nil
}

// parseFedCMVerifyForm parses the form body for FedCMVerifySubmit.
// Returns loginEventID, contactType, profileName, code, error.
func (h *AuthServer) parseFedCMVerifyForm(req *http.Request) (loginEventID, contactType, profileName, code string, err error) {
	loginEventID = req.PathValue(pathValueLoginEventID)
	if loginEventID == "" {
		if parseErr := req.ParseForm(); parseErr != nil {
			return "", "", "", "", fmt.Errorf("fedcm verify: failed to parse form: %w", parseErr)
		}
		loginEventID = req.PostForm.Get("login_event_id")
	}

	if parseErr := req.ParseForm(); parseErr != nil {
		return "", "", "", "", fmt.Errorf("fedcm verify: failed to parse form: %w", parseErr)
	}

	contactType = req.PostForm.Get("contact_type")
	profileName = req.PostForm.Get("profile_name")
	code = strings.TrimSpace(req.PostForm.Get("verification_code"))
	return loginEventID, contactType, profileName, code, nil
}

// fedcmCheckCode validates the verification code and returns the resolved profileID.
func (h *AuthServer) fedcmCheckCode(ctx context.Context, loginEvent *models.LoginEvent, code string) (string, error) {
	log := util.Log(ctx)

	maxAttempts := h.config.AuthProviderContactLoginMaxVerificationAttempts
	if maxAttempts == 0 {
		maxAttempts = 3
	}

	verResp, verErr := h.profileCli.CheckVerification(ctx, connect.NewRequest(&profilev1.CheckVerificationRequest{
		Id:   loginEvent.VerificationID,
		Code: code,
	}))
	if verErr != nil {
		return "", fmt.Errorf("verification failed, please try again")
	}
	if int(verResp.Msg.GetCheckAttempts()) > maxAttempts {
		return "", fmt.Errorf("too many incorrect attempts, please start again")
	}
	if !verResp.Msg.GetSuccess() {
		return "", fmt.Errorf("incorrect code, please try again")
	}

	profileID := loginEvent.ProfileID
	if profileID != "" {
		return profileID, nil
	}

	// First-time login — create a profile.
	createResp, createErr := h.profileCli.Create(ctx, connect.NewRequest(&profilev1.CreateRequest{
		Type:    profilev1.ProfileType_PERSON,
		Contact: loginEvent.ContactID,
	}))
	if createErr != nil {
		return "", fmt.Errorf("profile creation failed")
	}
	created := createResp.Msg.GetData()
	if created == nil || created.GetId() == "" {
		return "", fmt.Errorf("profile creation returned empty profile")
	}
	profileID = created.GetId()

	loginEvent.ProfileID = profileID
	if _, updateErr := h.loginEventRepo.Update(ctx, loginEvent, "profile_id"); updateErr != nil {
		log.WithError(updateErr).Error("fedcm verify: failed to update login event with profile_id")
	}

	return profileID, nil
}

// fedcmEnrichFromProfile fetches the profile and extracts contact detail, contact type
// and display name for the idp_session entry. Falls back to the provided defaults.
func (h *AuthServer) fedcmEnrichFromProfile(ctx context.Context, loginEvent *models.LoginEvent, profileID, defaultContactType, defaultName string) (contactDetail, contactTypeStr, name string) {
	contactTypeStr = defaultContactType
	name = defaultName

	getByIDReq := &profilev1.GetByIdRequest{}
	getByIDReq.SetId(profileID)
	profileResp, profileErr := h.profileCli.GetById(ctx, connect.NewRequest(getByIDReq))
	if profileErr != nil || profileResp.Msg.GetData() == nil {
		return "", contactTypeStr, name
	}

	prof := profileResp.Msg.GetData()
	for _, c := range prof.GetContacts() {
		if c.GetId() == loginEvent.ContactID {
			contactDetail = c.GetDetail()
			switch c.GetType() {
			case profilev1.ContactType_EMAIL:
				contactTypeStr = "email"
			case profilev1.ContactType_MSISDN:
				contactTypeStr = "phone"
			}
			break
		}
	}

	if pn := prof.GetProperties(); pn != nil {
		if m := pn.AsMap(); m != nil {
			if n, ok := m[KeyProfileName].(string); ok && n != "" {
				name = n
			}
		}
	}

	return contactDetail, contactTypeStr, name
}

// fedcmWriteIdPSession upserts the account entry into the idp_session cookie.
func (h *AuthServer) fedcmWriteIdPSession(
	ctx context.Context,
	rw http.ResponseWriter,
	req *http.Request,
	profileID, contact, contactType, name, loginEventID, authMethod string,
) {
	if h.fedcmSession == nil {
		return
	}
	log := util.Log(ctx)

	idpSession, readErr := h.fedcmSession.Read(req)
	if readErr != nil {
		idpSession = &models.IdPSession{
			Version:   models.IdPSessionCurrentVersion,
			CreatedAt: time.Now(),
		}
	}
	now := time.Now()
	if idpSession.CreatedAt.IsZero() {
		idpSession.CreatedAt = now
	}
	idpSession.LastActive = now
	idpSession.Upsert(models.IdPSessionEntry{
		ProfileID:    profileID,
		Contact:      contact,
		ContactType:  contactType,
		Name:         name,
		AddedAt:      now,
		LastUsedAt:   now,
		LoginEventID: loginEventID,
		AuthMethod:   authMethod,
	})
	if writeErr := h.fedcmSession.Write(rw, req, idpSession); writeErr != nil {
		log.WithError(writeErr).Error("fedcm: failed to write idp_session cookie")
	}
}
