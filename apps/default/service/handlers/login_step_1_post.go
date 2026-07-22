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
	"net/http"
	"net/url"
	"strings"
	"time"

	profilev1 "buf.build/gen/go/antinvestor/profile/protocolbuffers/go/profile/v1"
	"connectrpc.com/connect"
	"github.com/antinvestor/service-authentication/apps/default/service/models"
	"github.com/antinvestor/service-authentication/apps/default/utils"
	"github.com/pitabwire/frame/v2"
	"github.com/pitabwire/frame/v2/data"
	"github.com/pitabwire/util"
)

// LoginEndpointSubmit handles contact submission.
// creates verification and sends code to user's contact.
func (h *AuthServer) LoginEndpointSubmit(rw http.ResponseWriter, req *http.Request) error {
	parent := req.Context()
	start := time.Now()
	log := util.Log(parent)

	loginEventID := req.PathValue(pathValueLoginEventID)

	log = log.WithField("login_event_id", loginEventID)

	// Step 1: Retrieve login event from cache
	loginEvt, err := h.getLoginEventFromCache(parent, loginEventID)
	if err != nil {
		log.WithError(err).Error("cache lookup failed for login event")
		return err
	}
	// Profile lookups/creates run as the service bot (JWT home tenancy).
	// User-partition tenancy is applied only when needed for verification send.
	parent = serviceBotContext(parent)

	// Step 2: Handle contactDetail submission
	contactDetail := req.FormValue("contactDetail")
	if contactDetail == "" {
		log.Warn("empty contact detail submitted")
		http.Redirect(rw, req, "/s/login?login_challenge="+url.QueryEscape(loginEvt.LoginChallengeID)+"&error=contact_required", http.StatusSeeOther)
		return nil
	}

	// Log prefix safely (avoid panic on short strings)
	contactPrefix := contactDetail
	if len(contactPrefix) > 3 {
		contactPrefix = contactPrefix[:3]
	}
	log = log.WithField("contact_prefix", contactPrefix+"***")
	internalRedirectLinkToSignIn := "/s/login?login_challenge=" + url.QueryEscape(loginEvt.LoginChallengeID)

	// Step 2.5: Check rate limits for IP
	ipAddr := util.GetIP(req)
	rateLimitResult := h.CheckLoginRateLimit(parent, ipAddr)
	if !rateLimitResult.Allowed {
		log.WithFields(map[string]any{
			"attempts_used":   rateLimitResult.AttemptsUsed,
			"retry_after_sec": rateLimitResult.RetryAfterSec,
		}).Warn("login rate limit exceeded")

		errorMsg := url.QueryEscape("Too many login attempts. Please try again later.")
		http.Redirect(rw, req, internalRedirectLinkToSignIn+"&error="+errorMsg, http.StatusSeeOther)
		return nil
	}

	// Step 3: Look up or create contact for contactDetail
	var existingProfile *profilev1.ProfileObject
	var contactID string
	var contactType profilev1.ContactType

	result, err := h.profileCli.GetByContact(parent, connect.NewRequest(&profilev1.GetByContactRequest{Contact: contactDetail}))
	if err != nil && !frame.ErrorIsNotFound(err) {
		log.WithError(err).Error("profile lookup failed")
		http.Redirect(rw, req, internalRedirectLinkToSignIn, http.StatusSeeOther)
		return nil
	}

	if result != nil {
		existingProfile = result.Msg.GetData()
		if existingProfile != nil {
			if existingProfile.GetType() == profilev1.ProfileType_BOT {
				log.WithField("profile_id", existingProfile.GetId()).Warn("bot profile attempted UI login")
				errorMsg := url.QueryEscape("This account cannot log in through the web interface.")
				http.Redirect(rw, req, internalRedirectLinkToSignIn+"&error="+errorMsg, http.StatusSeeOther)
				return nil
			}

			// Find matching contactDetail ID
			for _, profileContact := range existingProfile.GetContacts() {
				if strings.EqualFold(contactDetail, profileContact.GetDetail()) {
					contactID = profileContact.GetId()
					contactType = profileContact.GetType()
					break
				}
			}
		}
	}

	// Step 5: Create contactDetail if not found
	if contactID == "" {
		contactResp, createErr := h.profileCli.CreateContact(parent, connect.NewRequest(&profilev1.CreateContactRequest{
			Contact: contactDetail,
		}))
		if createErr != nil {
			log.WithError(createErr).Error("failed to create contactDetail")
			http.Redirect(rw, req, internalRedirectLinkToSignIn, http.StatusSeeOther)
			return nil
		}
		contactID = contactResp.Msg.GetData().GetId()
		contactType = contactResp.Msg.GetData().GetType()
		log.WithField("contact_id", contactID).Debug("new contactDetail created")
	}

	// Step 6: Store login attempt
	profileID := ""
	if existingProfile != nil {
		profileID = existingProfile.GetId()
	}

	// Step 7: Create verification and send code (still service-bot Plane-1 path)
	parent = serviceBotContext(parent)
	resp, err := h.profileCli.CreateContactVerification(parent, connect.NewRequest(&profilev1.CreateContactVerificationRequest{
		Id:               util.IDString(),
		ContactId:        contactID,
		DurationToExpire: "15m",
	}))
	if err != nil {
		log.WithError(err).Error("failed to create contactDetail verification")
		http.Redirect(rw, req, internalRedirectLinkToSignIn, http.StatusSeeOther)
		return nil
	}

	loginEvent, err := h.storeLoginAttempt(parent, loginEvt, models.LoginSourceDirect, profileID, contactID, resp.Msg.GetId(), nil)
	if err != nil {
		log.WithError(err).Error("failed to store login attempt")
		http.Redirect(rw, req, internalRedirectLinkToSignIn, http.StatusSeeOther)
		return err
	}

	profileName := ""
	// Step 8: Extract profile name and show verification page
	if existingProfile != nil {
		var properties data.JSONMap
		properties = properties.FromProtoStruct(existingProfile.GetProperties())
		if name := properties.GetString(KeyProfileName); name != "" {
			profileName = name
		}
	}

	log.WithFields(map[string]any{
		"verification_id": resp.Msg.GetId(),
		"contact_id":      contactID,
		"contact_type":    contactType.String(),
		"tenant_id":       loginEvt.TenantID,
		"partition_id":    loginEvt.PartitionID,
		"login_event_id":  loginEvent.GetID(),
		"duration_ms":     time.Since(start).Milliseconds(),
	}).Info("verification code sent")

	h.showVerificationPage(rw, req, loginEvent.GetID(), profileName, contactType.String(), "")
	return nil
}

func (h *AuthServer) storeLoginAttempt(parent context.Context, loginEvt *models.LoginEvent, source models.LoginSource, profileID, contactID string, verificationID string, extra map[string]any) (*models.LoginEvent, error) {

	var (
		login *models.Login
		err   error
	)

	// Important: do not re-use records for empty profile IDs.
	// Re-using an "unbound" login row can couple independent login attempts.
	if profileID != "" {
		login, err = h.loginRepo.GetByProfileID(parent, profileID)
		if err != nil && !data.ErrorIsNoRows(err) {
			return nil, err
		}
	}

	if login == nil {
		login = &models.Login{
			ProfileID: profileID,
			ClientID:  loginEvt.ClientID,
			Source:    string(source),
		}
		login.GenID(parent)
		login.PartitionID = loginEvt.PartitionID
		login.TenantID = loginEvt.TenantID
		err = h.loginRepo.Create(parent, login)
		if err != nil {
			return nil, err
		}
	}

	loginEvt.LoginID = login.GetID()
	loginEvt.ProfileID = profileID
	loginEvt.DeviceID = utils.DeviceIDFromContext(parent)
	loginEvt.VerificationID = verificationID
	loginEvt.ContactID = contactID
	loginEvt.Properties = mergeLoginEventProperties(nil, extra)
	if loginEvt.Properties == nil {
		loginEvt.Properties = data.JSONMap{}
	}
	loginEvt.Properties[loginEventPropertyLoginSource] = string(source)

	err = h.loginEventRepo.Create(parent, loginEvt)
	if err != nil {
		return nil, err
	}

	return loginEvt, nil
}
