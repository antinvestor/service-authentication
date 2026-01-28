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
	"github.com/pitabwire/frame"
	"github.com/pitabwire/frame/data"
	"github.com/pitabwire/util"
)

// LoginEndpointSubmit handles contact submission.
// creates verification and sends code to user's contact.
func (h *AuthServer) LoginEndpointSubmit(rw http.ResponseWriter, req *http.Request) error {
	ctx := req.Context()
	start := time.Now()
	log := util.Log(ctx)

	loginEventID := req.PathValue(pathValueLoginEventID)

	log = log.WithField("login_event_id", loginEventID)

	// Step 1: Retrieve login event from cache
	loginEvt, err := h.getLoginEventFromCache(ctx, loginEventID)
	if err != nil {
		log.WithError(err).Error("cache lookup failed for login event")
		return err
	}
	ctx = util.SetTenancy(ctx, loginEvt)

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

	// Step 2.5: Check rate limits for IP and contact
	ipAddr := util.GetIP(req)
	rateLimitResult := h.CheckLoginRateLimit(ctx, ipAddr, contactDetail)
	if !rateLimitResult.Allowed {
		log.WithFields(map[string]any{
			"ip":              ipAddr,
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

	result, err := h.profileCli.GetByContact(ctx, connect.NewRequest(&profilev1.GetByContactRequest{Contact: contactDetail}))
	if err != nil && !frame.ErrorIsNotFound(err) {
		log.WithError(err).Error("profile lookup failed")
		http.Redirect(rw, req, internalRedirectLinkToSignIn, http.StatusSeeOther)
		return nil
	}

	if result != nil {
		existingProfile = result.Msg.GetData()
		if existingProfile != nil {
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
		contactResp, createErr := h.profileCli.CreateContact(ctx, connect.NewRequest(&profilev1.CreateContactRequest{
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

	// Step 7: Create verification and send code
	ctx = util.SetTenancy(ctx, loginEvt)
	resp, err := h.profileCli.CreateContactVerification(ctx, connect.NewRequest(&profilev1.CreateContactVerificationRequest{
		Id:               util.IDString(),
		ContactId:        contactID,
		DurationToExpire: "15m",
	}))
	if err != nil {
		log.WithError(err).Error("failed to create contactDetail verification")
		http.Redirect(rw, req, internalRedirectLinkToSignIn, http.StatusSeeOther)
		return err
	}

	loginEvent, err := h.storeLoginAttempt(ctx, loginEvt, models.LoginSourceDirect, profileID, contactID, resp.Msg.GetId(), nil)
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
		"contact_type":    contactType.String(),
		"duration_ms":     time.Since(start).Milliseconds(),
	}).Info("verification code sent")

	return h.showVerificationPage(rw, req, loginEvent.GetID(), profileName, contactType.String(), "")
}

func (h *AuthServer) storeLoginAttempt(ctx context.Context, loginEvt *models.LoginEvent, source models.LoginSource, profileID, contactID string, verificationID string, extra map[string]any) (*models.LoginEvent, error) {

	login, err := h.loginRepo.GetByProfileID(ctx, profileID)
	if err != nil {

		if !data.ErrorIsNoRows(err) {
			return nil, err
		}

		login = &models.Login{
			ProfileID: profileID,
			Source:    string(source),
		}
		login.GenID(ctx)
		login.PartitionID = loginEvt.PartitionID
		login.TenantID = loginEvt.TenantID
		err = h.loginRepo.Create(ctx, login)
		if err != nil {
			return nil, err
		}
	}

	loginEvt.LoginID = login.GetID()
	loginEvt.DeviceID = utils.DeviceIDFromContext(ctx)
	loginEvt.VerificationID = verificationID
	loginEvt.ContactID = contactID
	loginEvt.Properties = extra

	err = h.loginEventRepo.Create(ctx, loginEvt)
	if err != nil {
		return nil, err
	}

	return loginEvt, nil
}
