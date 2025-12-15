package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"

	"github.com/antinvestor/service-authentication/apps/default/service/hydra"
	"github.com/pitabwire/util"
)

const SessionKeyLoginStorageName = "login-storage"
const SessionKeyLoginChallenge = "login_challenge"
const SessionKeyClientID = "client_id"

// loginChallengeFingerprint generates a fingerprint for a login challenge to help track its integrity
// Returns a string containing length, SHA256 hash, and first/last 6 characters of the challenge
func loginChallengeFingerprint(challenge string) string {
	if challenge == "" {
		return "[empty]"
	}

	// Calculate SHA256 hash
	h := sha256.Sum256([]byte(challenge))
	hashStr := hex.EncodeToString(h[:])

	// Get first and last 6 chars (or less if string is shorter)
	first6 := challenge
	if len(challenge) > 6 {
		first6 = challenge[:6]
	}

	last6 := challenge
	if len(challenge) > 6 {
		last6 = challenge[len(challenge)-6:]
	}

	return fmt.Sprintf("len=%d, sha256=%s, first6=%s, last6=%s", 
		len(challenge), hashStr, first6, last6)
}

func (h *AuthServer) ShowLoginEndpoint(rw http.ResponseWriter, req *http.Request) error {
	ctx := req.Context()

	// Store loginChallenge in session before OAuth redirect
	session, err := h.getLogginSession().Get(req, SessionKeyLoginStorageName)
	if err != nil {
		util.Log(ctx).WithError(err).Error("failed to get session")
		return err
	}

	// Clean up the session value after retrieving it
	delete(session.Values, SessionKeyLoginChallenge)
	err = session.Save(req, rw)
	if err != nil {
		util.Log(ctx).WithError(err).Error("failed to save session after cleanup")
	}

	hydraCli := h.defaultHydraCli

	loginChallenge, err := hydra.GetLoginChallengeID(req)
	if err != nil {
		util.Log(ctx).WithError(err).Error("couldn't get a valid login challenge")
		return err
	}

	// Log login challenge fingerprint for debugging
	util.Log(ctx).WithField("login_challenge_fingerprint", loginChallengeFingerprint(loginChallenge)).
		Info("Received login challenge from URL query")

	getLogReq, err := hydraCli.GetLoginRequest(ctx, loginChallenge)
	if err != nil {
		util.Log(ctx).WithError(err).Error("couldn't get a valid login challenge")
		return err
	}

	if getLogReq.Skip {
		redirectUrl := ""
		params := &hydra.AcceptLoginRequestParams{LoginChallenge: loginChallenge, SubjectID: getLogReq.GetSubject()}
		redirectUrl, err = hydraCli.AcceptLoginRequest(ctx, params, "auto refresh")

		if err != nil {
			return err
		}

		http.Redirect(rw, req, redirectUrl, http.StatusSeeOther)
		return nil

	}

	session.Values[SessionKeyLoginChallenge] = loginChallenge

	client := getLogReq.GetClient()
	clientId, ok := client.GetClientIdOk()
	if ok {
		session.Values[SessionKeyClientID] = *clientId
	}
	err = session.Save(req, rw)
	if err != nil {
		util.Log(ctx).WithError(err).Error("failed to save login_challenge to session")
		return err
	}

	payload := initTemplatePayload(req.Context())

	payload["error"] = ""

	for k, val := range h.loginOptions {
		payload[k] = val
	}

	return loginTmpl.Execute(rw, payload)

}
