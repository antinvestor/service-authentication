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
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"sort"
	"strings"

	tenancyv1 "buf.build/gen/go/antinvestor/tenancy/protocolbuffers/go/tenancy/v1"
	"github.com/antinvestor/service-authentication/apps/default/service/hydra"
	"github.com/antinvestor/service-authentication/apps/default/service/models"
	"github.com/pitabwire/util"
)

const accessInstructionsPath = "/s/access/help"

type accessSupportContact struct {
	Label string
	Value string
	Href  template.URL
}

func buildAccessInstructionsPageURL(req *http.Request, redirectErr *accessInstructionsRedirectError) string {
	// If the user has accessible partitions, redirect to the workspace selector
	// instead of the support page.
	if redirectErr != nil && len(redirectErr.AccessiblePartitions) > 0 && strings.TrimSpace(redirectErr.LoginEventID) != "" {
		return buildWorkspaceSelectorURL(req, redirectErr)
	}

	query := make(url.Values)
	if req != nil {
		if uiLocales := strings.TrimSpace(req.URL.Query().Get("ui_locales")); uiLocales != "" {
			query.Set("ui_locales", uiLocales)
		}
	}

	if redirectErr != nil {
		if partitionName := strings.TrimSpace(redirectErr.PartitionName); partitionName != "" {
			query.Set("partition_name", partitionName)
		}
		if len(redirectErr.SupportContacts) > 0 {
			contactsData, err := json.Marshal(redirectErr.SupportContacts)
			if err == nil {
				query.Set("support_contacts", string(contactsData))
			}
		}
	}

	if encodedQuery := query.Encode(); encodedQuery != "" {
		return fmt.Sprintf("%s?%s", accessInstructionsPath, encodedQuery)
	}

	return accessInstructionsPath
}

const workspaceSelectorPath = "/s/access/workspace"

type workspaceEntry struct {
	Name        string
	Initial     string
	PartitionID string
}

func buildWorkspaceSelectorURL(req *http.Request, redirectErr *accessInstructionsRedirectError) string {
	query := make(url.Values)
	if req != nil {
		if uiLocales := strings.TrimSpace(req.URL.Query().Get("ui_locales")); uiLocales != "" {
			query.Set("ui_locales", uiLocales)
		}
		if loginChallenge := strings.TrimSpace(req.URL.Query().Get("login_challenge")); loginChallenge != "" {
			query.Set("login_challenge", loginChallenge)
		}
		if consentChallenge := strings.TrimSpace(req.URL.Query().Get("consent_challenge")); consentChallenge != "" {
			query.Set("consent_challenge", consentChallenge)
		}
	}
	if redirectErr != nil && strings.TrimSpace(redirectErr.LoginEventID) != "" {
		query.Set("login_event_id", strings.TrimSpace(redirectErr.LoginEventID))
	}

	if encodedQuery := query.Encode(); encodedQuery != "" {
		return fmt.Sprintf("%s?%s", workspaceSelectorPath, encodedQuery)
	}

	return workspaceSelectorPath
}

func workspaceEntryFromAccess(access *tenancyv1.AccessObject) workspaceEntry {
	partition := access.GetPartition()
	name := strings.TrimSpace(partition.GetName())
	if name == "" {
		name = partition.GetId()
	}

	initial := "W"
	if name != "" {
		initial = strings.ToUpper(name[:1])
	}

	return workspaceEntry{
		Name:        name,
		Initial:     initial,
		PartitionID: partition.GetId(),
	}
}

func (h *AuthServer) workspaceSelectionOptions(
	ctx context.Context,
	loginEvent *models.LoginEvent,
) ([]workspaceEntry, *tenancyv1.PartitionObject, error) {
	if loginEvent == nil {
		return nil, nil, fmt.Errorf("login event is required")
	}
	if loginEvent.ClientID == "" {
		return nil, nil, fmt.Errorf("login event client_id is required")
	}
	if loginEvent.ProfileID == "" {
		return nil, nil, fmt.Errorf("login event profile_id is required")
	}

	requestedPartition, err := h.resolvePartitionByClientID(ctx, loginEvent.ClientID)
	if err != nil {
		return nil, nil, err
	}

	accesses, err := h.listTenancyAccessByProfileID(ctx, loginEvent.ProfileID)
	if err != nil {
		return nil, requestedPartition, err
	}

	accessibleChildren, err := h.filterAccessibleChildPartitions(ctx, requestedPartition.GetId(), accesses)
	if err != nil {
		return nil, requestedPartition, err
	}

	workspaces := make([]workspaceEntry, 0, len(accessibleChildren))
	for _, access := range accessibleChildren {
		if access == nil || access.GetPartition() == nil {
			continue
		}
		workspaces = append(workspaces, workspaceEntryFromAccess(access))
	}

	return workspaces, requestedPartition, nil
}

func (h *AuthServer) renderWorkspaceSelectorPage(
	rw http.ResponseWriter,
	req *http.Request,
	loginEvent *models.LoginEvent,
	workspaces []workspaceEntry,
	requestedPartition *tenancyv1.PartitionObject,
	errorMsg string,
) error {
	payload := h.initTemplatePayloadWithI18n(req.Context(), req)
	payload["LoginEventID"] = loginEvent.GetID()
	payload["LoginChallengeID"] = strings.TrimSpace(req.FormValue("login_challenge"))
	payload["ConsentChallengeID"] = strings.TrimSpace(req.FormValue("consent_challenge"))
	payload["Workspaces"] = workspaces
	payload["HasWorkspaces"] = len(workspaces) > 0
	payload["Error"] = errorMsg
	if requestedPartition != nil {
		payload["PartitionName"] = requestedPartition.GetName()
		payload["SupportContacts"] = accessSupportContactsFromMap(partitionSupportContacts(requestedPartition))
	}

	rw.Header().Set("Content-Type", "text/html")
	rw.WriteHeader(http.StatusOK)
	return workspaceSelectorTmpl.Execute(rw, payload)
}

func (h *AuthServer) WorkspaceSelectorEndpoint(rw http.ResponseWriter, req *http.Request) error {
	loginEventID := strings.TrimSpace(req.FormValue("login_event_id"))
	if loginEventID == "" {
		return fmt.Errorf("login_event_id is required")
	}

	loginEvent, err := h.loginEventRepo.GetByID(req.Context(), loginEventID)
	if err != nil {
		return fmt.Errorf("failed to load login event for workspace selection: %w", err)
	}
	if loginEvent == nil {
		return fmt.Errorf("login event not found for workspace selection")
	}

	workspaces, requestedPartition, err := h.workspaceSelectionOptions(req.Context(), loginEvent)
	if err != nil {
		return fmt.Errorf("failed to resolve workspace options: %w", err)
	}

	return h.renderWorkspaceSelectorPage(rw, req, loginEvent, workspaces, requestedPartition, "")
}

func (h *AuthServer) WorkspaceSelectorSubmitEndpoint(rw http.ResponseWriter, req *http.Request) error {
	loginEventID := strings.TrimSpace(req.FormValue("login_event_id"))
	if loginEventID == "" {
		return fmt.Errorf("login_event_id is required")
	}

	loginEvent, err := h.loginEventRepo.GetByID(req.Context(), loginEventID)
	if err != nil {
		return fmt.Errorf("failed to load login event for workspace submission: %w", err)
	}
	if loginEvent == nil {
		return fmt.Errorf("login event not found for workspace submission")
	}

	workspaces, requestedPartition, err := h.workspaceSelectionOptions(req.Context(), loginEvent)
	if err != nil {
		return fmt.Errorf("failed to resolve workspace options: %w", err)
	}

	selectedPartitionID := strings.TrimSpace(req.FormValue("partition_id"))
	if selectedPartitionID == "" {
		return h.renderWorkspaceSelectorPage(rw, req, loginEvent, workspaces, requestedPartition, "Select a workspace to continue.")
	}

	selectedAllowed := false
	for _, workspace := range workspaces {
		if workspace.PartitionID == selectedPartitionID {
			selectedAllowed = true
			break
		}
	}
	if !selectedAllowed {
		return h.renderWorkspaceSelectorPage(rw, req, loginEvent, workspaces, requestedPartition, "The selected workspace is no longer available.")
	}

	setSelectedPartitionID(loginEvent, selectedPartitionID)
	_, updateErr := h.loginEventRepo.Update(req.Context(), loginEvent, "properties")
	if updateErr != nil {
		return fmt.Errorf("failed to persist workspace selection: %w", updateErr)
	}
	if cacheErr := h.setLoginEventToCache(req.Context(), loginEvent); cacheErr != nil {
		util.Log(req.Context()).WithError(cacheErr).Debug("failed to cache workspace selection")
	}

	loginEvent, err = h.ensureLoginEventTenancyAccess(req.Context(), loginEvent, loginEvent.ClientID, loginEvent.ProfileID)
	if err != nil {
		return err
	}

	if consentChallenge := strings.TrimSpace(req.FormValue("consent_challenge")); consentChallenge != "" {
		http.Redirect(rw, req, "/s/consent?consent_challenge="+url.QueryEscape(consentChallenge), http.StatusSeeOther)
		return nil
	}

	loginChallenge := strings.TrimSpace(req.FormValue("login_challenge"))
	if loginChallenge == "" {
		loginChallenge = strings.TrimSpace(loginEvent.LoginChallengeID)
	}
	if loginChallenge == "" {
		return fmt.Errorf("login_challenge is required to resume login")
	}

	acr := "workspace_select"
	switch loginEventAuthSource(loginEvent) {
	case string(models.LoginSourceDirect):
		acr = "2_factor"
	case string(models.LoginSourceSessionRefresh):
		acr = "session_refresh"
	case "":
		if loginEvent.VerificationID != "" {
			acr = "2_factor"
		}
	default:
		acr = loginEventAuthSource(loginEvent)
	}

	params := &hydra.AcceptLoginRequestParams{
		LoginChallenge:   loginChallenge,
		SubjectID:        loginEvent.ProfileID,
		SessionID:        loginEvent.GetID(),
		ExtendSession:    true,
		Remember:         true,
		RememberDuration: h.config.SessionRememberDuration,
	}

	loginContext := map[string]any{
		"login_event_id": loginEvent.GetID(),
	}

	redirectURL, err := h.defaultHydraCli.AcceptLoginRequest(req.Context(), params, loginContext, acr, loginEvent.ContactID)
	if err != nil {
		return fmt.Errorf("failed to resume login after workspace selection: %w", err)
	}

	http.Redirect(rw, req, redirectURL, http.StatusSeeOther)
	return nil
}

func (h *AuthServer) AccessInstructionsEndpoint(rw http.ResponseWriter, req *http.Request) error {
	payload := h.initTemplatePayloadWithI18n(req.Context(), req)
	payload["PartitionName"] = strings.TrimSpace(req.FormValue("partition_name"))
	payload["SupportContacts"] = accessSupportContactsFromQuery(req.FormValue("support_contacts"))

	rw.Header().Set("Content-Type", "text/html")
	rw.WriteHeader(http.StatusOK)
	return accessInstructionsTmpl.Execute(rw, payload)
}

func accessSupportContactsFromQuery(raw string) []accessSupportContact {
	if strings.TrimSpace(raw) == "" {
		return nil
	}

	stringContacts := make(map[string]string)
	if err := json.Unmarshal([]byte(raw), &stringContacts); err == nil {
		return accessSupportContactsFromMap(stringContacts)
	}

	genericContacts := make(map[string]any)
	if err := json.Unmarshal([]byte(raw), &genericContacts); err != nil {
		return nil
	}

	for key, value := range genericContacts {
		stringValue, ok := value.(string)
		if !ok {
			continue
		}
		stringValue = strings.TrimSpace(stringValue)
		if stringValue == "" {
			continue
		}
		stringContacts[key] = stringValue
	}

	return accessSupportContactsFromMap(stringContacts)
}

func accessSupportContactsFromMap(contacts map[string]string) []accessSupportContact {
	if len(contacts) == 0 {
		return nil
	}

	preferredKeys := []string{"msisdn", "phone", "whatsapp", "email"}
	keySet := make(map[string]struct{}, len(contacts))
	for key := range contacts {
		keySet[key] = struct{}{}
	}

	keys := make([]string, 0, len(contacts))
	for _, key := range preferredKeys {
		if _, ok := keySet[key]; ok {
			keys = append(keys, key)
			delete(keySet, key)
		}
	}

	remainingKeys := make([]string, 0, len(keySet))
	for key := range keySet {
		remainingKeys = append(remainingKeys, key)
	}
	sort.Strings(remainingKeys)
	keys = append(keys, remainingKeys...)

	result := make([]accessSupportContact, 0, len(keys))
	for _, key := range keys {
		value := strings.TrimSpace(contacts[key])
		if value == "" {
			continue
		}

		result = append(result, accessSupportContact{
			Label: supportContactLabel(key),
			Value: value,
			Href:  supportContactHref(key, value),
		})
	}

	return result
}

func supportContactLabel(key string) string {
	switch strings.ToLower(strings.TrimSpace(key)) {
	case "msisdn", "phone":
		return "Phone"
	case "whatsapp":
		return "WhatsApp"
	case "email", "support_email":
		return "Email"
	default:
		key = strings.ReplaceAll(strings.TrimSpace(key), "_", " ")
		key = strings.ReplaceAll(key, "-", " ")
		if key == "" {
			return "Contact"
		}
		return strings.ToUpper(key[:1]) + key[1:]
	}
}

func supportContactHref(key, value string) template.URL {
	switch strings.ToLower(strings.TrimSpace(key)) {
	case "email", "support_email":
		return template.URL("mailto:" + value)
	case "msisdn", "phone":
		replacer := strings.NewReplacer(" ", "", "-", "", "(", "", ")", "")
		return template.URL("tel:" + replacer.Replace(value))
	default:
		return ""
	}
}
