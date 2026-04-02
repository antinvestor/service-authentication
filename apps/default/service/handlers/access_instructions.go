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
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

const accessInstructionsPath = "/s/access/help"

type accessSupportContact struct {
	Label string
	Value string
	Href  template.URL
}

func buildAccessInstructionsPageURL(req *http.Request, redirectErr *accessInstructionsRedirectError) string {
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
