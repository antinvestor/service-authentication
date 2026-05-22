// Copyright 2023-2026 Ant Investor Ltd
// Licensed under the Apache License, Version 2.0 (see LICENSE).

package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
)

// FedCMWellKnownHandler serves the static FedCM discovery documents. It is
// independent of the main AuthServer so it can be constructed and tested
// without bringing up the full dependency graph.
type FedCMWellKnownHandler struct {
	publicOrigin    string
	backgroundColor string
	iconURL         string
}

// NewFedCMWellKnownHandler constructs a handler that advertises this origin
// as a FedCM Identity Provider. backgroundColor and iconURL populate the
// branding object inside config.json; either may be empty.
func NewFedCMWellKnownHandler(publicOrigin, backgroundColor, iconURL string) *FedCMWellKnownHandler {
	return &FedCMWellKnownHandler{
		publicOrigin:    strings.TrimRight(publicOrigin, "/"),
		backgroundColor: backgroundColor,
		iconURL:         iconURL,
	}
}

// WellKnownWebIdentity responds with the FedCM discovery pointer at
// /.well-known/web-identity. The browser sends Sec-Fetch-Dest: webidentity on
// FedCM fetches; we accept any value here since some test tooling omits it.
func (h *FedCMWellKnownHandler) WellKnownWebIdentity(w http.ResponseWriter, _ *http.Request) error {
	return writeFedCMJSON(w, map[string]any{
		"provider_urls": []string{h.publicOrigin + "/fedcm/config.json"},
	})
}

// FedCMConfig responds with the FedCM IdP config document. The branding object
// uses the US-spelled keys (background_colour, colour, icons[]) required by the
// FedCM spec; any other names are silently ignored by the browser.
func (h *FedCMWellKnownHandler) FedCMConfig(w http.ResponseWriter, _ *http.Request) error {
	branding := map[string]any{}
	if h.backgroundColor != "" {
		branding["background_colour"] = h.backgroundColor
	}
	if h.iconURL != "" {
		branding["icons"] = []map[string]any{
			{"url": h.iconURL, "size": 32},
		}
	}

	body := map[string]any{
		"accounts_endpoint":        h.publicOrigin + "/fedcm/accounts",
		"client_metadata_endpoint": h.publicOrigin + "/fedcm/client_metadata",
		"id_assertion_endpoint":    h.publicOrigin + "/fedcm/id-assertion",
		"disconnect_endpoint":      h.publicOrigin + "/fedcm/disconnect",
		"login_url":                h.publicOrigin + "/s/fedcm/login",
	}
	if len(branding) > 0 {
		body["branding"] = branding
	}
	return writeFedCMJSON(w, body)
}

func writeFedCMJSON(w http.ResponseWriter, v any) error {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	return json.NewEncoder(w).Encode(v)
}
