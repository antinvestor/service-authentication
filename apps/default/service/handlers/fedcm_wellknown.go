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
	publicOrigin string
}

// NewFedCMWellKnownHandler constructs a handler that advertises this origin
// as a FedCM Identity Provider.
func NewFedCMWellKnownHandler(publicOrigin string) *FedCMWellKnownHandler {
	return &FedCMWellKnownHandler{publicOrigin: strings.TrimRight(publicOrigin, "/")}
}

// WellKnownWebIdentity responds with the FedCM discovery pointer at
// /.well-known/web-identity.
func (h *FedCMWellKnownHandler) WellKnownWebIdentity(w http.ResponseWriter, _ *http.Request) error {
	return writeFedCMJSON(w, map[string]any{
		"provider_urls": []string{h.publicOrigin + "/fedcm/config.json"},
	})
}

// FedCMConfig responds with the FedCM IdP config document.
func (h *FedCMWellKnownHandler) FedCMConfig(w http.ResponseWriter, _ *http.Request) error {
	return writeFedCMJSON(w, map[string]any{
		"accounts_endpoint":        h.publicOrigin + "/fedcm/accounts",
		"client_metadata_endpoint": h.publicOrigin + "/fedcm/client_metadata",
		"id_assertion_endpoint":    h.publicOrigin + "/fedcm/id-assertion",
		"disconnect_endpoint":      h.publicOrigin + "/fedcm/disconnect",
		"login_url":                h.publicOrigin + "/s/fedcm/login",
		"branding": map[string]any{
			"background_colour": "#ffffff",
			"colour":            "#111111",
		},
	})
}

func writeFedCMJSON(w http.ResponseWriter, v any) error {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	return json.NewEncoder(w).Encode(v)
}
