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

import "net/http"

// FedCM Login Status API. Chrome 121+ tracks each IdP origin as
// logged-in / logged-out / unknown, and silently rejects every
// navigator.credentials.get({identity:...}) call when the status is anything
// other than logged-in — no .well-known fetch, no UI. The IdP must declare
// status changes via the Set-Login response header on top-level navigations
// from its own origin.
//
// Spec: https://developers.google.com/privacy-sandbox/cookies/fedcm/idp-sign-in
const (
	headerSetLogin    = "Set-Login"
	setLoginLoggedIn  = "logged-in"
	setLoginLoggedOut = "logged-out"
)

// setLoginStatusLoggedIn signals the browser that the user just completed an
// authentication round-trip on this IdP. Safe to call on responses that are
// top-level navigations (redirects, full HTML pages); on XHR responses the
// browser ignores the header.
func setLoginStatusLoggedIn(w http.ResponseWriter) {
	w.Header().Set(headerSetLogin, setLoginLoggedIn)
}

// setLoginStatusLoggedOut signals the browser that the user signed out of
// this IdP. Pair with clearing any IdP-side session cookies.
func setLoginStatusLoggedOut(w http.ResponseWriter) {
	w.Header().Set(headerSetLogin, setLoginLoggedOut)
}
