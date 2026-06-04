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

package events

import (
	"os"
	"strings"
)

const defaultFedCMPublicOrigin = "https://accounts.stawi.org"

func ensureFedCMCallbackRedirectURI(redirectURIs, grantTypes []string) []string {
	if !containsString(grantTypes, "authorization_code") {
		return redirectURIs
	}
	callback := fedCMCallbackRedirectURI()
	if callback == "" || containsString(redirectURIs, callback) {
		return redirectURIs
	}
	return append(redirectURIs, callback)
}

func fedCMCallbackRedirectURI() string {
	origin := strings.TrimRight(strings.TrimSpace(os.Getenv("FEDCM_PUBLIC_ORIGIN")), "/")
	if origin == "" {
		origin = defaultFedCMPublicOrigin
	}
	return origin + "/_internal/fedcm-callback"
}

func containsString(values []string, needle string) bool {
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), needle) {
			return true
		}
	}
	return false
}
