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

package hydraadmin

import (
	"testing"
)

func TestAudienceFromHTTPSURI(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		want string
	}{
		{"https://oauth2-w.stawi.org", "https://oauth2-w.stawi.org"},
		{"https://oauth2-w.stawi.org/admin", "https://oauth2-w.stawi.org"},
		{"https://identity-oauth2-hydra-admin-akpnezytka-od.a.run.app", "https://identity-oauth2-hydra-admin-akpnezytka-od.a.run.app"},
		{"http://service-authentication-oauth2-hydra-admin.identity.svc:4445", ""},
		{"http://127.0.0.1:4445", ""},
		{"", ""},
		{"not-a-url", ""},
		{"  https://oauth2-w.stawi.org/  ", "https://oauth2-w.stawi.org"},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			t.Parallel()
			if got := AudienceFromHTTPSURI(tc.in); got != tc.want {
				t.Fatalf("AudienceFromHTTPSURI(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
