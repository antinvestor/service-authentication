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
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"

	"github.com/antinvestor/service-authentication/apps/audit/service/business"
	"github.com/pitabwire/frame/v2/tenancy"
	"github.com/pitabwire/util"
)

// WellKnownKeysPath serves public signing keys without authentication.
const WellKnownKeysPath = "/.well-known/audit-keys.json"

type wellKnownKey struct {
	KeyID     string     `json:"key_id"`
	Algorithm string     `json:"algorithm"`
	PublicKey string     `json:"public_key_hex"`
	ValidFrom time.Time  `json:"valid_from"`
	RetiredAt *time.Time `json:"retired_at,omitempty"`
}

// WellKnownKeysHandler returns the unauthenticated public-key document.
func WellKnownKeysHandler(keys business.KeyProvider, serviceName string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		ctx := tenancy.WithSystemPrincipal(r.Context(), tenancy.SystemPrincipal{
			ServiceName: serviceName, AllowGlobal: true, Reason: "well-known-keys",
		})
		rows, err := keys.List(ctx)
		if err != nil {
			util.Log(ctx).WithError(err).Error("audit: well-known keys lookup failed")
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		out := make([]wellKnownKey, 0, len(rows))
		for _, k := range rows {
			out = append(out, wellKnownKey{
				KeyID: k.KeyID, Algorithm: k.Algorithm, PublicKey: hex.EncodeToString(k.PublicKey),
				ValidFrom: k.ValidFrom, RetiredAt: k.RetiredAt,
			})
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=300")
		if r.Method == http.MethodHead {
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": out})
	})
}
