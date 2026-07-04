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
	"strings"

	"github.com/pitabwire/frame/v2/security"
	"github.com/pitabwire/util"
)

// staticServiceProfiles maps service account client_id values (as used in
// the tenancy migrations) to the static profile IDs created by the profile
// service's bootstrap migration (20260331_bootstrap_profiles.sql).
//
// This eliminates the need to call the profile service API at sync time.
// When adding a new service, add its mapping here and in both migrations.
var staticServiceProfiles = map[string]string{
	"service-authentication": "d75qclkpf2t1uum8ij40",
	"service-profile":        "d75qclkpf2t1uum8ij4g",
	"service-tenancy":        "d75qclkpf2t1uum8ij50",
	"service-notification":   "d75qclkpf2t1uum8ij5g",
	"service-device":         "d75qclkpf2t1uum8ij60",
	"service-settings":       "d75qclkpf2t1uum8ij6g",
	"service-payment":        "d75qclkpf2t1uum8ij70",
	"service-payment-jenga":  "d75qclkpf2t1uum8ij7g",
	"service-ledger":         "d75qclkpf2t1uum8ij80",
	"service-billing":        "d75qclkpf2t1uum8ij8g",
	"service-files":          "d75qclkpf2t1uum8ij90",
	"service-chat-drone":     "d75qclkpf2t1uum8ij9g",
	"service-chat-gateway":   "d75qclkpf2t1uum8ija0",
	"trustage":               "d75qclkpf2t1uum8ijbg",
	"service-notification-integration-africastalking": "d75qclkpf2t1uum8ijc0",
	"service-notification-integration-emailsmtp":      "d75qclkpf2t1uum8ijcg",
}

type botProfileResolution struct {
	Scanned    int
	Resolved   int
	Unresolved int
	Skipped    int
}

// resolveBotProfiles ensures every service account has a real profile_id.
// Migration-seeded SAs use placeholder profile_ids (e.g. "service_authentication")
// — this step replaces them with the static IDs defined in the profile service
// migration (e.g. "svc_authentication_01").
//
// The mapping is driven by staticServiceProfiles which maps client_id values
// to static profile IDs. No profile service RPC calls are needed.
func (prtSrv *TenancyServer) resolveBotProfiles(ctx context.Context) botProfileResolution {
	result := botProfileResolution{}

	ctx = security.SkipTenancyChecksOnClaims(ctx)
	log := util.Log(ctx)

	allSAs, err := prtSrv.ServiceAccountRepo.GetAllBy(ctx, nil, 0, 0)
	if err != nil {
		log.WithError(err).Error("failed to list service accounts for bot profile resolution")
		return result
	}

	result.Scanned = len(allSAs)

	for _, sa := range allSAs {
		if !isPlaceholderProfileID(sa.ProfileID) {
			result.Skipped++
			continue
		}

		// Look up static profile ID by client_id.
		staticID, ok := staticServiceProfiles[sa.ClientID]
		if !ok {
			log.WithField("client_id", sa.ClientID).
				WithField("profile_id", sa.ProfileID).
				Warn("no static profile mapping for service account, skipping")
			result.Unresolved++
			continue
		}

		sa.ProfileID = staticID
		if _, updateErr := prtSrv.ServiceAccountRepo.Update(ctx, sa, "profile_id"); updateErr != nil {
			log.WithFields(map[string]any{
				"sa_id":      sa.GetID(),
				"profile_id": staticID,
			}).WithError(updateErr).Error("failed to update service account profile_id")
			result.Unresolved++
			continue
		}

		log.WithFields(map[string]any{
			"sa_id":      sa.GetID(),
			"client_id":  sa.ClientID,
			"profile_id": staticID,
		}).Info("resolved bot profile for service account")
		result.Resolved++
	}

	log.WithFields(map[string]any{
		"scanned":    result.Scanned,
		"resolved":   result.Resolved,
		"unresolved": result.Unresolved,
		"skipped":    result.Skipped,
	}).Info("bot profile resolution completed")

	return result
}

// isPlaceholderProfileID returns true if the profile_id looks like a
// human-readable placeholder rather than a real xid. Placeholder values
// from migrations contain underscores (e.g. "service_authentication") or
// are short names. Real xid IDs are exactly 20 characters with no underscores.
func isPlaceholderProfileID(profileID string) bool {
	if profileID == "" {
		return true
	}
	if strings.Contains(profileID, "_") {
		return true
	}
	return len(profileID) != 20
}
