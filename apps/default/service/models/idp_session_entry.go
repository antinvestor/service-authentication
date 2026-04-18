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

package models

import (
	"sort"
	"time"
)

// IdPSessionMaxEntries caps the number of accounts remembered per browser.
const IdPSessionMaxEntries = 5

// IdPSessionIdleTTL is the sliding idle window for an idp_session cookie.
const IdPSessionIdleTTL = 30 * 24 * time.Hour

// IdPSessionHardCap is the absolute maximum age of an idp_session cookie.
const IdPSessionHardCap = 90 * 24 * time.Hour

// IdPSessionCurrentVersion is the on-disk schema version of the idp_session payload.
const IdPSessionCurrentVersion = 1

// IdPSessionEntry describes one signed-in account held in an idp_session cookie.
// The Contact field may hold either an email address or a phone number; ContactType
// disambiguates the two for response mapping to the FedCM accounts endpoint.
type IdPSessionEntry struct {
	ProfileID    string    `json:"profile_id"`
	Contact      string    `json:"contact"`
	ContactType  string    `json:"contact_type"`
	Name         string    `json:"name"`
	AvatarURL    string    `json:"avatar_url,omitempty"`
	AddedAt      time.Time `json:"added_at"`
	LastUsedAt   time.Time `json:"last_used_at"`
	LoginEventID string    `json:"login_event_id"`
	DeviceID     string    `json:"device_id,omitempty"`
	AuthMethod   string    `json:"auth_method"`
}

// IdPSession is the encrypted payload stored in the idp_session cookie.
type IdPSession struct {
	Version    int               `json:"v"`
	Entries    []IdPSessionEntry `json:"entries"`
	CreatedAt  time.Time         `json:"created_at"`
	LastActive time.Time         `json:"last_active"`
}

// Upsert inserts or replaces the entry for entry.ProfileID. If adding a new
// entry would exceed IdPSessionMaxEntries, the oldest (by LastUsedAt) is evicted.
func (s *IdPSession) Upsert(entry IdPSessionEntry) {
	for i := range s.Entries {
		if s.Entries[i].ProfileID == entry.ProfileID {
			s.Entries[i] = entry
			return
		}
	}

	s.Entries = append(s.Entries, entry)

	if len(s.Entries) > IdPSessionMaxEntries {
		sort.SliceStable(s.Entries, func(i, j int) bool {
			return s.Entries[i].LastUsedAt.Before(s.Entries[j].LastUsedAt)
		})
		s.Entries = s.Entries[len(s.Entries)-IdPSessionMaxEntries:]
	}
}

// Remove drops the entry matching profileID. Returns true if an entry was removed.
func (s *IdPSession) Remove(profileID string) bool {
	for i := range s.Entries {
		if s.Entries[i].ProfileID == profileID {
			s.Entries = append(s.Entries[:i], s.Entries[i+1:]...)
			return true
		}
	}
	return false
}

// Find returns the entry matching profileID.
func (s *IdPSession) Find(profileID string) (IdPSessionEntry, bool) {
	for _, e := range s.Entries {
		if e.ProfileID == profileID {
			return e, true
		}
	}
	return IdPSessionEntry{}, false
}

// Expired reports whether the session is past either its idle TTL or its hard cap.
func (s *IdPSession) Expired(now time.Time) bool {
	if now.Sub(s.CreatedAt) > IdPSessionHardCap {
		return true
	}
	if now.Sub(s.LastActive) > IdPSessionIdleTTL {
		return true
	}
	return false
}
