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

package models_test

import (
	"testing"
	"time"

	"github.com/antinvestor/service-authentication/apps/default/service/models"
	"github.com/stretchr/testify/require"
)

func TestIdPSession_Upsert_AddsNewEntry(t *testing.T) {
	s := &models.IdPSession{Version: 1}
	entry := models.IdPSessionEntry{
		ProfileID:   "prof_1",
		Contact:     "a@b.com",
		ContactType: "email",
		Name:        "Alice",
		AddedAt:     time.Now(),
		LastUsedAt:  time.Now(),
	}

	s.Upsert(entry)

	require.Len(t, s.Entries, 1)
	require.Equal(t, "prof_1", s.Entries[0].ProfileID)
}

func TestIdPSession_Upsert_ReplacesExistingEntryByProfileID(t *testing.T) {
	s := &models.IdPSession{Version: 1, Entries: []models.IdPSessionEntry{
		{ProfileID: "prof_1", Name: "Old", LastUsedAt: time.Now().Add(-time.Hour)},
	}}

	s.Upsert(models.IdPSessionEntry{ProfileID: "prof_1", Name: "New", LastUsedAt: time.Now()})

	require.Len(t, s.Entries, 1)
	require.Equal(t, "New", s.Entries[0].Name)
}

func TestIdPSession_Upsert_EvictsOldestWhenOverCap(t *testing.T) {
	s := &models.IdPSession{Version: 1}
	base := time.Now().Add(-24 * time.Hour)
	for i := 0; i < models.IdPSessionMaxEntries; i++ {
		s.Entries = append(s.Entries, models.IdPSessionEntry{
			ProfileID:  "prof_" + string(rune('a'+i)),
			LastUsedAt: base.Add(time.Duration(i) * time.Minute),
		})
	}

	s.Upsert(models.IdPSessionEntry{ProfileID: "prof_new", LastUsedAt: time.Now()})

	require.Len(t, s.Entries, models.IdPSessionMaxEntries)
	for _, e := range s.Entries {
		require.NotEqual(t, "prof_a", e.ProfileID, "oldest entry should have been evicted")
	}
}

func TestIdPSession_Remove_DropsMatchingEntry(t *testing.T) {
	s := &models.IdPSession{Version: 1, Entries: []models.IdPSessionEntry{
		{ProfileID: "prof_1"}, {ProfileID: "prof_2"},
	}}

	removed := s.Remove("prof_1")

	require.True(t, removed)
	require.Len(t, s.Entries, 1)
	require.Equal(t, "prof_2", s.Entries[0].ProfileID)
}

func TestIdPSession_Remove_NoopWhenMissing(t *testing.T) {
	s := &models.IdPSession{Version: 1, Entries: []models.IdPSessionEntry{{ProfileID: "prof_1"}}}

	removed := s.Remove("prof_missing")

	require.False(t, removed)
	require.Len(t, s.Entries, 1)
}

func TestIdPSession_Find_ReturnsMatchingEntry(t *testing.T) {
	s := &models.IdPSession{Entries: []models.IdPSessionEntry{
		{ProfileID: "prof_1", Name: "Alice"},
	}}

	e, ok := s.Find("prof_1")

	require.True(t, ok)
	require.Equal(t, "Alice", e.Name)
}

func TestIdPSession_Find_MissReturnsFalse(t *testing.T) {
	s := &models.IdPSession{}
	_, ok := s.Find("nope")
	require.False(t, ok)
}

func TestIdPSession_Expired_TrueWhenPastHardCap(t *testing.T) {
	s := &models.IdPSession{CreatedAt: time.Now().Add(-91 * 24 * time.Hour), LastActive: time.Now()}
	require.True(t, s.Expired(time.Now()))
}

func TestIdPSession_Expired_TrueWhenIdleTooLong(t *testing.T) {
	s := &models.IdPSession{CreatedAt: time.Now().Add(-2 * 24 * time.Hour), LastActive: time.Now().Add(-31 * 24 * time.Hour)}
	require.True(t, s.Expired(time.Now()))
}

func TestIdPSession_Expired_FalseWhenFresh(t *testing.T) {
	s := &models.IdPSession{CreatedAt: time.Now().Add(-24 * time.Hour), LastActive: time.Now().Add(-time.Hour)}
	require.False(t, s.Expired(time.Now()))
}
