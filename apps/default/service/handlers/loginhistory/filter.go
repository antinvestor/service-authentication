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

package loginhistory

import (
	"context"
	"time"

	"github.com/antinvestor/service-authentication/apps/default/service/models"
)

const defaultLimit = 50
const maxLimit = 500

// LoginEventFilter defines filtering options for login event queries.
type LoginEventFilter struct {
	ProfileID string
	ClientID  string
	Source    string
	DeviceID  string
	StartDate *time.Time
	EndDate   *time.Time
	Limit     int
	Cursor    string
}

func (s *LoginHistoryServer) listLoginEvents(ctx context.Context, filter *LoginEventFilter) ([]*models.LoginEvent, error) {
	db := s.loginEventRepo.Pool().DB(ctx, true)

	if filter.ProfileID != "" {
		db = db.Where("profile_id = ?", filter.ProfileID)
	}
	if filter.ClientID != "" {
		db = db.Where("client_id = ?", filter.ClientID)
	}
	if filter.DeviceID != "" {
		db = db.Where("device_id = ?", filter.DeviceID)
	}
	if filter.StartDate != nil {
		db = db.Where("created_at >= ?", *filter.StartDate)
	}
	if filter.EndDate != nil {
		db = db.Where("created_at <= ?", *filter.EndDate)
	}
	if filter.Cursor != "" {
		db = db.Where("id < ?", filter.Cursor)
	}

	limit := filter.Limit
	if limit <= 0 {
		limit = defaultLimit
	}
	if limit > maxLimit {
		limit = maxLimit
	}

	var events []*models.LoginEvent
	err := db.Order("created_at DESC").Limit(limit).Find(&events).Error
	if err != nil {
		return nil, err
	}

	return events, nil
}
