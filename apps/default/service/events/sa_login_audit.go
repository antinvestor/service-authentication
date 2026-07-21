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
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/antinvestor/service-authentication/apps/default/service/models"
	"github.com/antinvestor/service-authentication/apps/default/service/repository"
	"github.com/pitabwire/frame/v2/data"
	"github.com/pitabwire/util"
)

// EventKeyServiceAccountLoginAudit is emitted after a successful SA token
// enrichment so durable login_events rows are written off the Hydra webhook
// hot path. Work is distributed via the shared events queue — replicas scale
// out without per-pod goroutine pools or locks.
const EventKeyServiceAccountLoginAudit = "auth.sa.login_audit"

// ServiceAccountLoginAuditPayload is the wire payload for EventKeyServiceAccountLoginAudit.
// LoginEventID must equal JWT session_id / login_event_id (stableSASessionID).
type ServiceAccountLoginAuditPayload struct {
	LoginEventID     string   `json:"login_event_id"`
	ClientID         string   `json:"client_id"`
	ServiceAccountID string   `json:"service_account_id"`
	TenantID         string   `json:"tenant_id"`
	PartitionID      string   `json:"partition_id"`
	ProfileID        string   `json:"profile_id"`
	AccessID         string   `json:"access_id"`
	SAType           string   `json:"sa_type"`
	TokenType        string   `json:"token_type"`
	GrantType        string   `json:"grant_type"`
	GrantedScopes    []string `json:"granted_scopes,omitempty"`
}

// ServiceAccountLoginAuditEvent upserts a durable login_events row for SA tokens.
type ServiceAccountLoginAuditEvent struct {
	loginRepo      repository.LoginRepository
	loginEventRepo repository.LoginEventRepository
}

// NewServiceAccountLoginAuditEventHandler constructs the queue consumer.
func NewServiceAccountLoginAuditEventHandler(
	loginRepo repository.LoginRepository,
	loginEventRepo repository.LoginEventRepository,
) *ServiceAccountLoginAuditEvent {
	return &ServiceAccountLoginAuditEvent{
		loginRepo:      loginRepo,
		loginEventRepo: loginEventRepo,
	}
}

// Name implements fevents.EventI.
func (e *ServiceAccountLoginAuditEvent) Name() string { return EventKeyServiceAccountLoginAudit }

// PayloadType implements fevents.EventI.
func (e *ServiceAccountLoginAuditEvent) PayloadType() any {
	return &ServiceAccountLoginAuditPayload{}
}

// Validate implements fevents.EventI.
func (e *ServiceAccountLoginAuditEvent) Validate(_ context.Context, payload any) error {
	p, ok := payload.(*ServiceAccountLoginAuditPayload)
	if !ok {
		return fmt.Errorf("invalid payload type, expected *ServiceAccountLoginAuditPayload got %T", payload)
	}
	if strings.TrimSpace(p.LoginEventID) == "" || strings.TrimSpace(p.ClientID) == "" || strings.TrimSpace(p.ProfileID) == "" {
		return errors.New("payload requires login_event_id, client_id, and profile_id")
	}
	return nil
}

// Execute implements fevents.EventI. Idempotent across retries and replicas.
func (e *ServiceAccountLoginAuditEvent) Execute(ctx context.Context, payload any) error {
	if e == nil || e.loginEventRepo == nil || e.loginRepo == nil {
		return errors.New("service account login audit handler not configured")
	}
	p, ok := payload.(*ServiceAccountLoginAuditPayload)
	if !ok {
		return fmt.Errorf("invalid payload type, expected *ServiceAccountLoginAuditPayload got %T", payload)
	}

	log := util.Log(ctx).WithFields(map[string]any{
		"login_event_id": p.LoginEventID,
		"client_id":      p.ClientID,
	})

	loginRecord, err := e.getOrCreateLoginRecord(ctx, p)
	if err != nil {
		return fmt.Errorf("resolve login record: %w", err)
	}

	existing, err := e.loginEventRepo.GetByID(ctx, p.LoginEventID)
	if err != nil {
		return fmt.Errorf("lookup login event: %w", err)
	}
	if existing != nil {
		if existing.Properties == nil {
			existing.Properties = data.JSONMap{}
		}
		existing.Properties["token_type"] = p.TokenType
		existing.Properties["grant_type"] = p.GrantType
		if _, uerr := e.loginEventRepo.Update(ctx, existing, "properties"); uerr != nil {
			log.WithError(uerr).Debug("sa login audit property update failed")
		}
		return nil
	}

	loginEvent := &models.LoginEvent{
		ClientID:  p.ClientID,
		LoginID:   loginRecord.GetID(),
		ProfileID: p.ProfileID,
		AccessID:  p.AccessID,
		Properties: data.JSONMap{
			"auth_flow":            "service_account_webhook",
			"grant_type":           p.GrantType,
			"token_type":           p.TokenType,
			"service_account_type": p.SAType,
		},
		Client: "hydra_token_webhook",
		BaseModel: data.BaseModel{
			TenantID:    p.TenantID,
			PartitionID: p.PartitionID,
		},
	}
	if len(p.GrantedScopes) > 0 {
		loginEvent.Properties["granted_scopes"] = append([]string(nil), p.GrantedScopes...)
	}
	loginEvent.ID = p.LoginEventID

	if err := e.loginEventRepo.Create(ctx, loginEvent); err != nil {
		if again, lerr := e.loginEventRepo.GetByID(ctx, p.LoginEventID); lerr == nil && again != nil {
			return nil
		}
		return fmt.Errorf("create sa login event: %w", err)
	}
	log.Debug("sa login audit row created")
	return nil
}

func (e *ServiceAccountLoginAuditEvent) getOrCreateLoginRecord(
	ctx context.Context,
	p *ServiceAccountLoginAuditPayload,
) (*models.Login, error) {
	login, err := e.loginRepo.GetByProfileID(ctx, p.ProfileID)
	if err == nil && login != nil {
		return login, nil
	}
	if err != nil && !data.ErrorIsNoRows(err) {
		return nil, err
	}

	login = &models.Login{
		ProfileID: p.ProfileID,
		ClientID:  p.ClientID,
		Source:    string(models.LoginSourceServiceAccount),
	}
	login.GenID(ctx)
	if err := e.loginRepo.Create(ctx, login); err != nil {
		if again, lerr := e.loginRepo.GetByProfileID(ctx, p.ProfileID); lerr == nil && again != nil {
			return again, nil
		}
		return nil, err
	}
	return login, nil
}
