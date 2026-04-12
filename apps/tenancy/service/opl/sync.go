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

package opl

import (
	"context"
	"sync"
	"time"

	"github.com/antinvestor/service-authentication/apps/tenancy/service/repository"
	"github.com/pitabwire/frame/security"
	"github.com/pitabwire/util"
)

const syncTimeout = 30 * time.Second

// Syncer loads all registered namespaces, generates the combined OPL, and
// pushes it to the Kubernetes ConfigMap. It serialises concurrent calls so
// rapid-fire registrations don't race.
type Syncer struct {
	repo    repository.ServiceNamespaceRepository
	updater *ConfigMapUpdater
	mu      sync.Mutex
}

// NewSyncer creates a syncer. Pass a nil updater to disable ConfigMap writes
// (useful in tests or local development).
func NewSyncer(repo repository.ServiceNamespaceRepository, updater *ConfigMapUpdater) *Syncer {
	return &Syncer{repo: repo, updater: updater}
}

// Sync generates and pushes OPL synchronously. Returns an error if the
// ConfigMap update fails.
func (s *Syncer) Sync(ctx context.Context) error {
	if s.updater == nil {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	logger := util.Log(ctx).WithField("component", "opl_sync")

	ctx = security.SkipTenancyChecksOnClaims(ctx)
	namespaces, err := s.repo.ListAll(ctx)
	if err != nil {
		return err
	}

	opl := GenerateCombined(namespaces)

	modified, err := s.updater.Update(ctx, opl)
	if err != nil {
		return err
	}

	if modified {
		logger.WithField("namespaces", len(namespaces)).Info("OPL ConfigMap updated — Keto will reload")
	} else {
		logger.WithField("namespaces", len(namespaces)).Debug("OPL ConfigMap unchanged — no restart needed")
	}
	return nil
}

// SyncAsync launches Sync in a background goroutine with a timeout.
// Errors are logged but not propagated — callers should not block on OPL
// sync success.
func (s *Syncer) SyncAsync(ctx context.Context) {
	if s.updater == nil {
		return
	}

	go func() {
		syncCtx, cancel := context.WithTimeout(context.Background(), syncTimeout)
		defer cancel()

		if err := s.Sync(syncCtx); err != nil {
			util.Log(ctx).WithError(err).Error("async OPL ConfigMap sync failed")
		}
	}()
}
