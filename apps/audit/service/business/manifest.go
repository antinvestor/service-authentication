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

package business

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	auditv1 "buf.build/gen/go/antinvestor/audit/protocolbuffers/go/audit/v1"
	"github.com/antinvestor/service-authentication/apps/audit/service/models"
	"github.com/antinvestor/service-authentication/apps/audit/service/repository"
	"github.com/pitabwire/frame/v2/data"
)

// ErrManifestServiceMismatch is returned when a caller registers for another service.
var ErrManifestServiceMismatch = errors.New("manifest.service must equal the caller's service name")

// manifestCacheTTL bounds how stale the validator's view of a manifest can be.
const manifestCacheTTL = 60 * time.Second

// RegisterResult reports the outcome of a manifest registration.
type RegisterResult struct {
	Service   string
	Version   int32
	Unchanged bool
}

// ManifestBusiness manages per-service vocabularies.
type ManifestBusiness interface {
	Register(ctx context.Context, caller Caller, m *auditv1.AuditManifest) (*RegisterResult, error)
	Get(ctx context.Context, service string) (*models.AuditManifest, error)
	// Lookup is the validator's cached view.
	Lookup(ctx context.Context, service string) (*Manifest, bool, error)
}

type manifestBusiness struct {
	repo repository.ManifestRepository

	mu    sync.Mutex
	cache map[string]manifestCacheEntry
}

type manifestCacheEntry struct {
	manifest *Manifest
	found    bool
	expires  time.Time
}

// NewManifestBusiness creates the manifest registry.
func NewManifestBusiness(repo repository.ManifestRepository) ManifestBusiness {
	return &manifestBusiness{repo: repo, cache: map[string]manifestCacheEntry{}}
}

func (mb *manifestBusiness) Register(ctx context.Context, caller Caller, m *auditv1.AuditManifest) (*RegisterResult, error) {
	if m == nil || m.GetService() == "" {
		return nil, errors.New("manifest with service is required")
	}
	if !caller.CanCreateAny && caller.ServiceName != m.GetService() {
		return nil, fmt.Errorf("%w: caller %q, manifest %q", ErrManifestServiceMismatch, caller.ServiceName, m.GetService())
	}
	content := manifestContent(m)
	canon, err := CanonicalJSON(map[string]any(content))
	if err != nil {
		return nil, fmt.Errorf("canonicalise manifest: %w", err)
	}
	sum := sha256.Sum256(canon)
	hash := hex.EncodeToString(sum[:])

	latest, err := mb.repo.Latest(ctx, m.GetService())
	if err != nil {
		return nil, fmt.Errorf("load manifest: %w", err)
	}
	if latest != nil && latest.ContentHash == hash {
		return &RegisterResult{Service: m.GetService(), Version: latest.ManifestVer, Unchanged: true}, nil
	}
	var version int32 = 1
	if latest != nil {
		version = latest.ManifestVer + 1
	}
	row := &models.AuditManifest{
		Service: m.GetService(), ManifestVer: version, ContentHash: hash, Content: content, RegisteredBy: caller.ProfileID,
	}
	if err = mb.repo.Create(ctx, row); err != nil {
		return nil, fmt.Errorf("store manifest: %w", err)
	}
	mb.mu.Lock()
	delete(mb.cache, m.GetService())
	mb.mu.Unlock()
	return &RegisterResult{Service: m.GetService(), Version: version}, nil
}

func (mb *manifestBusiness) Get(ctx context.Context, service string) (*models.AuditManifest, error) {
	return mb.repo.Latest(ctx, service)
}

func (mb *manifestBusiness) Lookup(ctx context.Context, service string) (*Manifest, bool, error) {
	now := time.Now()
	mb.mu.Lock()
	if e, ok := mb.cache[service]; ok && now.Before(e.expires) {
		mb.mu.Unlock()
		return e.manifest, e.found, nil
	}
	mb.mu.Unlock()

	row, err := mb.repo.Latest(ctx, service)
	if err != nil {
		return nil, false, err
	}
	entry := manifestCacheEntry{expires: now.Add(manifestCacheTTL)}
	if row != nil {
		entry.manifest, entry.found = ManifestFromModel(row), true
	}
	mb.mu.Lock()
	mb.cache[service] = entry
	mb.mu.Unlock()
	return entry.manifest, entry.found, nil
}

func manifestContent(m *auditv1.AuditManifest) data.JSONMap {
	return data.JSONMap{
		"actions":              sortedUnique(m.GetActions()),
		"resource_types":       sortedUnique(m.GetResourceTypes()),
		"open_vocabulary":      m.GetOpenVocabulary(),
		"allow_backdating":     m.GetAllowBackdating(),
		"extra_forbidden_keys": sortedUnique(m.GetExtraForbiddenKeys()),
	}
}

func sortedUnique(in []string) []any {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	res := make([]any, len(out))
	for i, s := range out {
		res[i] = s
	}
	return res
}

// ManifestFromModel converts a stored manifest into the validator's view.
func ManifestFromModel(row *models.AuditManifest) *Manifest {
	m := &Manifest{Version: row.ManifestVer, Actions: map[string]struct{}{}, ResourceTypes: map[string]struct{}{}}
	for _, a := range toStrings(row.Content["actions"]) {
		m.Actions[a] = struct{}{}
	}
	for _, r := range toStrings(row.Content["resource_types"]) {
		m.ResourceTypes[r] = struct{}{}
	}
	m.ExtraForbiddenKeys = toStrings(row.Content["extra_forbidden_keys"])
	m.OpenVocabulary, _ = row.Content["open_vocabulary"].(bool)
	m.AllowBackdating, _ = row.Content["allow_backdating"].(bool)
	return m
}

// ManifestToProto converts a stored manifest back to its wire form.
func ManifestToProto(row *models.AuditManifest) *auditv1.AuditManifest {
	out := &auditv1.AuditManifest{}
	out.SetService(row.Service)
	out.SetActions(toStrings(row.Content["actions"]))
	out.SetResourceTypes(toStrings(row.Content["resource_types"]))
	out.SetExtraForbiddenKeys(toStrings(row.Content["extra_forbidden_keys"]))
	ov, _ := row.Content["open_vocabulary"].(bool)
	out.SetOpenVocabulary(ov)
	ab, _ := row.Content["allow_backdating"].(bool)
	out.SetAllowBackdating(ab)
	return out
}

func toStrings(v any) []string {
	items, ok := v.([]any)
	if !ok {
		if ss, ok2 := v.([]string); ok2 {
			return ss
		}
		return nil
	}
	out := make([]string, 0, len(items))
	for _, it := range items {
		if s, ok := it.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
