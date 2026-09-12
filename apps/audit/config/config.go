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

package config

import (
	"strings"
	"time"

	"github.com/pitabwire/frame/v2/config"
)

// AuditConfig holds configuration for the audit service.
// See docs/superpowers/specs/2026-09-12-audit-service-v2-design.md §16.
type AuditConfig struct {
	config.ConfigurationDefault

	// SigningKeyRef locates the active Ed25519 private key:
	//   file:///path/to/key      — raw 64-byte seed+public or 32-byte seed, hex or binary
	//   vault://<path>#<prop>    — resolved to the mounted secret file
	//                              SigningKeyMountDir/<SigningKeyID>
	// Required at runtime; the process refuses to start without it.
	SigningKeyRef string `env:"AUDIT_SIGNING_KEY_REF"`

	// SigningKeyID names the active key. Must exist in audit_signing_keys
	// (seeded by the setup Job) and not be retired.
	SigningKeyID string `env:"AUDIT_SIGNING_KEY_ID"`

	// SigningKeyMountDir is where vault:// references are projected.
	SigningKeyMountDir string `env:"AUDIT_SIGNING_KEY_MOUNT_DIR" envDefault:"/var/run/secrets/audit"`

	KeyReloadInterval time.Duration `env:"AUDIT_KEY_RELOAD_INTERVAL" envDefault:"5m"`

	WriterTick       time.Duration `env:"AUDIT_WRITER_TICK"        envDefault:"100ms"`
	WriterIdleTick   time.Duration `env:"AUDIT_WRITER_IDLE_TICK"   envDefault:"1s"`
	WriterBatch      int           `env:"AUDIT_WRITER_BATCH"       envDefault:"500"`
	IntakeMaxBacklog int           `env:"AUDIT_INTAKE_MAX_BACKLOG" envDefault:"50000"`
	HeadMaxAge       time.Duration `env:"AUDIT_HEAD_MAX_AGE"       envDefault:"60s"`

	CheckpointInterval time.Duration `env:"AUDIT_CHECKPOINT_INTERVAL" envDefault:"1h"`
	CheckpointEveryN   int64         `env:"AUDIT_CHECKPOINT_EVERY_N"  envDefault:"10000"`

	// FrozenTenants is a comma-separated list of tenant ids the writer must
	// not advance (incident response).
	FrozenTenants string `env:"AUDIT_FROZEN_TENANTS"`

	RequireManifest bool `env:"AUDIT_REQUIRE_MANIFEST" envDefault:"false"`

	IntakeCommittedRetention time.Duration `env:"AUDIT_INTAKE_COMMITTED_RETENTION" envDefault:"168h"`
	RejectionsRetention      time.Duration `env:"AUDIT_REJECTIONS_RETENTION"       envDefault:"2160h"`

	VerifyMaxEntries int64 `env:"AUDIT_VERIFY_MAX_ENTRIES" envDefault:"1000000"`
}

// FrozenTenantSet returns the frozen tenant ids as a lookup set.
func (c *AuditConfig) FrozenTenantSet() map[string]struct{} {
	out := map[string]struct{}{}
	for _, t := range strings.Split(c.FrozenTenants, ",") {
		if t = strings.TrimSpace(t); t != "" {
			out[t] = struct{}{}
		}
	}
	return out
}
