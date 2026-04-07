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

import "github.com/pitabwire/frame/config"

// AuditConfig holds configuration for the audit service.
type AuditConfig struct {
	config.ConfigurationDefault

	// Ed25519 private key for signing audit entries (hex-encoded, 128 hex chars = 64 bytes).
	// MUST be overridden in production. If empty, a random key is generated at startup.
	AuditSigningKey string `envDefault:"" env:"AUDIT_SIGNING_KEY"`
}
